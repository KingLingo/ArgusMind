"""事件总线：按类型订阅 + 发布 + SSE 实时推送

- 同步调用（publish 直接执行所有已注册 handler）
- 按事件 dataclass 的类型订阅；子类默认不继承，需显式订阅
- 发布时 handler 可通过 `event.set_result(value)` 写回结果，供调用方拿到（例如 start → event_id）
- 捕获 handler 异常，避免单个 handler 崩溃影响整条流水
- SSE 支持：subscribe_task_events 返回异步队列，用于 Server-Sent Events 推送
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Type

from src.core.events import _EventBase, LogEvent, TokenEvent, TaskStatusEvent

EventHandler = Callable[[Any], Any]
logger = logging.getLogger(__name__)

# 异步事件类型：这些事件的 handler 不需要 set_result，可以异步执行以释放调用方线程
_ASYNC_EVENT_TYPES = frozenset({LogEvent, TokenEvent, TaskStatusEvent})


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[Type, List[EventHandler]] = defaultdict(list)
        self._lock = threading.RLock()
        # 小线程池处理异步事件，避免占用编排器执行线程
        self._async_pool = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="event-bus-async",
        )
        self._own_pool = True
        # SSE 订阅者：task_id -> list of asyncio.Queue
        self._sse_subscribers: Dict[str, List[asyncio.Queue]] = defaultdict(list)
        self._sse_lock = threading.Lock()
        self._sequence: Dict[str, int] = defaultdict(int)

    def subscribe(self, event_type: Type, handler: EventHandler) -> None:
        with self._lock:
            self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: Type, handler: EventHandler) -> None:
        with self._lock:
            lst = self._handlers.get(event_type)
            if lst and handler in lst:
                lst.remove(handler)

    def clear(self) -> None:
        with self._lock:
            self._handlers.clear()

    def set_async_pool(self, pool: ThreadPoolExecutor) -> None:
        """允许外部设置共享线程池（与 orchestrator 共用），避免创建额外线程。"""
        if self._own_pool and hasattr(self, "_async_pool"):
            self._async_pool.shutdown(wait=False)
        self._async_pool = pool
        self._own_pool = False

    def publish(self, event: _EventBase) -> Any:
        """同步发布事件；若有多个 handler，它们依次执行，返回最后一个 `set_result` 的值。"""
        with self._lock:
            handlers = list(self._handlers.get(type(event), []))
        for h in handlers:
            try:
                h(event)
            except Exception as ex:
                logger.exception(
                    "[event_bus] handler 异常 %s / %s: %s",
                    type(event).__name__,
                    getattr(h, "__name__", repr(h)),
                    ex,
                )
        # 自动推送 SSE
        self._try_push_sse(event)
        return event.result

    def publish_async(self, event: _EventBase) -> None:
        """异步发布事件：将 handler 提交到线程池后立即返回，不阻塞调用方。

        仅用于非关键事件（LogEvent / TokenEvent / TaskStatusEvent），
        这些事件的 handler 不需要返回值且可以延迟执行。
        """
        with self._lock:
            handlers = list(self._handlers.get(type(event), []))
        if not handlers:
            # 即使没有 handler，也推送 SSE
            self._try_push_sse(event)
            return
        for h in handlers:
            try:
                self._async_pool.submit(self._run_handler, event, h)
            except Exception as ex:
                logger.warning(
                    "[event_bus] 提交异步 handler 失败 %s: %s",
                    getattr(h, "__name__", repr(h)),
                    ex,
                )
        # 自动推送 SSE
        self._try_push_sse(event)

    def _run_handler(self, event: _EventBase, handler: EventHandler) -> None:
        try:
            handler(event)
        except Exception as ex:
            logger.exception(
                "[event_bus] 异步 handler 异常 %s / %s: %s",
                type(event).__name__,
                getattr(handler, "__name__", repr(handler)),
                ex,
            )

    # ---- SSE 实时推送支持 ----

    def _try_push_sse(self, event: _EventBase) -> None:
        """从事件中提取 task_id，如有 SSE 订阅者则推送。"""
        task_id = getattr(event, "task_id", None)
        if not task_id:
            return
        event_type = type(event).__name__
        data: Dict[str, Any] = {}
        for field_name in ("level", "module", "message", "status", "vul_name", "verdict"):
            val = getattr(event, field_name, None)
            if val is not None:
                data[field_name] = val
        self.publish_to_sse(str(task_id), event_type, data)

    def subscribe_task_events(self, task_id: str) -> asyncio.Queue:
        """订阅指定任务的事件流（用于 SSE 推送）。

        返回一个 asyncio.Queue，调用方从队列中读取事件。
        每个事件是一个 dict，包含 sequence、type、data 等字段。
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._sse_lock:
            self._sse_subscribers[task_id].append(queue)
        logger.debug("[event_bus] SSE 订阅 task_id=%s, 当前订阅数=%d",
                     task_id, len(self._sse_subscribers[task_id]))
        return queue

    def unsubscribe_task_events(self, task_id: str, queue: asyncio.Queue) -> None:
        """取消 SSE 订阅。"""
        with self._sse_lock:
            subscribers = self._sse_subscribers.get(task_id, [])
            if queue in subscribers:
                subscribers.remove(queue)
            if not subscribers and task_id in self._sse_subscribers:
                del self._sse_subscribers[task_id]
        logger.debug("[event_bus] SSE 取消订阅 task_id=%s", task_id)

    def publish_to_sse(self, task_id: str, event_type: str, data: Dict[str, Any]) -> None:
        """发布事件到 SSE 订阅队列。"""
        with self._sse_lock:
            subscribers = list(self._sse_subscribers.get(task_id, []))
        if not subscribers:
            return

        self._sequence[task_id] += 1
        payload = {
            "sequence": self._sequence[task_id],
            "type": event_type,
            "task_id": task_id,
            "timestamp": time.time(),
            "data": data,
        }

        for queue in subscribers:
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("[event_bus] SSE 队列已满，丢弃事件 task_id=%s", task_id)

    def emit_task_event(self, task_id: str, event_type: str, data: Dict[str, Any]) -> None:
        """便捷方法：同时发布到传统 handler 和 SSE 队列。"""
        self.publish_to_sse(task_id, event_type, data)

    async def sse_event_stream(
        self, task_id: str, after_sequence: int = 0
    ) -> AsyncIterator[str]:
        """生成 SSE 格式的事件流（用于 FastAPI StreamingResponse）。

        Args:
            task_id: 任务 ID
            after_sequence: 只推送该序号之后的事件（用于断线重连）

        Yields:
            SSE 格式的字符串（data: {...}\n\n）
        """
        queue = self.subscribe_task_events(task_id)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    sequence = event.get("sequence", 0)
                    if sequence > after_sequence:
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    # 发送心跳保持连接
                    yield f": heartbeat {time.time()}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            self.unsubscribe_task_events(task_id, queue)


# 全局单例
_default_bus: Optional[EventBus] = None
_default_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    global _default_bus
    if _default_bus is None:
        with _default_bus_lock:
            if _default_bus is None:
                _default_bus = EventBus()
    return _default_bus


def reset_event_bus() -> None:
    """测试用：重置全局总线"""
    global _default_bus
    with _default_bus_lock:
        _default_bus = EventBus()
