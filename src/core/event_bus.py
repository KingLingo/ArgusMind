"""事件总线：按类型订阅 + 发布

- 同步调用（publish 直接执行所有已注册 handler）
- 按事件 dataclass 的类型订阅；子类默认不继承，需显式订阅
- 发布时 handler 可通过 `event.set_result(value)` 写回结果，供调用方拿到（例如 start → event_id）
- 捕获 handler 异常，避免单个 handler 崩溃影响整条流水
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Type

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
        return event.result

    def publish_async(self, event: _EventBase) -> None:
        """异步发布事件：将 handler 提交到线程池后立即返回，不阻塞调用方。

        仅用于非关键事件（LogEvent / TokenEvent / TaskStatusEvent），
        这些事件的 handler 不需要返回值且可以延迟执行。
        """
        with self._lock:
            handlers = list(self._handlers.get(type(event), []))
        if not handlers:
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
