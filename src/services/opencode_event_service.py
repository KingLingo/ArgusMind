"""OpenCode SSE 事件服务

职责：
- 把 OpenCode SSE 推送的事件实时落库到 opencode_events（payload 存整条事件的完整 JSON）
- 把每次 step-finish 累积出来的 code_agent token 实时回写到对应 events 行的
  code_agent_input_delta / code_agent_output_delta，便于前端实时查看进度

注意事项：
- 这里仅"覆盖写"events.code_agent_*_delta 为当前累计总额；
  EventSpan.finish() 在结束时仍会再写一次（最终值与累计值一致），不会重复累加 task 总量
- task 维度的 token 由 `token_ledger` 汇总；EventSpan 经 TokenEvent 调用 ``report_token_usage`` 入账本，
  本服务不参与 ledger 写入，避免双重计费
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


from src.core.event_bus import get_event_bus
from src.core.events import TokenEvent
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventRecord, OpencodeEvent
from src.repositories.opencode_event_repository import OpencodeEventRepository

logger = logging.getLogger(__name__)


def record_opencode_event(
    *,
    event_id: int,
    session_id: str,
    event_type: str,
    part_type: Optional[str] = None,
    part_id: Optional[str] = None,
    message_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_status: Optional[str] = None,
    title: Optional[str] = None,
    content: Optional[str] = None,
    token_input: Optional[int] = None,
    token_output: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Optional[int]:
    """把一条 SSE 事件持久化到 opencode_events，返回新行 id。"""
    if not event_id:
        return None
    try:
        with session_scope() as session:
            row = OpencodeEvent(
                event_id=event_id,
                session_id=session_id or "",
                event_type=event_type or "",
                part_type=part_type,
                part_id=part_id,
                message_id=message_id,
                tool_name=tool_name,
                tool_status=tool_status,
                title=title,
                content=content,
                token_input=token_input,
                token_output=token_output,
                payload=payload,
            )
            session.add(row)
            session.flush()
            return int(row.id)
    except Exception as ex:  # 持久化失败不应阻断 SSE 主流程
        logger.warning("[opencode_event_service] 写入 SSE 事件失败: %s", ex)
        return None


class _BufferedOpenCodeWriter:
    """批量写入 opencode_events + events.code_agent_*_delta，减少独立事务数。

    策略：
    - 攒满 FLUSH_BATCH_SIZE 条或上次 flush 超过 FLUSH_INTERVAL_SEC 时触发批量提交。
    - close() 时强制 flush 剩余数据。
    """

    FLUSH_BATCH_SIZE = 20
    FLUSH_INTERVAL_SEC = 2.0

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []
        self._last_flush = time.monotonic()
        self._last_token_input = 0
        self._last_token_output = 0
        self._token_dirty = False
        self._event_id: Optional[int] = None
        self._task_id: str = ""
        self._lock = threading.Lock()
        self._closed = False

    def bind(self, event_id: int, task_id: str) -> None:
        self._event_id = event_id
        self._task_id = task_id

    def add_event(self, record: Dict[str, Any]) -> None:
        if self._closed:
            return
        with self._lock:
            self._events.append(record)
            if len(self._events) >= self.FLUSH_BATCH_SIZE:
                self._flush_locked()

    def update_tokens(self, total_input: int, total_output: int) -> None:
        if self._closed:
            return
        with self._lock:
            self._last_token_input = total_input
            self._last_token_output = total_output
            self._token_dirty = True
            now = time.monotonic()
            if now - self._last_flush >= self.FLUSH_INTERVAL_SEC:
                self._flush_locked()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """持有锁时调用，批量 flush events 和 token。"""
        events_batch = self._events[:]
        self._events.clear()
        token_dirty = self._token_dirty
        token_input = self._last_token_input
        token_output = self._last_token_output
        self._token_dirty = False
        self._last_flush = time.monotonic()

        if not events_batch and not token_dirty:
            return

        try:
             with session_scope() as session:
                 if events_batch:
                     session.bulk_insert_mappings(OpencodeEvent, events_batch)
                 if token_dirty and self._event_id:
                    event = session.get(EventRecord, self._event_id)
                    if event is not None:
                        event.code_agent_input_delta = token_input
                        event.code_agent_output_delta = token_output
                        session.commit()
        except Exception as ex:
            logger.warning("[opencode batch] 批量写入失败: %s", ex)
            # 回退：逐条重试
            for ev in events_batch:
                try:
                    with session_scope() as s:
                        s.add(OpencodeEvent(**ev))
                except Exception:
                    pass

        # TokenEvent 独立发送（不影响 DB 事务）
        if token_dirty and self._event_id and self._task_id:
            try:
                bus = get_event_bus()
                bus.publish(
                    TokenEvent(
                        task_id=self._task_id,
                        source_event_id=self._event_id,
                        llm_input=0,
                        llm_output=0,
                        code_agent_input=token_input,
                        code_agent_output=token_output,
                    )
                )
            except Exception:
                pass


_buffered_writers: dict[int, _BufferedOpenCodeWriter] = {}
_buffered_lock = threading.Lock()


def get_buffered_writer(event_id: int, task_id: str = "") -> _BufferedOpenCodeWriter:
    """获取或创建 event_id 对应的批量 writer。"""
    with _buffered_lock:
        w = _buffered_writers.get(event_id)
        if w is None:
            w = _BufferedOpenCodeWriter()
            w.bind(event_id, task_id)
            _buffered_writers[event_id] = w
        return w


def close_buffered_writer(event_id: int) -> None:
    """关闭并移除 event_id 对应的批量 writer。"""
    with _buffered_lock:
        w = _buffered_writers.pop(event_id, None)
        if w is not None:
            w.close()


def update_event_code_agent_tokens(
    *,
    event_id: int,
    task_id: str,
    total_input: int,
    total_output: int,
) -> bool:
    """实时把累计 token 写到 events.code_agent_*_delta（走批量 writer）。"""
    if not event_id:
        return False
    try:
        w = get_buffered_writer(event_id, task_id)
        w.update_tokens(total_input, total_output)
        return True
    except Exception as ex:
        logger.warning("[opencode_event_service] 批量回写 token 失败: %s", ex)
        return False


def record_opencode_event_buffered(
    *,
    event_id: int,
    session_id: str,
    event_type: str,
    part_type: Optional[str] = None,
    part_id: Optional[str] = None,
    message_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_status: Optional[str] = None,
    title: Optional[str] = None,
    content: Optional[str] = None,
    token_input: Optional[int] = None,
    token_output: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    """通过批量 writer 异步写入 opencode_event（不立即落库）。"""
    if not event_id:
        return
    w = get_buffered_writer(event_id)
    w.add_event({
        "event_id": event_id,
        "session_id": session_id or "",
        "event_type": event_type or "",
        "part_type": part_type,
        "part_id": part_id,
        "message_id": message_id,
        "tool_name": tool_name,
        "tool_status": tool_status,
        "title": title,
        "content": content,
        "token_input": token_input,
        "token_output": token_output,
        "payload": payload,
    })


def list_opencode_events(
    *,
    event_id: int,
    after_id: Optional[int] = None,
    page_size: Optional[int] = None,
) -> Tuple[List[OpencodeEvent], int]:
    """按 event_id 拉取 SSE 事件，供前端展示。"""
    with session_scope() as session:
        rows, total = OpencodeEventRepository(session).list(
            event_id=event_id,
            after_id=after_id,
            page_size=page_size,
        )
        for r in rows:
            session.expunge(r)
        return rows, total
