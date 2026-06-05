"""Token 账本服务：只写 `token_ledger`，任务维度 token 由查询时聚合

核心逻辑：
- ``report_token_usage``：每次传入的四个计数为**当前维度下的用量总量**（由调用方在 event 等上下文中累加好后上报）。
- 若带 ``source_event_id``：账本中**至多一行**绑定该 event，再次上报则**覆盖**更新四列（不插入新行）。
- 若 ``source_event_id`` 为空：每次插入新行（无稳定键则无法覆盖；适合无关联 event 的一次性上报）。
- 任务总用量 = 对 ``token_ledger`` 按 ``task_id`` 对四列分别 ``SUM``（有 source_event_id 的行表示「该 event 的总量快照」）。
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Dict, Tuple

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.infrastructure.db import session_scope
from src.infrastructure.db.models import TokenLedger


def report_token_usage(
    *,
    task_id: str,
    llm_input: int = 0,
    llm_output: int = 0,
    code_agent_input: int = 0,
    code_agent_output: int = 0,
    source_event_id: int | None = None,
    note: str = "",
) -> bool:
    """上报 token 用量（总量语义）。返回 True 表示已写入或已覆盖更新。"""
    if not task_id:
        return False
    # 容忍全零上报（部分 LLM 不返回 usage，但至少记录一次心跳）

    with session_scope() as session:
        if source_event_id:
            existing = session.execute(
                select(TokenLedger).where(TokenLedger.source_event_id == source_event_id)
            ).scalar_one_or_none()
            if existing is not None:
                existing.llm_input = int(llm_input)
                existing.llm_output = int(llm_output)
                existing.code_agent_input = int(code_agent_input)
                existing.code_agent_output = int(code_agent_output)
                if note:
                    existing.note = note or ""
                session.flush()
                return True

        entry = TokenLedger(
            task_id=task_id,
            source_event_id=source_event_id,
            llm_input=llm_input,
            llm_output=llm_output,
            code_agent_input=code_agent_input,
            code_agent_output=code_agent_output,
            note=note or "",
        )
        session.add(entry)

        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            if not source_event_id:
                return False
            existing = session.execute(
                select(TokenLedger).where(TokenLedger.source_event_id == source_event_id)
            ).scalar_one_or_none()
            if existing is None:
                return False
            existing.llm_input = int(llm_input)
            existing.llm_output = int(llm_output)
            existing.code_agent_input = int(code_agent_input)
            existing.code_agent_output = int(code_agent_output)
            if note:
                existing.note = note or ""
            session.flush()
            return True

        return True


def sum_task_tokens_map_from_ledger(session: Session, task_ids: Sequence[str]) -> Dict[str, Tuple[int, int, int, int]]:
    """按 task_id 对 token_ledger 四列求和（有 source_event_id 的行为该 event 总量快照，无键行为独立片段行）。"""
    ids = [tid for tid in task_ids if tid]
    if not ids:
        return {}
    stmt = (
        select(
            TokenLedger.task_id,
            func.coalesce(func.sum(TokenLedger.llm_input), 0),
            func.coalesce(func.sum(TokenLedger.llm_output), 0),
            func.coalesce(func.sum(TokenLedger.code_agent_input), 0),
            func.coalesce(func.sum(TokenLedger.code_agent_output), 0),
        )
        .where(TokenLedger.task_id.in_(ids))
        .group_by(TokenLedger.task_id)
    )
    out: Dict[str, Tuple[int, int, int, int]] = {tid: (0, 0, 0, 0) for tid in ids}
    for row in session.execute(stmt).all():
        tid = str(row[0])
        out[tid] = (int(row[1]), int(row[2]), int(row[3]), int(row[4]))
    return out


def sum_task_tokens_from_ledger(session: Session, task_id: str) -> Tuple[int, int, int, int]:
    """单任务聚合（同上）。"""
    return sum_task_tokens_map_from_ledger(session, [task_id]).get(task_id, (0, 0, 0, 0))


def sum_task_cache_stats_from_ledger(session: Session, task_id: str) -> Tuple[int, int]:
    """
    从 token_ledger 中读取 note 以 'cache_stats:' 开头的行，
    返回 (总命中数, 总未命中数)。
    llm_input 列为命中数，llm_output 列为未命中数。
    多个 Agent（chain_analyzer、chain_confirmer）的数据汇总求和。
    """
    from sqlalchemy import func as sa_func
    row = session.execute(
        select(
            sa_func.coalesce(sa_func.sum(TokenLedger.llm_input), 0),
            sa_func.coalesce(sa_func.sum(TokenLedger.llm_output), 0),
        )
        .where(
            TokenLedger.task_id == task_id,
            TokenLedger.note.like("cache_stats:%"),
        )
    ).one()
    return int(row[0]), int(row[1])
