"""仪表盘聚合查询"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Dict, List, NamedTuple, Optional, Tuple

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from src.core.enums import FindingSeverity, TaskStatus
from src.infrastructure.db.models import Project, Task, TokenLedger, Vulnerability

SEVERITY_KEYS = tuple(s.value for s in FindingSeverity) + ("unknown",)
TASK_STATUS_KEYS = tuple(s.value for s in TaskStatus)

# 简单 TTL 缓存（token_totals 高频调用但数据秒级不敏感）
_token_totals_cache: dict = {"ts": 0.0, "data": None}
_TOKEN_TOTALS_TTL = 30  # 秒


class ProjectOverviewRow(NamedTuple):
    total_projects: int
    total_files: int
    total_lines: int


class ProjectTopVulnRow(NamedTuple):
    project_id: str
    project_name: str
    vulnerability_count: int


class StatsRepository:
    def __init__(self, session: Session):
        self.session = session

    def task_counts_by_status(self) -> Tuple[int, Dict[str, int]]:
        rows = self.session.execute(
            select(Task.status, func.count()).group_by(Task.status)
        ).all()
        by_status = {k: 0 for k in TASK_STATUS_KEYS}
        total = 0
        for status, cnt in rows:
            key = (status or "pending").strip().lower()
            n = int(cnt)
            total += n
            if key in by_status:
                by_status[key] = n
            else:
                by_status[key] = by_status.get(key, 0) + n
        return total, by_status

    def project_overview_scalars(self) -> ProjectOverviewRow:
        row = self.session.execute(
            select(
                func.count(Project.id),
                func.coalesce(func.sum(Project.file_count), 0),
                func.coalesce(func.sum(Project.line_count), 0),
            )
        ).one()
        return ProjectOverviewRow(
            total_projects=int(row[0]),
            total_files=int(row[1]),
            total_lines=int(row[2]),
        )

    def top_projects_by_vulnerabilities(self, *, limit: int = 5) -> List[ProjectTopVulnRow]:
        vuln_subq = (
            select(
                Vulnerability.project_id.label("project_id"),
                func.count(Vulnerability.id).label("vulnerability_count"),
            )
            .group_by(Vulnerability.project_id)
            .subquery()
        )
        rows = self.session.execute(
            select(
                Project.id,
                Project.name,
                vuln_subq.c.vulnerability_count,
            )
            .join(vuln_subq, Project.id == vuln_subq.c.project_id)
            .order_by(vuln_subq.c.vulnerability_count.desc(), Project.name.asc())
            .limit(limit)
        ).all()
        return [
            ProjectTopVulnRow(
                project_id=str(r[0]),
                project_name=str(r[1]),
                vulnerability_count=int(r[2]),
            )
            for r in rows
        ]

    def aggregate_language_stats_python(self) -> Dict[str, Dict[str, int]]:
        """使用 PostgreSQL JSONB 聚合函数在 DB 内完成语言统计合并。"""
        sql = text("""
            SELECT
                lang.key AS language,
                SUM((lang.value->>'code')::int) AS code,
                SUM((lang.value->>'files')::int) AS files,
                SUM((lang.value->>'lines')::int) AS lines
            FROM projects,
                 jsonb_each(COALESCE(language_stats, '{}'::jsonb)) AS top,
                 jsonb_each(COALESCE(top.value, '{}'::jsonb)) AS lang
            WHERE top.key = 'languages'
            GROUP BY lang.key
            ORDER BY SUM((lang.value->>'code')::int) DESC
        """)
        rows = self.session.execute(sql).all()
        merged: Dict[str, Dict[str, int]] = {}
        for lang, code, files, lines in rows:
            merged[str(lang)] = {
                "code": int(code or 0),
                "files": int(files or 0),
                "lines": int(lines or 0),
            }
        return merged

    def finding_counts_by_severity(self) -> Tuple[int, Dict[str, int]]:
        rows = self.session.execute(
            select(func.lower(Vulnerability.level), func.count()).group_by(func.lower(Vulnerability.level))
        ).all()
        by_severity = {k: 0 for k in SEVERITY_KEYS}
        total = 0
        for level, cnt in rows:
            key = (level or "").strip().lower() or "unknown"
            n = int(cnt)
            total += n
            if key in by_severity:
                by_severity[key] = n
            else:
                by_severity["unknown"] = by_severity.get("unknown", 0) + n
        return total, by_severity

    def finding_counts_by_category(self, *, limit: int = 50) -> List[Tuple[str, int]]:
        rows = self.session.execute(
            select(Vulnerability.category_name, func.count())
            .group_by(Vulnerability.category_name)
            .order_by(func.count().desc())
            .limit(limit)
        ).all()
        out: List[Tuple[str, int]] = []
        for name, cnt in rows:
            label = (name or "").strip() or "未分类"
            out.append((label, int(cnt)))
        return out

    def finding_daily_by_severity(
        self,
        *,
        since: Optional[datetime] = None,
    ) -> List[Tuple[str, str, int]]:
        stmt = select(
            func.date(Vulnerability.created_at).label("day"),
            func.lower(Vulnerability.level).label("level"),
            func.count().label("cnt"),
        ).group_by(func.date(Vulnerability.created_at), func.lower(Vulnerability.level))
        if since is not None:
            stmt = stmt.where(Vulnerability.created_at >= since)
        stmt = stmt.order_by(func.date(Vulnerability.created_at))
        rows = self.session.execute(stmt).all()
        return [(str(r[0]), (r[1] or "unknown").strip().lower() or "unknown", int(r[2])) for r in rows]

    def token_totals(self) -> Tuple[int, int, int, int]:
        global _token_totals_cache
        now = time.monotonic()
        if now - _token_totals_cache["ts"] < _TOKEN_TOTALS_TTL:
            cached = _token_totals_cache["data"]
            if cached is not None:
                return cached
        row = self.session.execute(
            select(
                func.coalesce(func.sum(TokenLedger.llm_input), 0),
                func.coalesce(func.sum(TokenLedger.llm_output), 0),
                func.coalesce(func.sum(TokenLedger.code_agent_input), 0),
                func.coalesce(func.sum(TokenLedger.code_agent_output), 0),
            )
            .where(~TokenLedger.note.like("cache_stats:%"))
        ).one()
        result = (int(row[0]), int(row[1]), int(row[2]), int(row[3]))
        _token_totals_cache["ts"] = now
        _token_totals_cache["data"] = result
        return result

    def token_daily(
        self,
        *,
        since: Optional[datetime] = None,
    ) -> List[Tuple[str, int, int, int, int]]:
        stmt = (
            select(
                func.date(TokenLedger.created_at).label("day"),
                func.coalesce(func.sum(TokenLedger.llm_input), 0),
                func.coalesce(func.sum(TokenLedger.llm_output), 0),
                func.coalesce(func.sum(TokenLedger.code_agent_input), 0),
                func.coalesce(func.sum(TokenLedger.code_agent_output), 0),
            )
            .where(~TokenLedger.note.like("cache_stats:%"))
            .group_by(func.date(TokenLedger.created_at))
            .order_by(func.date(TokenLedger.created_at))
        )
        if since is not None:
            stmt = stmt.where(TokenLedger.created_at >= since)
        rows = self.session.execute(stmt).all()
        return [(str(r[0]), int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in rows]
