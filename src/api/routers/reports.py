"""任务审计报告：聚合 findings + token + LLM event 数量形成概览。

增强：返回快速扫描统计、覆盖率数据、HTML 报告下载路径。
"""
from __future__ import annotations

import os
import re

from fastapi import APIRouter, HTTPException

from sqlalchemy import func, select

from src.api.security import CurrentUserDep
from src.infrastructure.db import session_scope
from src.infrastructure.db.models import EventRecord, LogEntry, Project, Task, Vulnerability
from src.schemas.common import OkResponse
from src.services.token_service import sum_task_tokens_from_ledger

router = APIRouter(dependencies=[CurrentUserDep])


def _extract_quick_scan_stats(events: list[EventRecord]) -> dict:
    """从事件记录中提取快速扫描统计。"""
    for ev in events:
        if "快速扫描" in (ev.reason or ""):
            # 尝试从 final_status 提取结果
            result_text = ev.final_status or ""
            # 从 reason 提取发现数量
            match = re.search(r"(\d+)\s*个潜在问题", ev.reason or "")
            count = int(match.group(1)) if match else 0
            return {
                "completed": ev.status == "completed",
                "findings_count": count,
                "reason": ev.reason or "",
            }
    return {"completed": False, "findings_count": 0, "reason": ""}


def _extract_coverage_data(events: list[EventRecord]) -> dict:
    """从事件记录中提取覆盖率数据。

    覆盖率事件格式（orchestrator 发布）：
        reason="审计覆盖率报告: 45.5% (23/50 文件)"
    """
    for ev in events:
        if "覆盖率" in (ev.reason or ""):
            # 从 reason 中提取覆盖率百分比和文件数
            rate_match = re.search(r"(\d+(?:\.\d+)?)\s*%", ev.reason or "")
            if not rate_match:
                rate_match = re.search(r"(\d+(?:\.\d+)?)\s*%", ev.final_status or "")
            rate = float(rate_match.group(1)) if rate_match else 0
            # 从 reason 提取已审查/总文件
            file_match = re.search(r"(\d+)/(\d+)\s*文件", ev.reason or "")
            reviewed = int(file_match.group(1)) if file_match else 0
            total = int(file_match.group(2)) if file_match else 0
            return {
                "coverage_rate": rate,
                "reviewed_files": reviewed,
                "total_files": total,
            }
    return {"coverage_rate": 0, "reviewed_files": 0, "total_files": 0}


def _find_html_report(project_path: str, task_id: str) -> dict:
    """查找已生成的 HTML 报告文件。"""
    report_dir = os.path.join(project_path, ".argusmind", "reports")
    report_file = os.path.join(report_dir, f"audit-report-{task_id}.html")
    if os.path.isfile(report_file):
        return {
            "available": True,
            "download_path": f"/api/reports/{task_id}/html",
            "file_name": f"audit-report-{task_id}.html",
        }
    return {"available": False, "download_path": "", "file_name": ""}


@router.get("/{task_id}", response_model=OkResponse[dict])
def get_report(task_id: str) -> OkResponse[dict]:
    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        findings_rows = (
            session.execute(
                select(Vulnerability).where(Vulnerability.task_id == task_id).order_by(Vulnerability.created_at.desc())
            )
            .scalars()
            .all()
        )

        # 结论聚合
        verdict_counts = dict(
            session.execute(
                select(Vulnerability.verdict, func.count())
                .where(Vulnerability.task_id == task_id)
                .group_by(Vulnerability.verdict)
            ).all()
        )

        # LLM 事件数量
        action_counts = dict(
            session.execute(
                select(EventRecord.action_type, func.count())
                .where(EventRecord.task_id == task_id)
                .group_by(EventRecord.action_type)
            ).all()
        )

        # 日志 ERROR/WARNING 数量
        log_counts = dict(
            session.execute(
                select(LogEntry.level, func.count())
                .where(LogEntry.task_id == task_id)
                .group_by(LogEntry.level)
            ).all()
        )

        # 查询与快速扫描和覆盖率相关的事件
        info_events = (
            session.execute(
                select(EventRecord)
                .where(EventRecord.task_id == task_id)
                .where(EventRecord.action_type == "information")
                .order_by(EventRecord.started_at.asc())
            )
            .scalars()
            .all()
        )

        findings_payload = [
            {
                "id": f.id,
                "vul_name": f.vul_name,
                "verdict": f.verdict,
                "confidence": f.confidence or "LOW",
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "neo4j_element_id": f.neo4j_element_id,
            }
            for f in findings_rows
        ]

        li, lo, ci, co = sum_task_tokens_from_ledger(session, task_id)

        # 快速扫描统计：findings_count 用数据库实际入库数量，与 severity 统计一致
        quick_scan = _extract_quick_scan_stats(list(info_events))
        quick_scan["findings_count"] = len(findings_payload)

        # 覆盖率数据
        coverage = _extract_coverage_data(list(info_events))

        # HTML 报告路径
        project = session.get(Project, task.project_id) if task.project_id else None
        project_path = project.storage_path if project else ""
        html_report = _find_html_report(project_path, task_id)

        # 严重等级分布
        severity_counts = {"C": 0, "H": 0, "M": 0, "L": 0}
        for f in findings_rows:
            # level 字段存储 CRITICAL/HIGH/MEDIUM/LOW
            lvl = str(f.level or "").upper()
            if lvl in ("CRITICAL", "C"):
                severity_counts["C"] += 1
            elif lvl in ("HIGH", "H"):
                severity_counts["H"] += 1
            elif lvl in ("MEDIUM", "M"):
                severity_counts["M"] += 1
            else:
                severity_counts["L"] += 1

        report = {
            "task": {
                "id": task.id,
                "project_id": task.project_id,
                "status": task.status,
                "started_at": task.created_at.isoformat() if task.created_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "error": task.error or "",
            },
            "tokens": {
                "llm_input": li,
                "llm_output": lo,
                "code_agent_input": ci,
                "code_agent_output": co,
            },
            "summary": {
                "total_findings": len(findings_payload),
                "verdict": verdict_counts,
                "severity": severity_counts,
                "events_by_action": action_counts,
                "log_levels": log_counts,
            },
            "quick_scan": quick_scan,
            "coverage": coverage,
            "html_report": html_report,
            "findings": findings_payload,
        }
        return OkResponse[dict](data=report)


@router.get("/{task_id}/html")
def get_html_report(task_id: str):
    """下载 HTML 审计报告。"""
    from fastapi.responses import FileResponse

    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        project = session.get(Project, task.project_id) if task.project_id else None
        if not project:
            raise HTTPException(status_code=404, detail="project not found")

        report_dir = os.path.join(project.storage_path, ".argusmind", "reports")
        report_file = os.path.join(report_dir, f"audit-report-{task_id}.html")

        if not os.path.isfile(report_file):
            raise HTTPException(status_code=404, detail="HTML report not found")

        return FileResponse(
            report_file,
            media_type="text/html",
            filename=f"audit-report-{task_id}.html",
        )
