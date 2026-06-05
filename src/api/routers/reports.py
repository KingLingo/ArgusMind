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
                select(Vulnerability)
                .where(Vulnerability.task_id == task_id)
                .where(Vulnerability.status != "false_positive")
                .order_by(Vulnerability.created_at.desc())
            )
            .scalars()
            .all()
        )

        # 结论聚合
        verdict_counts = dict(
            session.execute(
                select(Vulnerability.verdict, func.count())
                .where(Vulnerability.task_id == task_id)
                .where(Vulnerability.status != "false_positive")
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


@router.post("/{task_id}/regenerate")
def regenerate_html_report(task_id: str):
    """重新生成 HTML 审计报告（含评分/覆盖率/利用链等完整数据）。"""
    from src.services.report_generator import write_report_to_file

    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        project = session.get(Project, task.project_id) if task.project_id else None
        if not project:
            raise HTTPException(status_code=404, detail="project not found")

        project_name = project.name or "Unknown"
        project_path = project.storage_path or ""
        if not project_path:
            raise HTTPException(status_code=400, detail="project storage_path is empty")

        # 查询所有发现 + 明细（排除误报）
        rows = session.query(Vulnerability).filter(
            Vulnerability.task_id == task_id,
            Vulnerability.status != "false_positive",
        ).all()

        # 预加载所有 detail
        detail_map = {}
        from src.infrastructure.db.models.vulnerability import VulnerabilityDetail
        details = session.query(VulnerabilityDetail).filter(
            VulnerabilityDetail.vulnerability_id.in_([r.id for r in rows])
        ).all()
        for d in details:
            detail_map[d.vulnerability_id] = d

        # 查询扫描统计信息事件
        evs = session.query(EventRecord).filter(
            EventRecord.task_id == task_id,
            EventRecord.action_type == "information"
        ).order_by(EventRecord.started_at.asc()).all()

        findings = []
        for row in rows:
            detail = detail_map.get(row.id)
            entry_points_str = detail.entry_points if detail and detail.entry_points else ""
            evidence_str = detail.evidence if detail and detail.evidence else ""
            detail_str = detail.detail if detail and detail.detail else ""
            verification_reason = detail.verification_reason if detail and detail.verification_reason else ""
            ast_context = detail.ast_context if detail and detail.ast_context else {}
            exploitation_chain = detail.exploitation_chain if detail and detail.exploitation_chain else {}

            # 读取新字段（已有数据为空时从知识映射推导）
            vuln_type = row.category_name or ""

            remediation = (detail.remediation if detail else "") or ""
            safe_validation = (detail.safe_validation if detail else "") or ""
            impact = (detail.impact if detail else "") or detail_str
            owasp = (detail.owasp if detail else "") or ""
            gbt_mapping = (detail.gbt_mapping if detail else "") or ""
            cwe = (detail.cwe if detail else "") or ""
            code_snippet = (detail.code_snippet if detail else "") or ""
            language = (detail.language if detail else "") or ""
            cvss_score = (detail.cvss_score if detail else "") or ""
            sink_val = (detail.sink if detail and detail.sink else []) or []

            # 对已有数据：从知识映射推导缺失字段
            if not cwe and vuln_type:
                try:
                    from src.knowledge.audit_config import VULN_CWE_MAP
                    cwe = VULN_CWE_MAP.get(vuln_type.upper(), "")
                except Exception:
                    pass
            if not owasp and vuln_type:
                try:
                    from src.knowledge.owasp_mapping import OWASP_MAPPING, OWASP_NAMES
                    oids = OWASP_MAPPING.get(vuln_type.upper(), [])
                    owasp = ", ".join(f"{oid} {OWASP_NAMES.get(oid, '')}" for oid in oids)
                except Exception:
                    pass
            if not gbt_mapping and vuln_type:
                try:
                    from src.knowledge.gbt_standards import get_gbt_mapping
                    gbt_mapping = get_gbt_mapping(vuln_type.upper(), language) or ""
                except Exception:
                    pass
            if not cvss_score:
                sev = (row.level or "M").upper()
                cvss_score = {"C": "9.5", "H": "7.5", "M": "5.0", "L": "2.0"}.get(sev, "5.0")
            if not code_snippet and not row.source == "chain_analysis":
                # 使用证据或详情作为代码上下文
                code_snippet = evidence_str or detail_str
            if not language and entry_points_str:
                ext = os.path.splitext(entry_points_str.split("\n")[0].split(":")[0])[1].lower()
                lang_map = {".py": "python", ".js": "javascript", ".ts": "typescript",
                            ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
                            ".c": "c", ".cpp": "cpp", ".cs": "csharp"}
                language = lang_map.get(ext, "")

            findings.append({
                "id": row.id,
                "project_id": row.project_id,
                "task_id": row.task_id,
                "vul_name": row.vul_name,
                "title": row.vul_name,
                "vuln_type": vuln_type,
                "vulnType": vuln_type,
                "type": vuln_type,
                "category_name": vuln_type,
                "verdict": row.verdict,
                "severity": row.level or "L",
                "level": row.level or "L",
                "confidence": float(row.confidence or 0) if str(row.confidence or "").replace(".", "").isdigit() else 0.5,
                "source": row.source or "quick_scan",
                "neo4j_element_id": row.neo4j_element_id or "",
                "status": row.status,
                "verification_status": row.verification_status,
                "evidence": evidence_str,
                "reason": evidence_str,
                "detail": detail_str,
                "remediation": remediation,
                "safe_validation": safe_validation,
                "impact": impact,
                "impact_description": impact,
                "verification_note": verification_reason,
                "code_snippet": code_snippet,
                "cwe": cwe,
                "owasp": owasp,
                "gbt_mapping": gbt_mapping,
                "language": language,
                "cvss_score": float(cvss_score) if cvss_score and cvss_score.replace(".", "").isdigit() else 5.0,
                "location": entry_points_str.split("\n")[0] if entry_points_str else "",
                "file": entry_points_str.split("\n")[0] if entry_points_str else "",
                "entry_points": entry_points_str,
                "ast_context": ast_context if isinstance(ast_context, dict) else {},
                "exploitation_chain": exploitation_chain if isinstance(exploitation_chain, dict) else {},
                "sink": sink_val if isinstance(sink_val, list) else [],
                "evidence_points": entry_points_str.split("\n") if entry_points_str else [],
            })

        quick_scan = [f for f in findings if f.get("source") in ("quick_scan", "component_scan")]
        llm = [f for f in findings if f.get("source") not in ("quick_scan", "component_scan")]

        # --- audit_score：从 findings 重新计算 ---
        audit_score_result = None
        try:
            from src.knowledge.audit_scoring import calculate_audit_score
            audit_score_result = calculate_audit_score(findings)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"[regenerate] calculate_audit_score 失败: {e}")

        # --- scan_stats：从事件 + findings 统计重建 ---
        scan_stats = {
            "code_findings": len([f for f in findings if f.get("source") == "quick_scan"]),
            "component_findings": len([f for f in findings if f.get("source") == "component_scan"]),
            "total_findings": len(findings),
        }
        # 从 information 事件提取原始扫描统计
        for ev in evs:
            if "快速扫描" in (ev.reason or ""):
                import re
                m = re.search(r"(\d+)\s*个潜在问题", ev.reason or "")
                if m:
                    scan_stats["total_candidates"] = int(m.group(1))
                reason = ev.reason or ""
                if "代码" in reason:
                    m2 = re.search(r"代码=(\d+)", reason)
                    if m2:
                        scan_stats["code_findings"] = int(m2.group(1))
                if "组件" in reason:
                    m3 = re.search(r"组件=(\d+)", reason)
                    if m3:
                        scan_stats["component_findings"] = int(m3.group(1))

        # --- coverage_report：从事件数据重建 ---
        coverage_report = None
        for ev in evs:
            reason = ev.reason or ""
            if "覆盖率" in reason:
                import re
                m = re.search(r"([\d.]+)%", reason)
                rate = float(m.group(1)) if m else 0
                m2 = re.search(r"(\d+)/(\d+)", reason)
                reviewed = int(m2.group(1)) if m2 else 0
                total = int(m2.group(2)) if m2 else 0
                coverage_report = {
                    "coverage_rate": rate,
                    "reviewed_files": reviewed,
                    "total_files": total,
                    "unreviewed_code_files": max(0, total - reviewed),
                    "reviewed_attack_classes": [],
                    "subsystem_gaps": {},
                }
                break
        if coverage_report is None:
            # 兜底：使用 API 已有数据
            from sqlalchemy import text
            row = session.execute(
                text("SELECT coverage_rate FROM tasks WHERE id = :task_id"),
                {"task_id": task_id}
            ).fetchone()
            if row and row[0]:
                rate = float(row[0])
                coverage_report = {
                    "coverage_rate": rate,
                    "reviewed_files": 0,
                    "total_files": 0,
                    "unreviewed_code_files": 0,
                    "reviewed_attack_classes": [],
                    "subsystem_gaps": {},
                }

        report_dir = os.path.join(str(project_path), ".argusmind", "reports")
        result = write_report_to_file(
            report_dir=report_dir,
            task_id=task_id,
            project_name=project_name,
            findings=findings,
            audit_score=audit_score_result,
            coverage_report=coverage_report,
            scan_stats=scan_stats,
            quick_scan_findings=quick_scan,
            llm_findings=llm,
            exploit_chain_report=None,
        )

        return OkResponse[dict](data={
            "file_path": result["file_path"],
            "file_name": result["file_name"],
            "total_findings": len(findings),
            "quick_scan_count": len(quick_scan),
            "llm_count": len(llm),
            "audit_score": audit_score_result,
            "scan_stats": scan_stats,
            "coverage": coverage_report,
        })
