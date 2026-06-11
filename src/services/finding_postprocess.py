# -*- coding: utf-8 -*-
"""Finding 结果后处理 —— 参考 CodeScan 的 summary/findings.go + report/report.go。

提供：
1. ActiveFindings / RejectedFindings 过滤
2. EffectiveSeverity（优先使用 reviewed_severity）
3. 阶段专用输出字段提取（参考 CodeScan stageConfigs）
4. Finding 去重和排序

用法：
    from src.services.finding_postprocess import (
        get_active_findings, get_rejected_findings, get_effective_severity,
        extract_stage_fields, postprocess_findings,
    )
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import VerificationStatus

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# Finding 过滤（参考 CodeScan ActiveFindings / RejectedFindings）
# ══════════════════════════════════════════════════════════════════

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


def get_verification_status(finding: Dict[str, Any]) -> str:
    """获取 finding 的验证状态。"""
    status = str(finding.get("verification_status", "")).strip().lower()
    if status in ("confirmed", "uncertain", "rejected"):
        return status
    return "unreviewed"


def is_rejected(finding: Dict[str, Any]) -> bool:
    """检查 finding 是否被驳回。"""
    return get_verification_status(finding) == "rejected"


def is_active(finding: Dict[str, Any]) -> bool:
    """检查 finding 是否为活跃状态（未被驳回）。"""
    return not is_rejected(finding)


def get_active_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """过滤出所有未被驳回的 findings。"""
    return [f for f in findings if is_active(f)]


def get_rejected_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """过滤出所有被驳回的 findings。"""
    return [f for f in findings if is_rejected(f)]


# ══════════════════════════════════════════════════════════════════
# EffectiveSeverity（参考 CodeScan EffectiveSeverity）
# ══════════════════════════════════════════════════════════════════

def get_effective_severity(finding: Dict[str, Any]) -> str:
    """获取有效严重等级（优先使用 reviewed_severity）。"""
    reviewed = str(finding.get("reviewed_severity", "")).strip()
    if reviewed:
        return _normalize_severity(reviewed)
    return _normalize_severity(str(finding.get("severity", "UNKNOWN")))


def _normalize_severity(value: str) -> str:
    """规范化严重等级。"""
    upper = value.strip().upper()
    if upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        return upper
    return "UNKNOWN"


def get_severity_rank(severity: str) -> int:
    """获取严重等级的数值排序。"""
    return _SEVERITY_RANK.get(_normalize_severity(severity), 0)


# ══════════════════════════════════════════════════════════════════
# 阶段专用输出字段（参考 CodeScan stageConfigs）
# ══════════════════════════════════════════════════════════════════

# 每种漏洞类型的专用字段定义（从 finding 中提取用于报告展示）
_STAGE_FIELDS: Dict[str, List[Dict[str, Any]]] = {
    "COMMAND_INJECTION": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "SQL_INJECTION": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "SSRF": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "AUTH_BYPASS": [
        {"key": "auth_mechanism", "label": "认证机制", "code": False},
        {"key": "affected_endpoints", "label": "受影响接口", "code": True},
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc_http", "label": "HTTP POC", "code": True},
        {"key": "trigger_steps", "label": "触发步骤", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "XSS": [
        {"key": "sink_type", "label": "危险汇点类型", "code": False},
        {"key": "render_context", "label": "渲染上下文", "code": False},
        {"key": "payload_hint", "label": "Payload 提示", "code": True},
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc_http", "label": "HTTP POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "PATH_TRAVERSAL": [
        {"key": "file_operation", "label": "文件操作类型", "code": False},
        {"key": "input_vector", "label": "输入向量", "code": False},
        {"key": "target_path", "label": "目标路径", "code": False},
        {"key": "validation_logic", "label": "校验逻辑", "code": True},
        {"key": "payload_hint", "label": "Payload 提示", "code": True},
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "DESERIALIZATION": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "XXE": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "FILE_UPLOAD": [
        {"key": "file_operation", "label": "文件操作类型", "code": False},
        {"key": "validation_logic", "label": "校验逻辑", "code": True},
        {"key": "payload_hint", "label": "Payload 提示", "code": True},
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
    "HARD_CODED_SECRET": [
        {"key": "secret_type", "label": "凭据类型", "code": False},
        {"key": "exposure_mechanism", "label": "暴露机制", "code": True},
        {"key": "upgrade_recommendation", "label": "修复建议", "code": True},
    ],
    "CODE_INJECTION": [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "poc", "label": "POC", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ],
}


def get_stage_fields(vul_name: str) -> List[Dict[str, Any]]:
    """获取指定漏洞类型的专用字段定义。"""
    if vul_name in _STAGE_FIELDS:
        return _STAGE_FIELDS[vul_name]
    # 模糊匹配
    vul_upper = vul_name.upper().replace(" ", "_").replace("-", "_")
    for key, fields in _STAGE_FIELDS.items():
        if key in vul_upper or vul_upper in key:
            return fields
    # 通用字段
    return [
        {"key": "execution_logic", "label": "执行逻辑", "code": True},
        {"key": "vulnerable_code", "label": "漏洞代码", "code": True},
        {"key": "impact", "label": "影响", "code": True},
    ]


def extract_stage_fields(finding: Dict[str, Any], vul_name: str) -> List[Dict[str, Any]]:
    """从 finding 中提取阶段专用字段（用于报告展示）。

    Returns:
        [{"label": "执行逻辑", "value": "...", "code": True}, ...]
    """
    fields_def = get_stage_fields(vul_name)
    extracted = []
    used_keys = set()

    for field_def in fields_def:
        key = field_def["key"]
        value = finding.get(key)
        if value is None:
            continue
        str_val = _format_value(value)
        if not str_val:
            continue
        extracted.append({
            "label": field_def["label"],
            "value": str_val,
            "code": field_def.get("code", False),
        })
        used_keys.add(key)

    # 提取未被标准字段覆盖的额外字段
    skip_keys = {
        "title", "file", "line", "end_line", "function", "reason",
        "severity", "type", "verification_status", "reviewed_severity",
        "verification_reason", "origin", "location", "confidence",
        "code_snippet", "codeSnippet", "guardContext", "sanitizer_detected",
        "_filter_score", "_filter_reason", "_file_lines", "status",
        "validated_code", "corrected_from", "validation_note",
    }
    skip_keys.update(used_keys)

    for key, value in finding.items():
        if key in skip_keys:
            continue
        str_val = _format_value(value)
        if not str_val:
            continue
        extracted.append({
            "label": _pretty_label(key),
            "value": str_val,
            "code": _should_use_code_block(key, str_val),
        })

    return extracted


def _format_value(value: Any) -> str:
    """格式化值为字符串。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        parts = [str(v).strip() for v in value if str(v).strip()]
        return "\n".join(parts)
    if isinstance(value, dict):
        import json
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value).strip()


def _pretty_label(key: str) -> str:
    """将 key 转换为可读标签。"""
    label = key.replace("_", " ").strip()
    parts = label.split()
    return " ".join(p.capitalize() for p in parts) if parts else key


def _should_use_code_block(key: str, value: str) -> bool:
    """判断是否应使用代码块展示。"""
    code_keys = {
        "poc", "poc_http", "vulnerable_code", "execution_logic",
        "trigger_steps", "impact", "affected_endpoints", "validation_logic",
        "payload_hint", "upgrade_recommendation", "exposure_mechanism",
        "reproduction_steps", "bypass_vector", "code_snippet",
    }
    if key.lower() in code_keys:
        return True
    if "\n" in value:
        return True
    return len(value) > 140


# ══════════════════════════════════════════════════════════════════
# 统一后处理入口
# ══════════════════════════════════════════════════════════════════

def postprocess_findings(
    findings: List[Dict[str, Any]],
    vul_name: str = "",
) -> Dict[str, Any]:
    """统一的 finding 后处理。

    1. 过滤出活跃 findings
    2. 计算有效严重等级
    3. 提取阶段专用字段
    4. 按严重等级排序
    5. 统计各等级数量

    Returns:
        {
            "active_findings": [...],
            "rejected_findings": [...],
            "severity_breakdown": {"CRITICAL": 2, "HIGH": 5, ...},
            "highest_severity": "CRITICAL",
            "total_active": 7,
            "total_rejected": 1,
        }
    """
    active = get_active_findings(findings)
    rejected = get_rejected_findings(findings)

    # 计算有效严重等级并排序
    for f in active:
        f["_effective_severity"] = get_effective_severity(f)

    active.sort(key=lambda f: -get_severity_rank(f.get("_effective_severity", "UNKNOWN")))

    # 严重等级统计
    severity_counts: Dict[str, int] = {}
    for f in active:
        sev = f.get("_effective_severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    highest = "UNKNOWN"
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if severity_counts.get(sev, 0) > 0:
            highest = sev
            break

    # 提取阶段专用字段（如果指定了漏洞类型）
    if vul_name:
        for f in active:
            f["_stage_fields"] = extract_stage_fields(f, vul_name)

    return {
        "active_findings": active,
        "rejected_findings": rejected,
        "severity_breakdown": severity_counts,
        "highest_severity": highest,
        "total_active": len(active),
        "total_rejected": len(rejected),
    }


def postprocess_and_log(
    findings: List[Dict[str, Any]],
    vul_name: str = "",
    task_id: str = "",
) -> Dict[str, Any]:
    """后处理并记录日志。"""
    result = postprocess_findings(findings, vul_name)

    logger.info(
        "[task=%s] %s: 活跃=%d, 驳回=%d, 最高等级=%s, 分布=%s",
        task_id, vul_name or "unknown",
        result["total_active"], result["total_rejected"],
        result["highest_severity"], result["severity_breakdown"],
    )

    return result
