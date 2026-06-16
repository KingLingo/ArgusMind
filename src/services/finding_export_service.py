# -*- coding: utf-8 -*-
"""漏洞导出服务 —— 多格式导出（Excel / CSV / Markdown / SARIF / JSON）。

所有格式共用一条取数与归一化路径（``collect_findings``），保证字段一致。
SARIF 2.1.0 便于接入 GitHub Code Scanning / CI；Markdown 便于归档与人工评审；
CSV 便于表格分析；JSON 便于二次处理。
"""
from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.schemas.vulnerability import FindingFilter

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("xlsx", "csv", "md", "markdown", "sarif", "json")

# 严重等级 → SARIF level
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
    "INFORMATIONAL": "note",
}


def _parse_json_field(text: Any) -> Any:
    """尽力把 Text 字段解析为 JSON 对象/数组；失败则原样返回字符串。"""
    if text is None:
        return None
    if isinstance(text, (dict, list)):
        return text
    s = str(text).strip()
    if not s:
        return None
    if s[0] in "[{":
        try:
            return json.loads(s)
        except Exception:
            return s
    return s


def _first_location(*sources: Any) -> Tuple[str, Optional[int]]:
    """从 entry_points / evidence / sink 等结构里尽力提取 (file, line)。"""
    def _scan(obj: Any) -> Tuple[str, Optional[int]]:
        if isinstance(obj, dict):
            file = obj.get("file") or obj.get("file_path") or obj.get("path") or obj.get("location")
            line = obj.get("line") or obj.get("line_number") or obj.get("startLine")
            if file:
                try:
                    line_int = int(line) if line is not None else None
                except (TypeError, ValueError):
                    line_int = None
                return str(file), line_int
            # 没命中则深入子结构
            for v in obj.values():
                f, ln = _scan(v)
                if f:
                    return f, ln
        elif isinstance(obj, list):
            for item in obj:
                f, ln = _scan(item)
                if f:
                    return f, ln
        return "", None

    for src in sources:
        parsed = _parse_json_field(src)
        f, ln = _scan(parsed)
        if f:
            return f, ln
    return "", None


def _flatten(vuln, detail) -> Dict[str, Any]:
    """把 Vulnerability(+detail) ORM 行展平为脱离 session 的纯 dict。"""
    d = detail
    file, line = _first_location(
        getattr(d, "entry_points", None) if d else None,
        getattr(d, "sink", None) if d else None,
        getattr(d, "evidence", None) if d else None,
    )
    created = getattr(vuln, "created_at", None)
    return {
        "id": str(getattr(vuln, "id", "") or ""),
        "project_id": getattr(vuln, "project_id", "") or "",
        "task_id": str(getattr(vuln, "task_id", "") or ""),
        "vul_name": getattr(vuln, "vul_name", "") or "",
        "category_name": getattr(vuln, "category_name", "") or "",
        "level": (getattr(vuln, "level", "") or "").upper(),
        "verdict": getattr(vuln, "verdict", "") or "",
        "verification_status": getattr(vuln, "verification_status", "") or "",
        "status": getattr(vuln, "status", "") or "",
        "confidence": getattr(vuln, "confidence", "") or "",
        "source": getattr(vuln, "source", "") or "",
        "neo4j_element_id": getattr(vuln, "neo4j_element_id", "") or "",
        "created_at": created.strftime("%Y-%m-%d %H:%M:%S") if created else "",
        # detail
        "cwe": (getattr(d, "cwe", "") or "") if d else "",
        "cve": (getattr(d, "cve", "") or "") if d else "",
        "owasp": (getattr(d, "owasp", "") or "") if d else "",
        "gbt_mapping": (getattr(d, "gbt_mapping", "") or "") if d else "",
        "cvss_score": (getattr(d, "cvss_score", "") or "") if d else "",
        "language": (getattr(d, "language", "") or "") if d else "",
        "file": file,
        "line": line,
        "code_snippet": (getattr(d, "code_snippet", "") or "") if d else "",
        "detail": (getattr(d, "detail", "") or "") if d else "",
        "remediation": (getattr(d, "remediation", "") or "") if d else "",
        "impact": (getattr(d, "impact", "") or "") if d else "",
        "verification_reason": (getattr(d, "verification_reason", "") or "") if d else "",
        "analysis_report": (getattr(d, "vulnerability_analysis_report", "") or "") if d else "",
        "poc": (getattr(d, "poc", "") or "") if d else "",
    }


def collect_findings(flt: FindingFilter, limit: int = 5000) -> List[Dict[str, Any]]:
    """按过滤条件取漏洞并展平为纯 dict 列表（已脱离 DB session）。"""
    from src.infrastructure.db import session_scope
    from src.repositories.vulnerability_repository import VulnerabilityRepository

    with session_scope() as session:
        rows, _ = VulnerabilityRepository(session).list(
            project_id=flt.project_id,
            task_id=flt.task_id,
            keyword=flt.keyword,
            severity=flt.severity,
            status=flt.status,
            source=flt.source,
            current=1,
            page_size=limit,
        )
        return [_flatten(r, getattr(r, "detail", None)) for r in rows]


# --------------------------------------------------------------------------- #
# 各格式序列化
# --------------------------------------------------------------------------- #
_COLUMNS = [
    ("id", "ID"), ("vul_name", "漏洞名称"), ("category_name", "类型"),
    ("level", "等级"), ("verdict", "判定"), ("source", "来源"),
    ("status", "状态"), ("verification_status", "二次校验"), ("confidence", "置信度"),
    ("file", "文件"), ("line", "行号"), ("cwe", "CWE"), ("cve", "CVE"),
    ("owasp", "OWASP"), ("cvss_score", "CVSS"), ("language", "语言"),
    ("created_at", "创建时间"),
]


def to_csv(findings: List[Dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label for _, label in _COLUMNS])
    for f in findings:
        writer.writerow([f.get(key, "") if f.get(key) is not None else "" for key, _ in _COLUMNS])
    # 加 BOM，Excel 打开中文不乱码
    return ("﻿" + buf.getvalue()).encode("utf-8")


def to_json(findings: List[Dict[str, Any]]) -> bytes:
    payload = {"total": len(findings), "findings": findings}
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def to_markdown(findings: List[Dict[str, Any]]) -> bytes:
    lines: List[str] = ["# 漏洞审计报告", "", f"共 **{len(findings)}** 条发现。", ""]

    # 汇总表
    lines += ["## 概览", "", "| 等级 | 数量 |", "| --- | --- |"]
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("level") or "UNKNOWN"] = counts.get(f.get("level") or "UNKNOWN", 0) + 1
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(level):
            lines.append(f"| {level} | {counts[level]} |")
    for level, n in counts.items():
        if level not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            lines.append(f"| {level} | {n} |")
    lines.append("")

    # 明细
    lines += ["## 漏洞明细", ""]
    for i, f in enumerate(findings, 1):
        loc = f.get("file") or ""
        if loc and f.get("line"):
            loc = f"{loc}:{f['line']}"
        lines.append(f"### {i}. {f.get('vul_name') or '(未命名)'}  `[{f.get('level') or 'N/A'}]`")
        lines.append("")
        meta = [
            f"- **类型**: {f.get('category_name') or '-'}",
            f"- **判定/置信度**: {f.get('verdict') or '-'} / {f.get('confidence') or '-'}",
            f"- **来源**: {f.get('source') or '-'}　**状态**: {f.get('status') or '-'}",
        ]
        if loc:
            meta.append(f"- **位置**: `{loc}`")
        ref = " ".join(x for x in [
            f"CWE:{f['cwe']}" if f.get("cwe") else "",
            f"CVE:{f['cve']}" if f.get("cve") else "",
            f"OWASP:{f['owasp']}" if f.get("owasp") else "",
            f"CVSS:{f['cvss_score']}" if f.get("cvss_score") else "",
        ] if x)
        if ref:
            meta.append(f"- **关联**: {ref}")
        lines += meta + [""]
        if f.get("detail"):
            lines += ["**描述**", "", str(f["detail"]).strip(), ""]
        if f.get("code_snippet"):
            lang = f.get("language") or ""
            lines += ["**相关代码**", "", f"```{lang}", str(f["code_snippet"]).strip(), "```", ""]
        if f.get("remediation"):
            lines += ["**修复建议**", "", str(f["remediation"]).strip(), ""]
        if f.get("poc"):
            lines += ["**PoC**", "", "```", str(f["poc"]).strip(), "```", ""]
        lines.append("---")
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def to_sarif(findings: List[Dict[str, Any]]) -> bytes:
    """生成 SARIF 2.1.0，可直接喂给 GitHub Code Scanning。"""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = (f.get("cwe") or f.get("category_name") or f.get("vul_name") or "ArgusMind.Finding").strip()
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": (f.get("category_name") or rule_id).replace(" ", ""),
                "shortDescription": {"text": (f.get("category_name") or f.get("vul_name") or rule_id)[:200]},
                "properties": {k: v for k, v in (("cwe", f.get("cwe")), ("owasp", f.get("owasp"))) if v},
            }
        level = _SARIF_LEVEL.get((f.get("level") or "").upper(), "warning")
        message = f.get("vul_name") or f.get("category_name") or "Finding"
        if f.get("detail"):
            message = f"{message}: {str(f['detail'])[:500]}"
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "properties": {
                "verdict": f.get("verdict"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
                "source": f.get("source"),
                "cvss": f.get("cvss_score"),
                "findingId": f.get("id"),
            },
        }
        if f.get("file"):
            region: Dict[str, Any] = {}
            if f.get("line"):
                region["startLine"] = int(f["line"])
            phys: Dict[str, Any] = {"artifactLocation": {"uri": f["file"]}}
            if region:
                phys["region"] = region
            result["locations"] = [{"physicalLocation": phys}]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ArgusMind",
                        "informationUri": "https://github.com/pulseio76/ArgusMind",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2).encode("utf-8")


def to_xlsx(findings: List[Dict[str, Any]]) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "漏洞列表"
    ws.append([label for _, label in _COLUMNS])
    for f in findings:
        ws.append([f.get(key, "") if f.get(key) is not None else "" for key, _ in _COLUMNS])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


_DISPATCH = {
    "xlsx": (to_xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "vulnerabilities.xlsx"),
    "csv": (to_csv, "text/csv; charset=utf-8", "vulnerabilities.csv"),
    "md": (to_markdown, "text/markdown; charset=utf-8", "vulnerabilities.md"),
    "markdown": (to_markdown, "text/markdown; charset=utf-8", "vulnerabilities.md"),
    "sarif": (to_sarif, "application/sarif+json", "vulnerabilities.sarif"),
    "json": (to_json, "application/json; charset=utf-8", "vulnerabilities.json"),
}


def build_export(fmt: str, flt: FindingFilter, limit: int = 5000) -> Tuple[bytes, str, str]:
    """返回 (内容字节, media_type, 文件名)。fmt 不支持时抛 ValueError。"""
    fmt = (fmt or "xlsx").strip().lower()
    if fmt not in _DISPATCH:
        raise ValueError(f"不支持的导出格式: {fmt}（可选: {', '.join(SUPPORTED_FORMATS)}）")
    serializer, media_type, filename = _DISPATCH[fmt]
    findings = collect_findings(flt, limit=limit)
    content = serializer(findings)
    return content, media_type, filename
