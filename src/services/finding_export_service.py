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

SUPPORTED_FORMATS = ("xlsx", "csv", "md", "markdown", "sarif", "json", "pdf")

# 严重等级 → 展示颜色（PDF/标签）
_LEVEL_COLOR = {
    "CRITICAL": "#a8071a",
    "HIGH": "#d4380d",
    "MEDIUM": "#d46b08",
    "LOW": "#389e0d",
    "INFO": "#8c8c8c",
}

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


def to_pdf(findings: List[Dict[str, Any]]) -> bytes:
    """生成 PDF 报告。使用 reportlab 内置 STSong-Light CID 字体渲染中文，无需系统字体。"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, Preformatted,
        )
    except ImportError as e:  # pragma: no cover
        raise ValueError("PDF 导出需要 reportlab，请先安装：pip install reportlab") from e

    from xml.sax.saxutils import escape

    font = "STSong-Light"
    try:
        pdfmetrics.registerFont(UnicodeCIDFont(font))
    except Exception:  # pragma: no cover - 极端环境下回退默认字体
        font = "Helvetica"

    base = getSampleStyleSheet()
    title_style = ParagraphStyle("AMTitle", parent=base["Title"], fontName=font, fontSize=20)
    h2 = ParagraphStyle("AMH2", parent=base["Heading2"], fontName=font, fontSize=13, spaceBefore=10)
    normal = ParagraphStyle("AMBody", parent=base["BodyText"], fontName=font, fontSize=9, leading=13)
    small = ParagraphStyle("AMSmall", parent=normal, fontSize=8, textColor=colors.HexColor("#595959"))
    code_style = ParagraphStyle("AMCode", parent=normal, fontName="Courier", fontSize=8,
                                backColor=colors.HexColor("#f5f5f5"), leftIndent=4, leading=11)

    def _p(text: str, style=normal) -> Paragraph:
        return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), style)

    story: List[Any] = []
    story.append(Paragraph("ArgusMind 漏洞审计报告", title_style))
    story.append(Spacer(1, 4 * mm))

    # 概览表
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.get("level") or "UNKNOWN"] = counts.get(f.get("level") or "UNKNOWN", 0) + 1
    story.append(_p(f"共 {len(findings)} 条发现", small))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    rows = [["等级", "数量"]]
    for lv in order:
        if counts.get(lv):
            rows.append([lv, str(counts[lv])])
    for lv, n in counts.items():
        if lv not in order:
            rows.append([lv, str(n)])
    if len(rows) > 1:
        t = Table(rows, colWidths=[60 * mm, 30 * mm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#fafafa")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9d9d9")),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(Spacer(1, 2 * mm))
        story.append(t)

    # 明细
    story.append(Paragraph("漏洞明细", h2))
    for i, f in enumerate(findings, 1):
        level = f.get("level") or "N/A"
        color = _LEVEL_COLOR.get(level, "#595959")
        story.append(Paragraph(
            f'{i}. {escape(str(f.get("vul_name") or "(未命名)"))} '
            f'<font color="{color}">[{level}]</font>',
            ParagraphStyle("AMItem", parent=h2, fontSize=11, spaceBefore=8),
        ))
        loc = f.get("file") or ""
        if loc and f.get("line"):
            loc = f"{loc}:{f['line']}"
        meta_rows = [
            ["类型", f.get("category_name") or "-", "判定", f.get("verdict") or "-"],
            ["来源", f.get("source") or "-", "置信度", f.get("confidence") or "-"],
            ["位置", loc or "-", "状态", f.get("status") or "-"],
            ["CWE", f.get("cwe") or "-", "OWASP", f.get("owasp") or "-"],
            ["CVE", f.get("cve") or "-", "CVSS", f.get("cvss_score") or "-"],
        ]
        mt = Table(
            [[_p(c, small) for c in r] for r in meta_rows],
            colWidths=[18 * mm, 67 * mm, 18 * mm, 67 * mm],
        )
        mt.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#eeeeee")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fafafa")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#fafafa")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(mt)
        if f.get("detail"):
            story.append(_p("<b>描述</b>", small))
            story.append(_p(f["detail"]))
        if f.get("code_snippet"):
            story.append(_p("<b>相关代码</b>", small))
            snippet = str(f["code_snippet"])[:1500]
            story.append(Preformatted(snippet, code_style))
        if f.get("remediation"):
            story.append(_p("<b>修复建议</b>", small))
            story.append(_p(f["remediation"]))
        story.append(Spacer(1, 3 * mm))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
        title="ArgusMind 漏洞审计报告",
    )
    doc.build(story)
    return buf.getvalue()


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
    "pdf": (to_pdf, "application/pdf", "vulnerabilities.pdf"),
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
