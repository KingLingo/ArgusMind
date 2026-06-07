# -*- coding utf-8 -*-
"""HTML 审计报告生成器 —— 整合自 gbt-codeagent/services/reportWriter.js。

生成包含以下内容的 HTML 报告：
1. 审计评分卡片（分数环 + 门禁判定）
2. 漏洞统计概览（按严重等级/来源/类型）
3. 漏洞详情列表（代码片段 + 证据 + 修复建议）
4. 覆盖率报告
5. 组件漏洞信息
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def _escape(text: str) -> str:
    """HTML 转义。"""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def _format_beijing_time(iso_string: str) -> str:
    """格式化时间为北京时间。"""
    if not iso_string:
        return ""
    try:
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return iso_string


def _score_ring_class(score: int) -> str:
    """根据评分返回 CSS 类名。"""
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    return "low"


def _severity_badge_class(severity: str) -> str:
    """根据严重等级返回 CSS 类名。"""
    s = str(severity).upper()
    if s in ("C", "CRITICAL", "严重"):
        return "critical"
    if s in ("H", "HIGH", "高危"):
        return "high"
    if s in ("M", "MEDIUM", "中危"):
        return "medium"
    return "low"


def _severity_label(severity: str) -> str:
    """获取严重等级中文标签。"""
    s = str(severity).upper()
    if s in ("C", "CRITICAL"):
        return "Critical"
    if s in ("H", "HIGH"):
        return "High"
    if s in ("M", "MEDIUM"):
        return "Medium"
    if s in ("L", "LOW"):
        return "Low"
    return severity

SCAN_SOURCES = frozenset({"quick_scan", "component_scan", "pattern_analyzer", "gapfill", "file_review"})


# ---------- HTML 报告入口 ----------


def generate_html_report(
    task_id: str,
    project_name: str,
    findings: List[Dict[str, Any]],
    audit_score: Optional[Dict[str, Any]] = None,
    coverage_report: Optional[Dict[str, Any]] = None,
    scan_stats: Optional[Dict[str, Any]] = None,
    quick_scan_findings: Optional[List[Dict[str, Any]]] = None,
    llm_findings: Optional[List[Dict[str, Any]]] = None,
    exploit_chain_report: Optional[Dict[str, Any]] = None,
) -> str:
    """生成完整的 HTML 审计报告。

    Args:
        task_id: 任务 ID
        project_name: 项目名称
        findings: 所有漏洞发现列表
        audit_score: 审计评分结果（来自 calculate_audit_score）
        coverage_report: 覆盖率报告（来自 CoverageTracker.generate_report）
        scan_stats: 扫描统计信息
        quick_scan_findings: 快速扫描发现
        llm_findings: LLM 审计发现

    Returns:
        HTML 字符串
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 分离快速扫描和 LLM 发现
    if quick_scan_findings is None:
        quick_scan_findings = [f for f in findings if f.get("source") in SCAN_SOURCES]
    if llm_findings is None:
        llm_findings = [f for f in findings if f.get("source") not in SCAN_SOURCES]

    # 漏洞统计：分别统计快扫和 LLM，确保与 API 数据一致
    severity_counts = {"C": 0, "H": 0, "M": 0, "L": 0}
    all_reported = (quick_scan_findings or []) + (llm_findings or [])
    for f in all_reported:
        sev = str(f.get("severity", "L")).upper()
        if sev in ("C", "CRITICAL", "严重"):
            severity_counts["C"] += 1
        elif sev in ("H", "HIGH", "高危"):
            severity_counts["H"] += 1
        elif sev in ("M", "MEDIUM", "中危"):
            severity_counts["M"] += 1
        else:
            severity_counts["L"] += 1

    total_findings = len(all_reported)

    # 构建 HTML
    doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>审计报告 - {_escape(project_name)}</title>
  <style>
    body{{font-family:Segoe UI,PingFang SC,sans-serif;margin:0;background:#f0f5ff;color:#1a1a1a}}
    main{{max-width:1120px;margin:0 auto;padding:32px 20px 64px}}
    .card{{background:#fff;border:1px solid #dbeafe;border-radius:24px;padding:22px;box-shadow:0 18px 40px rgba(59,130,246,.12);margin-bottom:20px}}
    .score-card{{display:flex;align-items:center;gap:20px;margin:12px 0;padding:12px 18px;border-radius:16px;background:#fff;border:1px solid #e0e7ff;flex-wrap:wrap}}
    .score-ring{{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;flex-shrink:0}}
    .score-ring.high{{background:#d1fae5;color:#065f46;border:3px solid #6ee7b7}}
    .score-ring.medium{{background:#fef3c7;color:#92400e;border:3px solid #fcd34d}}
    .score-ring.low{{background:#fecaca;color:#991b1b;border:3px solid #fca5a5}}
    .score-detail{{flex:1;min-width:200px}}
    .score-detail .counts{{display:flex;gap:14px;flex-wrap:wrap;font-size:13px}}
    .score-detail .counts span{{white-space:nowrap}}
    .score-gate{{padding:4px 12px;border-radius:999px;font-size:12px;font-weight:600}}
    .score-gate.pass{{background:#d1fae5;color:#065f46}}
    .score-gate.fail{{background:#fecaca;color:#991b1b}}
    .hero{{background:linear-gradient(135deg,#eff6ff,#dbeafe)}}
    .hero h1,.project h3,.finding h4,.sub-card h4{{font-family:Georgia,Noto Serif SC,serif}}
    .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:18px}}
    .metric{{padding:14px;border-radius:16px;background:#f0f5ff;border:1px solid #bfdbfe}}
    .sub-card{{margin-top:16px;padding:16px;border-radius:18px;background:#f0f5ff;border:1px solid #bfdbfe}}
    .finding{{border-top:1px solid #dbeafe;padding-top:14px;margin-top:14px}}
    .badge{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#dbeafe}}
    .badge.critical{{background:#fecaca;color:#991b1b}}
    .badge.high{{background:#fed7aa;color:#92400e}}
    .badge.medium{{background:#bfdbfe;color:#1e40af}}
    .badge.low{{background:#dbeafe;color:#3b82f6}}
    .badge.source-quick{{background:#e0e7ff}}
    .badge.source-llm{{background:#dbeafe}}
    .badge.source-component{{background:#fef3c7;color:#92400e}}
    .muted{{color:#667eea}}
    .tag{{display:inline-block;margin:0 8px 8px 0;padding:6px 10px;border-radius:999px;background:#dbeafe;font-size:12px}}
    .code-context{{margin:8px 0;padding:10px;border-radius:8px;background:#1a1a1a;color:#10b981;font-size:12px;overflow-x:auto;white-space:pre;font-family:Consolas,Monaco,monospace}}
    .ast-context{{margin-top:12px;padding:12px;border-radius:12px;background:#f0fdf4;border:1px solid #86efac;font-size:13px}}
    .ast-context p{{margin:4px 0}}
    .callout{{padding:14px 16px;border-radius:18px;border:1px solid #bfdbfe;background:#eff6ff;margin-top:18px}}
    a{{color:#2563eb}}
    .finding-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}}
    .finding-meta{{font-size:13px;color:#666;margin-top:6px}}
    .coverage-bar{{height:8px;border-radius:4px;background:#e0e7ff;overflow:hidden;margin-top:6px}}
    .coverage-fill{{height:100%;border-radius:4px;transition:width 0.3s}}
    .coverage-fill.high{{background:#6ee7b7}}
    .coverage-fill.medium{{background:#fcd34d}}
    .coverage-fill.low{{background:#fca5a5}}
    table{{width:100%;border-collapse:collapse;margin-top:12px}}
    th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #e0e7ff;font-size:13px}}
    th{{background:#f0f5ff;font-weight:600}}
    @media (max-width:900px){{.grid{{grid-template-columns:1fr}}.finding-head{{display:block}}}}
  </style>
</head>
<body>
  <main>
    {_build_hero_section(task_id, project_name, now, total_findings, severity_counts, scan_stats, findings)}
    {_build_score_section(audit_score, severity_counts)}
    {_build_findings_section("快速扫描结果", quick_scan_findings, "source-quick", "规则层未发现高置信度结果。")}
    {_build_findings_section("LLM 深度审计结果", llm_findings, "source-llm", "LLM 未发现额外漏洞。")}
    {_build_exploit_chain_section(exploit_chain_report)}
    {_build_coverage_section(coverage_report)}
  </main>
</body>
</html>"""
    return doc


def _build_hero_section(
    task_id: str,
    project_name: str,
    now: str,
    total_findings: int,
    severity_counts: Dict[str, int],
    scan_stats: Optional[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> str:
    """构建报告头部区域。"""
    stats_html = ""
    if scan_stats:
        stats_html = f"""
      <div class="grid">
        <div class="metric"><strong>扫描文件数</strong><br/>{_escape(str(scan_stats.get('total_files_scanned', 0)))}</div>
        <div class="metric"><strong>代码发现</strong><br/>{_escape(str(scan_stats.get('code_findings', 0)))}</div>
        <div class="metric"><strong>组件漏洞</strong><br/>{_escape(str(scan_stats.get('component_findings', 0)))}</div>
        <div class="metric"><strong>总发现数</strong><br/>{_escape(str(total_findings))}</div>
      </div>"""

    # 收集审计技能标签
    skill_tags_set: set = set()
    for f in findings:
        vt = f.get("vuln_type", "") or ""
        if "INJECTION" in vt or "COMMAND" in vt or "SQL" in vt:
            skill_tags_set.add("查询与注入")
        if "PATH_TRAVERSAL" in vt or "FILE" in vt or "UPLOAD" in vt:
            skill_tags_set.add("上传与存储")
        if "AUTH" in vt or "IDOR" in vt or "ACCESS" in vt:
            skill_tags_set.add("访问控制")
        if "XSS" in vt:
            skill_tags_set.add("XSS防护")
        if "SSRF" in vt or "XXE" in vt:
            skill_tags_set.add("SSRF/XXE")
        if "CRYPTO" in vt or "HASH" in vt or "PASSWORD" in vt or "CREDENTIALS" in vt:
            skill_tags_set.add("加密审计")
        if "DESERIALIZATION" in vt or "SERIALIZATION" in vt:
            skill_tags_set.add("反序列化")
        if "COMPONENT" in vt:
            skill_tags_set.add("供应链安全")
        if "CONFIG" in vt or "CORS" in vt:
            skill_tags_set.add("配置审计")
    skill_tags_set.add("GB/T 国标代码安全审计")
    skill_tags = "".join(f'<span class="tag">{_escape(t)}</span>' for t in sorted(skill_tags_set))

    return f"""
    <section class="card hero">
      <h1>防御性代码审计报告</h1>
      <p class="muted">报告分为两层：规则型快速扫描，以及 LLM 深度复核。全程不包含利用方式或攻击载荷。</p>
      <div class="grid">
        <div class="metric"><strong>任务 ID</strong><br/>{_escape(task_id)}</div>
        <div class="metric"><strong>项目名称</strong><br/>{_escape(project_name)}</div>
        <div class="metric"><strong>生成时间</strong><br/>{_escape(now)}</div>
        <div class="metric"><strong>确认结果</strong><br/>{_escape(str(total_findings))}</div>
      </div>
      {stats_html}
      <div class="callout">
        <strong>执行摘要</strong>
        <p>本次审计共发现 {total_findings} 个潜在安全漏洞（Critical: {severity_counts['C']}，High: {severity_counts['H']}，Medium: {severity_counts['M']}，Low: {severity_counts['L']}）。规则引擎基于 sink 模式匹配快速扫描代码仓库，识别出命令注入、SQL注入、路径遍历、XSS、SSRF 等攻击面。如果某个文件没有发现报告，不代表绝对安全，只表示当前规则集下未匹配到高置信度问题。</p>
        <div class="counts">
          <span style="color:#991b1b">Critical: {severity_counts['C']}</span> &nbsp;
          <span style="color:#92400e">High: {severity_counts['H']}</span> &nbsp;
          <span style="color:#1e40af">Medium: {severity_counts['M']}</span> &nbsp;
          <span style="color:#3b82f6">Low: {severity_counts['L']}</span>
        </div>
      </div>
      {f'<div style="margin-top:16px">{skill_tags}</div>' if skill_tags else ''}
    </section>"""


def _build_score_section(
    audit_score: Optional[Dict[str, Any]],
    severity_counts: Dict[str, int],
) -> str:
    """构建评分卡片区域。"""
    if not audit_score:
        return ""

    score = audit_score.get("score", 0)
    grade = audit_score.get("grade", "D")
    grade_desc = audit_score.get("grade_desc", "")
    gate = audit_score.get("gate", "fail")
    gate_reason = audit_score.get("gate_reason", "")
    ring_class = _score_ring_class(score)
    gate_class = "pass" if gate == "pass" else "fail"
    gate_label = "通过" if gate == "pass" else "未通过"

    return f"""
    <section class="card">
      <h2>审计评分</h2>
      <div class="score-card">
        <div class="score-ring {ring_class}">{score}</div>
        <div class="score-detail">
          <strong>安全评分: {score}/100 ({grade} — {grade_desc})</strong>
          <div class="counts">
            <span style="color:#991b1b">Critical: {severity_counts['C']}</span>
            <span style="color:#92400e">High: {severity_counts['H']}</span>
            <span style="color:#1e40af">Medium: {severity_counts['M']}</span>
            <span style="color:#3b82f6">Low: {severity_counts['L']}</span>
          </div>
        </div>
        <span class="score-gate {gate_class}">{gate_label}: {_escape(gate_reason)}</span>
      </div>
    </section>"""


def _build_findings_section(
    title: str,
    findings: List[Dict[str, Any]],
    source_badge_class: str,
    empty_message: str,
) -> str:
    """构建漏洞发现列表区域。"""
    if not findings:
        return f"""
    <section class="card">
      <h2>{_escape(title)}</h2>
      <p class="muted">{_escape(empty_message)}</p>
    </section>"""

    findings_html = ""
    for idx, f in enumerate(findings):
        findings_html += _render_finding(idx + 1, f, source_badge_class)

    return f"""
    <section class="card">
      <h2>{_escape(title)} ({len(findings)} 条)</h2>
      {findings_html}
    </section>"""


def _render_finding(index: int, f: Dict[str, Any], source_badge_class: str) -> str:
    """渲染单个漏洞发现。"""
    severity = f.get("severity", "L")
    badge_class = _severity_badge_class(severity)
    severity_label = _severity_label(severity)
    title = f.get("title", f.get("vul_name", "未知漏洞"))
    vuln_type = f.get("vuln_type", f.get("vulnType", ""))
    location = f.get("location", f.get("file", ""))
    cvss_score = f.get("cvss_score", f.get("cvssScore", 0))
    cvss_raw = f.get("cvss_score_raw", cvss_score)
    owasp = f.get("owasp", "")
    gbt_mapping = f.get("gbt_mapping", f.get("gbtMapping", ""))
    cwe = f.get("cwe", "")
    evidence = f.get("evidence", f.get("reason", ""))
    impact_desc = f.get("impact_description", f.get("impact", ""))
    remediation = f.get("remediation", "")
    safe_validation = f.get("safe_validation", f.get("safeValidation", ""))
    verification_note = f.get("verification_note", "")
    ast_context = f.get("ast_context", {})
    code_snippet = f.get("code_snippet", f.get("codeSnippet", ""))
    confidence = f.get("confidence", 0)
    source = f.get("source", "unknown")
    cve = f.get("cve", "")
    language = f.get("language", "")
    sink = f.get("sink", [])
    evidence_points = f.get("evidence_points", [])

    # 代码片段
    snippet_html = ""
    if code_snippet:
        snippet_html = f'<pre class="code-context">{_escape(str(code_snippet))}</pre>'

    # CVE 标签
    cve_html = f'<span class="badge">{_escape(cve)}</span> ' if cve else ""

    # CWE 标签
    cwe_html = f'<span class="badge">{_escape(cwe)}</span> ' if cwe else ""

    # 置信度
    conf_pct = int(confidence * 100) if isinstance(confidence, (int, float)) else 0

    # 来源标签
    source_label = {"quick_scan": "规则扫描", "component_scan": "组件扫描", "pattern_analyzer": "模式匹配", "gapfill": "覆盖盲区", "file_review": "文件审计", "llm": "LLM复核"}.get(source, source)

    # Sink + 证据点摘要
    sink_html = ""
    if sink or evidence_points:
        parts = []
        if sink:
            parts.append(f'<strong>危险Sink:</strong> {_escape(", ".join(sink) if isinstance(sink, list) else str(sink))}')
        if evidence_points:
            parts.append(f'<strong>证据点:</strong> {_escape(", ".join(evidence_points) if isinstance(evidence_points, list) else str(evidence_points))}')
        sink_html = f'<p>{" &nbsp;|&nbsp; ".join(parts)}</p>'

    # AST 深度分析
    ast_html = ""
    if isinstance(ast_context, dict) and ast_context.get("sink"):
        ac = ast_context
        ast_html = f"""
      <div class="ast-context">
        <p><strong>--- AST 深度分析 ---</strong></p>
        <p><strong>危险sink：</strong>{_escape(str(ac.get('sink', 'n/a')))} ({_escape(str(ac.get('sink_severity', ac.get('sinkSeverity', 'n/a'))))})</p>
        <p><strong>风险描述：</strong>{_escape(str(ac.get('sink_desc', 'n/a')))}</p>
        <p><strong>用户输入检测：</strong>{'✓ 有' if ac.get('has_user_input') else '✗ 无'}</p>
        <p><strong>输入验证：</strong>{'✓ 有' if ac.get('has_validation') else '✗ 无'}</p>
        <p><strong>编码处理：</strong>{'✓ 有' if ac.get('has_encoding') else '✗ 无'}</p>
        {f'<p><strong>深度建议：</strong>{_escape(str(ac.get("recommendation", "")))}</p>' if ac.get('recommendation') else ''}
      </div>"""

    return f"""
      <div class="finding">
        <div class="finding-head">
          <h4>{index}. {_escape(str(title))}</h4>
          <div>
            <span class="badge {badge_class}">{severity_label}</span>
            <span class="badge {source_badge_class}">{_escape(source_label)}</span>
            {cve_html}
            {cwe_html}
          </div>
        </div>
        <div class="finding-meta">
          <strong>位置:</strong> {_escape(str(location))} &nbsp;
          <strong>CVSS:</strong> {_escape(str(cvss_score))} &nbsp;
          {f'<strong>编程语言:</strong> {_escape(str(language))} &nbsp;' if language else ''}
          <strong>置信度:</strong> {conf_pct}% &nbsp;
          {f'<strong>OWASP:</strong> {_escape(str(owasp))} &nbsp;' if owasp else ''}
          {f'<strong>国标:</strong> {_escape(str(gbt_mapping))} &nbsp;' if gbt_mapping else ''}
        </div>
        {f'<p><strong>漏洞类型:</strong> {_escape(str(vuln_type))}</p>' if vuln_type else ''}
        {f'<p class="muted">验证说明：{_escape(str(verification_note))}</p>' if verification_note else ''}
        {f'<p><strong>证据:</strong> {_escape(str(evidence))}</p>' if evidence else ''}
        {f'<p><strong>影响:</strong> {_escape(str(impact_desc))}</p>' if impact_desc else ''}
        {f'<p><strong>修复建议:</strong> {_escape(str(remediation))}</p>' if remediation else ''}
        {f'<p><strong>安全验证建议:</strong> {_escape(str(safe_validation))}</p>' if safe_validation else ''}
        {sink_html}
        {snippet_html}
        {ast_html}
      </div>"""


def _build_coverage_section(coverage_report: Optional[Dict[str, Any]]) -> str:
    """构建覆盖率区域。"""
    if not coverage_report:
        return ""

    total = coverage_report.get("total_files", 0)
    reviewed = coverage_report.get("reviewed_files", 0)
    rate = coverage_report.get("coverage_rate", 0)
    unreviewed = coverage_report.get("unreviewed_code_files", 0)
    attack_classes = coverage_report.get("reviewed_attack_classes", [])
    gaps = coverage_report.get("subsystem_gaps", {})
    # total 包含非代码文件，单独计算
    non_code = max(0, total - reviewed - unreviewed)

    # 覆盖率进度条
    fill_class = "high" if rate >= 80 else ("medium" if rate >= 50 else "low")

    # 攻击类型标签
    attack_tags = " ".join(
        f'<span class="badge">{_escape(cls)}</span>' for cls in attack_classes[:10]
    )

    # 子系统盲区表格
    gap_rows = ""
    for subsys, count in list(gaps.items())[:10]:
        gap_rows += f"<tr><td>{_escape(subsys)}</td><td>{count}</td></tr>"

    gap_table = ""
    if gap_rows:
        gap_table = f"""
      <table>
        <tr><th>子系统</th><th>未审查文件数</th></tr>
        {gap_rows}
      </table>"""

    return f"""
    <section class="card">
      <h2>审计覆盖率</h2>
      <div class="score-card">
        <div class="score-ring {fill_class}">{rate:.0f}%</div>
        <div class="score-detail">
          <strong>覆盖率: {rate:.1f}%</strong>
          <div class="counts">
            <span>总文件: {total}</span>
            <span>已审查: {reviewed}</span>
            <span>未审查代码文件: {unreviewed}</span>
            {f'<span>非代码文件: {non_code}</span>' if non_code > 0 else ''}
          </div>
        </div>
      </div>
      <div class="coverage-bar">
        <div class="coverage-fill {fill_class}" style="width:{min(rate, 100)}%"></div>
      </div>
      {f'<div style="margin-top:12px"><strong>已检查攻击类型:</strong> {attack_tags}</div>' if attack_tags else ''}
      {f'<div class="sub-card"><h4>未覆盖子系统</h4>{gap_table}</div>' if gap_table else ''}
    </section>"""


def _build_exploit_chain_section(chain_report: Optional[Dict[str, Any]]) -> str:
    """构建利用链分析区域。"""
    if not chain_report or not chain_report.get("chains"):
        return ""

    chains = chain_report["chains"]
    summary = chain_report.get("summary", {})

    chains_html = ""
    for i, chain in enumerate(chains):
        entries_html = ""
        for entry in chain.get("entries", []):
            sev_class = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium"}.get(
                str(entry.get("severity", "")).lower(), "sev-low"
            )
            entries_html += (
                f'<div class="finding {sev_class}" style="padding:6px 10px;margin:4px 0;border-radius:8px">'
                f'<strong>{_escape(entry.get("type", ""))}</strong> '
                f'<span style="color:#6b7280;font-size:12px">{_escape(entry.get("location", ""))}</span> '
                f'<span class="badge" style="font-size:11px">{_escape(str(entry.get("severity", "")))}</span>'
                f'</div>'
            )

        connections = chain.get("connections", [])
        conn_html = ""
        if connections:
            for conn in connections:
                conn_html += (
                    f'<span class="badge" style="background:#e0e7ff;color:#3730a3;font-size:11px;margin:2px">'
                    f'{_escape(conn.get("type", ""))}</span> '
                )

        risk_score = chain.get("risk_score", 0)
        risk_class = "sev-critical" if risk_score >= 80 else "sev-high" if risk_score >= 60 else "sev-medium"

        chains_html += (
            f'<div class="sub-card" style="margin-top:12px">'
            f'<h4>利用链 #{i + 1} '
            f'<span class="badge {risk_class}" style="font-size:11px">风险评分: {risk_score}</span></h4>'
            f'<div style="margin:8px 0">{entries_html}</div>'
            f'<div style="margin-top:6px">连接: {conn_html}</div>'
            f'<p style="font-size:13px;color:#4b5563;margin-top:8px">{_escape(chain.get("description", ""))}</p>'
            f'</div>'
        )

    total_chains = chain_report.get("total_chains", 0)
    max_risk = summary.get("max_risk_score", 0)

    return f"""
    <section class="card">
      <h2>利用链分析 <span class="badge" style="background:#fef3c7;color:#92400e">{total_chains} 条链</span></h2>
      <div style="display:flex;gap:20px;margin:12px 0;flex-wrap:wrap">
        <div class="metric"><strong>利用链数</strong><br/>{total_chains}</div>
        <div class="metric"><strong>最高风险评分</strong><br/>{max_risk}</div>
      </div>
      {chains_html}
    </section>"""


def write_report_to_file(
    report_dir: str,
    task_id: str,
    project_name: str,
    findings: List[Dict[str, Any]],
    audit_score: Optional[Dict[str, Any]] = None,
    coverage_report: Optional[Dict[str, Any]] = None,
    scan_stats: Optional[Dict[str, Any]] = None,
    quick_scan_findings: Optional[List[Dict[str, Any]]] = None,
    llm_findings: Optional[List[Dict[str, Any]]] = None,
    exploit_chain_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """生成 HTML 报告并写入文件。

    Returns:
        包含 file_path 和 download_path 的字典
    """
    os.makedirs(report_dir, exist_ok=True)
    file_name = f"audit-report-{task_id}.html"
    file_path = os.path.join(report_dir, file_name)

    html_content = generate_html_report(
        task_id=task_id,
        project_name=project_name,
        findings=findings,
        audit_score=audit_score,
        coverage_report=coverage_report,
        scan_stats=scan_stats,
        quick_scan_findings=quick_scan_findings,
        llm_findings=llm_findings,
        exploit_chain_report=exploit_chain_report,
    )

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return {
        "file_name": file_name,
        "file_path": file_path,
        "download_path": f"/reports/{file_name}",
    }
