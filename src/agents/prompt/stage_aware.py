# -*- coding: utf-8 -*-
"""阶段感知提示词构建器 —— 参考 CodeScan 的 stageConfigs + adaptPromptForRunKind。

为每种漏洞类型注入：
1. 专用扫描指引（该漏洞类型的 source/sink/safety 模式）
2. 项目热点文件清单（从 ProjectManifest 预扫描结果）
3. 路由上下文（已发现的路由候选文件）
4. Gap Check / Revalidate 模式提示（复跑时注入现有结果）

用法：
    from src.agents.prompt.stage_aware import build_stage_aware_prompt
    enhanced = build_stage_aware_prompt(base_prompt, vul_name, language, manifest, run_kind="initial")
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# ══════════════════════════════════════════════════════════════════
# 漏洞类型 → 专用扫描指引（参考 CodeScan stageConfigs）
# ══════════════════════════════════════════════════════════════════

_STAGE_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "COMMAND_INJECTION": {
        "label": "命令注入",
        "source_patterns": [
            "request.getParameter, @RequestParam, @PathVariable, @RequestBody",
            "req.query, req.body, req.params",
            "sys.argv, os.environ, input()",
        ],
        "sink_patterns": [
            "Runtime.exec(), ProcessBuilder, os.system(), subprocess.Popen()",
            "child_process.exec(), child_process.spawn(), execSync()",
            "exec(), system(), popen(), shell_exec()",
        ],
        "safety_patterns": [
            "白名单验证命令名称",
            "使用参数数组而非字符串拼接",
            "execFile() 替代 exec()",
        ],
        "scan_keywords": ["exec", "system", "popen", "subprocess", "ProcessBuilder", "Runtime", "command", "cmd", "shell"],
    },
    "SQL_INJECTION": {
        "label": "SQL注入",
        "source_patterns": [
            "request.getParameter, @RequestParam, @PathVariable, @RequestBody",
            "req.query, req.body, req.params",
            "input(), sys.argv",
        ],
        "sink_patterns": [
            "Statement/JdbcTemplate 拼接, MyBatis ${}, HQL 拼接",
            "mysql.query(拼接), sequelize.query(拼接)",
            "cursor.execute(拼接), ORM.raw()",
        ],
        "safety_patterns": [
            "PreparedStatement, MyBatis #{}, JPA :param",
            "mysql2.execute(), sequelize bind, Prisma ORM",
            "参数化查询, 占位符绑定",
        ],
        "scan_keywords": ["SELECT", "INSERT", "UPDATE", "DELETE", "query", "execute", "sql", "Raw", "createQuery", "JdbcTemplate"],
    },
    "SSRF": {
        "label": "服务端请求伪造",
        "source_patterns": [
            "request.getParameter, @RequestParam",
            "req.query, req.body",
        ],
        "sink_patterns": [
            "HttpURLConnection, RestTemplate, WebClient(用户可控 URL)",
            "requests.get/post, urllib, fetch(), axios",
        ],
        "safety_patterns": [
            "域名白名单, 内网地址过滤",
            "URL scheme 限制",
        ],
        "scan_keywords": ["HttpURLConnection", "RestTemplate", "WebClient", "HttpClient", "requests.get", "requests.post", "fetch", "axios", "urllib", "URL"],
    },
    "DESERIALIZATION": {
        "label": "反序列化",
        "source_patterns": [
            "@RequestBody, request body, 文件上传内容",
        ],
        "sink_patterns": [
            "ObjectInputStream, XMLDecoder, XStream, Jackson enableDefaultTyping",
            "Fastjson parseObject, pickle.load, yaml.load",
        ],
        "safety_patterns": [
            "类型白名单, 安全配置, JsonTypeInfo.Id.NONE",
            "yaml.safe_load, RestrictedUnpickler",
        ],
        "scan_keywords": ["ObjectInputStream", "pickle", "yaml.load", "XMLDecoder", "XStream", "enableDefaultTyping", "Fastjson", "readValue", "deserialize"],
    },
    "CODE_INJECTION": {
        "label": "代码注入",
        "source_patterns": [
            "request.getParameter, @RequestParam",
            "req.query, req.body",
        ],
        "sink_patterns": [
            "ScriptEngine.eval(), GroovyShell.evaluate(), SpEL ExpressionParser",
            "eval(), Function(), compile(), exec()",
        ],
        "safety_patterns": [
            "表达式沙箱, 输入白名单",
            "SimpleEvaluationContext 替代 StandardEvaluationContext",
        ],
        "scan_keywords": ["eval", "exec", "Function", "compile", "ExpressionParser", "GroovyShell", "ScriptEngine", "Sandbox"],
    },
    "XSS": {
        "label": "跨站脚本",
        "source_patterns": [
            "@RequestParam, request.getParameter",
            "req.query, req.body",
        ],
        "sink_patterns": [
            "用户输入直接写入响应体(return content)",
            "innerHTML, dangerouslySetInnerHTML, v-html, response.write",
        ],
        "safety_patterns": [
            "HTML 实体编码, CSP 头",
            "模板引擎自动转义",
        ],
        "scan_keywords": ["innerHTML", "dangerouslySetInnerHTML", "v-html", "html", "render", "template", "response.write", "document.write"],
    },
    "PATH_TRAVERSAL": {
        "label": "路径遍历",
        "source_patterns": [
            "request.getParameter, MultipartFile 文件名",
            "req.query, req.body",
        ],
        "sink_patterns": [
            "FileInputStream/FileOutputStream(用户可控路径)",
            "readFile, writeFile, sendFile, open()",
        ],
        "safety_patterns": [
            "Paths.get().normalize(), toRealPath()",
            "path.resolve + 白名单目录检查",
        ],
        "scan_keywords": ["File", "path", "readFile", "writeFile", "sendFile", "open", "upload", "download", "filepath", "directory"],
    },
    "AUTH_BYPASS": {
        "label": "认证绕过",
        "source_patterns": [
            "HTTP 请求头, Cookie, Token",
        ],
        "sink_patterns": [
            "缺少 @PreAuthorize 的敏感端点",
            "客户端可控的头(X-Forwarded-For)做 IP 校验",
            "JWT 未验证签名/过期",
        ],
        "safety_patterns": [
            "Spring Security 全局拦截器",
            "服务端 session 验证",
        ],
        "scan_keywords": ["login", "auth", "token", "session", "jwt", "password", "PreAuthorize", "SecurityContext", "middleware"],
    },
    "XXE": {
        "label": "XML外部实体注入",
        "source_patterns": [
            "@RequestBody (XML 格式)",
        ],
        "sink_patterns": [
            "XMLReader, SAXReader, SAXBuilder, DocumentBuilder(未禁用外部实体)",
        ],
        "safety_patterns": [
            "禁用 DTD/外部实体",
            "XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false",
        ],
        "scan_keywords": ["SAXReader", "SAXBuilder", "DocumentBuilder", "XMLReader", "XMLInputFactory", "parseXML", "XML"],
    },
    "FILE_UPLOAD": {
        "label": "文件上传",
        "source_patterns": [
            "MultipartFile, @RequestParam('file')",
        ],
        "sink_patterns": [
            "getOriginalFilename()拼路径, transferTo()",
            "FileOutputStream(用户可控文件名)",
        ],
        "safety_patterns": [
            "UUID重命名, 白名单扩展名+MIME",
            "上传目录禁用脚本执行",
        ],
        "scan_keywords": ["upload", "MultipartFile", "transferTo", "FormFile", "SaveUploadedFile", "multer"],
    },
    "HARD_CODED_SECRET": {
        "label": "硬编码凭据",
        "source_patterns": ["无（配置/源码级别问题）"],
        "sink_patterns": ["password/secret/api_key 字面量"],
        "safety_patterns": ["环境变量/KMS 获取"],
        "scan_keywords": ["password", "secret", "api_key", "apikey", "token", "private_key", "credential"],
    },
    "JNDI_INJECTION": {
        "label": "JNDI注入",
        "source_patterns": ["request.getParameter"],
        "sink_patterns": ["InitialContext.lookup(用户输入)"],
        "safety_patterns": ["固定 JNDI 名称"],
        "scan_keywords": ["InitialContext", "lookup", "DirContext", "jndi"],
    },
    "SPEL_INJECTION": {
        "label": "SpEL表达式注入",
        "source_patterns": ["request.getParameter"],
        "sink_patterns": ["ExpressionParser.parseExpression()"],
        "safety_patterns": ["SimpleEvaluationContext"],
        "scan_keywords": ["ExpressionParser", "StandardEvaluationContext", "parseExpression", "SpEL"],
    },
    "SSTI": {
        "label": "服务端模板注入",
        "source_patterns": ["@RequestParam, @PathVariable"],
        "sink_patterns": ["Thymeleaf 视图名拼接, FreeMarker/Velocity 模板字符串"],
        "safety_patterns": ["模板路径来自配置而非用户输入"],
        "scan_keywords": ["template", "render", "Thymeleaf", "FreeMarker", "Velocity", "Jinja2"],
    },
}


def get_stage_guidance(vul_name: str) -> Optional[Dict[str, Any]]:
    """根据漏洞名称获取阶段指引。"""
    # 直接匹配
    if vul_name in _STAGE_GUIDANCE:
        return _STAGE_GUIDANCE[vul_name]
    # 模糊匹配
    vul_lower = vul_name.lower()
    for key, value in _STAGE_GUIDANCE.items():
        if key.lower() in vul_lower or vul_lower in key.lower():
            return value
        label = value.get("label", "")
        if label and (label in vul_name or vul_name in label):
            return value
    return None


def build_stage_scan_hints(vul_name: str) -> str:
    """为指定漏洞类型构建专用扫描指引文本。"""
    guidance = get_stage_guidance(vul_name)
    if not guidance:
        return ""

    lines = [f"\n## {guidance['label']} 专用扫描指引"]

    lines.append("\n### 关注的 Source（输入来源）")
    for src in guidance.get("source_patterns", []):
        lines.append(f"- {src}")

    lines.append("\n### 关注的 Sink（危险操作）")
    for sink in guidance.get("sink_patterns", []):
        lines.append(f"- {sink}")

    if guidance.get("safety_patterns"):
        lines.append("\n### 关注的 Safety（防护措施）")
        for safety in guidance["safety_patterns"]:
            lines.append(f"- {safety}")

    if guidance.get("scan_keywords"):
        lines.append("\n### 推荐 ripgrep 搜索关键词")
        keywords = guidance["scan_keywords"]
        for kw in keywords[:8]:
            lines.append(f"- `{kw}`")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# Gap Check / Revalidate 模式提示（参考 CodeScan adaptPromptForRunKind）
# ══════════════════════════════════════════════════════════════════

def build_gap_check_hint(existing_findings: List[Dict[str, Any]]) -> str:
    """构建 Gap Check 模式提示（复跑补充遗漏时注入）。"""
    if not existing_findings:
        return ""

    lines = [
        "\n## 补充检查模式 (Gap Check)",
        "- 以下为当前已有的发现摘要，你需要重新审查代码寻找遗漏项",
        "- 保留所有仍然有效的现有发现",
        "- 仅添加新确认的发现（遗漏的替代代码路径、未覆盖的 sink 等）",
        "- 如果两个条目描述同一根因问题，合并为一条",
        "- 最终输出必须是完整的合并 JSON 数组，不仅输出增量",
        "",
        "### 现有发现摘要：",
    ]
    for i, f in enumerate(existing_findings[:15], 1):
        file_loc = f.get("file", f.get("location", ""))
        line = f.get("line", "")
        reason = f.get("reason", f.get("title", ""))
        lines.append(f"{i}. {file_loc}:{line} - {reason[:80]}")
    if len(existing_findings) > 15:
        lines.append(f"... 还有 {len(existing_findings) - 15} 条发现")

    return "\n".join(lines)


def build_revalidate_hint(existing_findings: List[Dict[str, Any]]) -> str:
    """构建 Revalidate 模式提示（复跑验证时注入）。"""
    if not existing_findings:
        return ""

    lines = [
        "\n## 重新验证模式 (Revalidate)",
        "- 你是高级安全审查工程师，正在执行静态重新验证",
        "- 仅验证当前已有发现，不要发明新发现",
        "- 重新读取代码，根据实际代码证据验证每个发现",
        "- 对每个发现添加/更新以下字段：",
        '  - "verification_status": "confirmed" / "uncertain" / "rejected"',
        '  - "reviewed_severity": 验证后的严重程度',
        '  - "verification_reason": 基于证据的简要说明',
        "- 仅当漏洞路径和影响有强代码证据支持时标记为 confirmed",
        "- 当证据不足或不可利用时标记为 uncertain",
        "- 误报、重复、无代码支持的标记为 rejected",
        "- 最终输出必须是包含所有发现和新验证字段的完整 JSON 数组",
        "",
        "### 当前发现摘要：",
    ]
    for i, f in enumerate(existing_findings[:15], 1):
        file_loc = f.get("file", f.get("location", ""))
        line = f.get("line", "")
        severity = f.get("severity", "")
        reason = f.get("reason", f.get("title", ""))
        lines.append(f"{i}. [{severity}] {file_loc}:{line} - {reason[:80]}")
    if len(existing_findings) > 15:
        lines.append(f"... 还有 {len(existing_findings) - 15} 条发现")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# 路由上下文注入（参考 CodeScan BuildKnownRoutesContext）
# ══════════════════════════════════════════════════════════════════

def build_route_context_hint(route_candidate_files: list) -> str:
    """构建路由上下文提示（注入到审计 prompt）。"""
    if not route_candidate_files:
        return ""

    lines = [
        "\n## 项目路由候选文件（已通过正则预扫描识别）",
        "以下文件中检测到了路由定义模式（如 @RequestMapping、@app.route、router.get 等），",
        "这些文件通常是请求入口和攻击面，建议优先审查：\n",
    ]
    for f in route_candidate_files[:20]:
        path = f.path if hasattr(f, "path") else f.get("path", "")
        rules = f.rules if hasattr(f, "rules") else f.get("rules", [])
        if hasattr(rules[0], "name") if rules else False:
            rule_names = [r.name for r in rules]
        elif isinstance(rules, list) and rules and isinstance(rules[0], dict):
            rule_names = [r.get("name", "") for r in rules]
        else:
            rule_names = []
        lines.append(f"- `{path}` ({', '.join(rule_names)})")

    if len(route_candidate_files) > 20:
        lines.append(f"- ... 还有 {len(route_candidate_files) - 20} 个文件")

    return "\n".join(lines)


def build_hotspot_context_hint(hotspot_files: list, vul_name: str) -> str:
    """构建热点文件上下文提示。"""
    if not hotspot_files:
        return ""

    lines = [
        f"\n## {vul_name} 阶段热点文件（已通过正则预扫描识别）",
        "以下文件中检测到了与当前漏洞类型相关的危险模式，建议优先审查：\n",
    ]
    for f in hotspot_files[:15]:
        path = f.path if hasattr(f, "path") else f.get("path", "")
        rules = f.rules if hasattr(f, "rules") else f.get("rules", [])
        if rules and hasattr(rules[0], "name"):
            rule_names = [r.name for r in rules]
            hit_lines = []
            for r in rules[:2]:
                hit_lines.extend(r.lines[:3])
            line_hint = ", ".join(str(l) for l in sorted(set(hit_lines))[:6])
        elif isinstance(rules, list) and rules and isinstance(rules[0], dict):
            rule_names = [r.get("name", "") for r in rules]
            line_hint = ""
        else:
            rule_names = []
            line_hint = ""
        lines.append(f"- `{path}` (rules: {', '.join(rule_names)}{', lines: ' + line_hint if line_hint else ''})")

    if len(hotspot_files) > 15:
        lines.append(f"- ... 还有 {len(hotspot_files) - 15} 个文件")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
# 统一入口
# ══════════════════════════════════════════════════════════════════

def build_stage_aware_prompt(
    base_prompt: str,
    vul_name: str,
    language: str = "",
    manifest: Any = None,
    run_kind: str = "initial",
    existing_findings: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """构建阶段感知的增强提示词。

    Args:
        base_prompt: 基础提示词
        vul_name: 漏洞类型名称
        language: 编程语言
        manifest: ProjectManifest 实例（可选）
        run_kind: 运行模式 ("initial" / "gap_check" / "revalidate")
        existing_findings: 已有发现列表（gap_check/revalidate 时提供）

    Returns:
        增强后的提示词
    """
    enhanced = base_prompt

    # 1. 注入阶段专用扫描指引
    stage_hints = build_stage_scan_hints(vul_name)
    if stage_hints:
        enhanced += stage_hints

    # 2. 注入路由上下文（如果有 manifest）
    if manifest is not None:
        route_files = manifest.route_candidate_files if hasattr(manifest, "route_candidate_files") else []
        if route_files:
            route_hint = build_route_context_hint(route_files)
            if route_hint:
                enhanced += route_hint

        # 3. 注入热点文件清单
        vul_key = _resolve_vul_key(vul_name)
        if vul_key:
            hotspot_files = manifest.get_stage_hotspots(vul_key) if hasattr(manifest, "get_stage_hotspots") else []
            if hotspot_files:
                hotspot_hint = build_hotspot_context_hint(hotspot_files, vul_name)
                if hotspot_hint:
                    enhanced += hotspot_hint

    # 4. Gap Check / Revalidate 模式
    if run_kind == "gap_check" and existing_findings:
        gap_hint = build_gap_check_hint(existing_findings)
        if gap_hint:
            enhanced += gap_hint
    elif run_kind == "revalidate" and existing_findings:
        reval_hint = build_revalidate_hint(existing_findings)
        if reval_hint:
            enhanced += reval_hint

    return enhanced


def _resolve_vul_key(vul_name: str) -> str:
    """将漏洞中文名映射为 _STAGE_GUIDANCE 的 key。"""
    if vul_name in _STAGE_GUIDANCE:
        return vul_name
    vul_lower = vul_name.lower()
    for key, value in _STAGE_GUIDANCE.items():
        label = value.get("label", "")
        if label and (label in vul_name or vul_name in label):
            return key
        if key.lower() in vul_lower:
            return key
    return ""
