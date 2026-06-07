# -*- coding: utf-8 -*-
"""安全线索画像系统 —— 整合自 gbt-codeagent/services/securityHintProfile.js。

对代码中的安全信号做 4 维分类画像：
- has_input: 是否含用户输入源（request.getParameter、req.body 等）
- has_sink: 是否调用危险 API（exec、SQL拼接、File操作等）
- has_validation: 是否有校验/净化（@Valid、sanitize、escape 等）
- has_safety: 是否有安全防护（PreparedStatement、PreAuthorize 等）

用于风险候选预筛选和置信度增强。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

# ═══════════════════════════════════════════════════════════════
# 通用安全线索模式（跨语言）
# ═══════════════════════════════════════════════════════════════

_COMMON_PATTERNS = {
    "input_sources": [
        re.compile(r'(?i)\b(upload|file|filename|filepath|path|callback|redirect)\b'),
    ],
    "dangerous_sinks": [
        re.compile(r'(?i)\b(eval|exec)\b'),
        re.compile(r'(?i)\b(select|insert|update|delete)\b.*(\+|\bf(?:ormat)?\b.*\()'),
        re.compile(r'(?i)\b(innerHTML|dangerouslySetInnerHTML|document\.write)\b'),
    ],
    "safety_signals": [
        re.compile(r'(?i)\b(whitelist|allowlist)\b'),
        re.compile(r'(?i)\b(parameterized|prepared|placeholder)\b'),
    ],
    "validation_signals": [
        re.compile(r'(?i)\b(validate|sanitize|escape|check|verify|guard|filter)\b'),
        re.compile(r'(?i)\b(auth|authorize|permission|acl|role|requiredLogin|requiredAuth)\b'),
        re.compile(r'(?i)\b(is_safe|safe_path|normalized|canonical)\b'),
    ],
}

# ═══════════════════════════════════════════════════════════════
# 语言级安全线索模式
# ═══════════════════════════════════════════════════════════════

_LANGUAGE_PATTERNS: Dict[str, Dict[str, List[re.Pattern]]] = {
    ".py": {
        "input_sources": [
            re.compile(r'request\.(args|form|json|values|files)\b'),
            re.compile(r'\b(input|sys\.argv|os\.environ|getenv)\b'),
        ],
        "dangerous_sinks": [
            re.compile(r'\b(subprocess\.(run|Popen|call)|os\.system)\b'),
            re.compile(r'\b(pickle\.load|pickle\.loads|yaml\.load)\b'),
            re.compile(r'\b(requests\.(get|post|request)|httpx\.(get|post))\b'),
            re.compile(r'\b(open|Path\.open|read_text|write_text)\b'),
            re.compile(r'\b(sqlite3|pymysql|psycopg2|sqlalchemy)\b'),
        ],
        "safety_signals": [
            re.compile(r'\b(yaml\.safe_load|html\.escape|markupsafe\.escape)\b'),
            re.compile(r'\b(pathlib\.Path|resolve\(\))\b'),
            re.compile(r'\b(subprocess\.\w+\s*\(\s*\[)\b'),
        ],
        "validation_signals": [
            re.compile(r'\b(pydantic|validator|marshmallow|schema\.load)\b'),
        ],
    },
    ".js": {
        "input_sources": [
            re.compile(r'\b(req|request)\.(query|body|params|headers|files)\b'),
            re.compile(r'\b(process\.env|window\.location|document\.location)\b'),
        ],
        "dangerous_sinks": [
            re.compile(r'\b(child_process\.(exec|spawn|execSync))\b'),
            re.compile(r'\b(require\s*\(|import\s*\()\b'),
            re.compile(r'\b(fetch|axios\.(get|post|request))\b'),
            re.compile(r'\b(fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream))\b'),
        ],
        "safety_signals": [
            re.compile(r'\b(path\.normalize|path\.resolve)\b'),
            re.compile(r'\b(DOMPurify|validator\.)\b'),
        ],
        "validation_signals": [
            re.compile(r'\b(zod|joi|yup|express-validator)\b'),
        ],
    },
    ".java": {
        "input_sources": [
            re.compile(r'\b(request\.getParameter|@RequestParam|@PathVariable|@RequestBody)\b'),
            re.compile(r'\b(System\.getenv|MultipartFile)\b'),
        ],
        "dangerous_sinks": [
            re.compile(r'\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\b'),
            re.compile(r'\b(HttpURLConnection|RestTemplate|WebClient)\b'),
            re.compile(r'\b(FileInputStream|FileOutputStream|Files\.(read|write))\b'),
            re.compile(r'\b(Statement|createStatement|executeQuery|executeUpdate)\b'),
        ],
        "safety_signals": [
            re.compile(r'\b(PreparedStatement|@PreAuthorize|hasRole)\b'),
            re.compile(r'\b(Paths\.get|normalize\(\)|toRealPath\(\))\b'),
        ],
        "validation_signals": [
            re.compile(r'\b(@Valid|Validator|BindingResult)\b'),
        ],
    },
    ".go": {
        "input_sources": [
            re.compile(r'\b(r\.URL\.Query|FormValue|PostFormValue|ShouldBindJSON|BindJSON)\b'),
            re.compile(r'\b(os\.Getenv|c\.Param|c\.Query|c\.PostForm)\b'),
        ],
        "dangerous_sinks": [
            re.compile(r'\b(exec\.Command|sql\.DB|QueryRow|Query|Exec)\b'),
            re.compile(r'\b(http\.Get|http\.Post|client\.Do)\b'),
            re.compile(r'\b(os\.Open|os\.Create|ioutil\.ReadFile|os\.WriteFile)\b'),
            re.compile(r'\b(template\.HTML|text\/template)\b'),
        ],
        "safety_signals": [
            re.compile(r'\b(html/template|filepath\.Clean|filepath\.Join)\b'),
            re.compile(r'\b(PrepareContext|QueryContext|ExecContext)\b'),
        ],
        "validation_signals": [
            re.compile(r'\b(validator\.New|ShouldBind|binding:)\b'),
        ],
    },
    ".php": {
        "input_sources": [
            re.compile(r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)'),
        ],
        "dangerous_sinks": [
            re.compile(r'\b(system|exec|shell_exec|passthru|popen)\s*\('),
            re.compile(r'\b(mysqli_query|PDO::query)\s*\('),
            re.compile(r'\b(unserialize)\s*\('),
            re.compile(r'\b(include|require)\s*\('),
        ],
        "safety_signals": [
            re.compile(r'\b(PDO::prepare|mysqli_prepare)\b'),
            re.compile(r'\b(escapeshellarg|escapeshellcmd|htmlspecialchars)\b'),
            re.compile(r'\b(basename|realpath)\b'),
        ],
        "validation_signals": [
            re.compile(r'\b(filter_var|filter_input|htmlentities)\b'),
        ],
    },
}


def _match_patterns(text: str, patterns: List[re.Pattern]) -> bool:
    """检查文本是否匹配任一模式。"""
    return any(p.search(text) for p in patterns)


def get_security_hint_profile(
    code_snippet: str,
    extension: str = "",
) -> Dict[str, bool]:
    """为代码片段构建安全信号画像。

    Args:
        code_snippet: 代码文本
        extension: 文件扩展名（含点号，如 .java .py .js）

    Returns:
        {"has_input": bool, "has_sink": bool, "has_validation": bool, "has_safety": bool}
    """
    profile = {
        "has_input": False,
        "has_sink": False,
        "has_validation": False,
        "has_safety": False,
    }

    # 先检查通用模式
    for cat in ["input_sources", "dangerous_sinks", "validation_signals", "safety_signals"]:
        patterns = _COMMON_PATTERNS.get(cat, [])
        if _match_patterns(code_snippet, patterns):
            key = {"input_sources": "has_input", "dangerous_sinks": "has_sink",
                   "validation_signals": "has_validation", "safety_signals": "has_safety"}[cat]
            profile[key] = True

    # 再检查语言级模式（更精准）
    lang_patterns = _LANGUAGE_PATTERNS.get(extension, {})
    for cat in ["input_sources", "dangerous_sinks", "validation_signals", "safety_signals"]:
        patterns = lang_patterns.get(cat, [])
        if _match_patterns(code_snippet, patterns):
            key = {"input_sources": "has_input", "dangerous_sinks": "has_sink",
                   "validation_signals": "has_validation", "safety_signals": "has_safety"}[cat]
            profile[key] = True

    return profile


def security_hint_score(profile: Dict[str, bool]) -> int:
    """计算安全线索评分。

    对应 gbt-codeagent auditCandidateFilter：
    - has_input + has_sink = 200 分
    - has_input + has_sink + 无 validation + 无 safety = +150 分
    """
    score = 0
    if profile.get("has_input"):
        score += 25
    if profile.get("has_sink"):
        score += 35
    if profile.get("has_input") and profile.get("has_sink"):
        score += 200
        if not profile.get("has_validation") and not profile.get("has_safety"):
            score += 150
    return score


def profile_finding(
    finding: Dict[str, Any],
    project_root: str = "",
) -> Dict[str, Any]:
    """为单个 finding 做安全画像分析，返回增强后的 finding。

    会读取 finding 所在文件的影响行上下文进行画像分析。
    """
    import os

    file_path = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    extension = os.path.splitext(file_path)[1].lower() if file_path else ""

    snippet = finding.get("evidence", finding.get("code_snippet", ""))
    if not snippet and project_root and file_path:
        full_path = os.path.join(project_root, file_path)
        if os.path.isfile(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().split("\n")
                if 1 <= line <= len(lines):
                    # 取上下文 5 行
                    ctx_start = max(0, line - 1 - 5)
                    ctx_end = min(len(lines), line + 5)
                    snippet = "\n".join(lines[ctx_start:ctx_end])
            except Exception:
                pass

    if snippet:
        profile = get_security_hint_profile(snippet, extension)
        finding["_security_profile"] = profile
        finding["_hint_score"] = security_hint_score(profile)
    else:
        finding["_security_profile"] = {
            "has_input": False, "has_sink": False,
            "has_validation": False, "has_safety": False,
        }
        finding["_hint_score"] = 0

    return finding
