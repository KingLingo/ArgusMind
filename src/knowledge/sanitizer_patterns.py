# -*- coding: utf-8 -*-
"""净化函数模式 —— 整合自 config/sanitizer_patterns.yaml。

用于检测代码中的安全防护措施（净化/编码/参数化），降低误报率。
"""

from __future__ import annotations

import re
from typing import Dict, List


# ═══════════════════════════════════════════════════════════════
# 按分类组织的净化函数模式
# ═══════════════════════════════════════════════════════════════

SANITIZER_PATTERNS: Dict[str, List[Dict[str, object]]] = {
    "sql": [
        {
            "name": "PreparedStatement",
            "patterns": [
                re.compile(r"PreparedStatement", re.I),
                re.compile(r"prepareStatement", re.I),
                re.compile(r"JdbcTemplate\.", re.I),
                re.compile(r"NamedParameterJdbcTemplate", re.I),
                re.compile(r"@Param", re.I),
                re.compile(r"namedParameter", re.I),
                re.compile(r"queryForObject", re.I),
                re.compile(r"queryForList", re.I),
                re.compile(r"executeQuery\s*\(", re.I),
                re.compile(r"createQuery\s*\(", re.I),
                re.compile(r"createNativeQuery\s*\(", re.I),
            ],
            "confidence": 0.95,
        },
        {
            "name": "ORM框架",
            "patterns": [
                re.compile(r"Eloquent\s+", re.I),
                re.compile(r"\.find\s*\(.*\)", re.I),
                re.compile(r"\.findOne\s*\(.*\)", re.I),
                re.compile(r"\.findById\s*\(.*\)", re.I),
                re.compile(r"\.where\(.*\)\s*\.first\(\)", re.I),
                re.compile(r"\.where\(.*\)\s*\.get\(\)", re.I),
                re.compile(r"TypeORM.*\.(find|findOne|findBy|createQueryBuilder)", re.I),
                re.compile(r"Prisma\.(client|query)", re.I),
                re.compile(r"Sequelize\.(query|model)", re.I),
            ],
            "confidence": 0.9,
        },
        {
            "name": "参数绑定",
            "patterns": [
                re.compile(r"\.param\(", re.I),
                re.compile(r"\.bind\(", re.I),
                re.compile(r"\?\s*\[", re.I),
                re.compile(r"\$\{[^}]*\?\}", re.I),
                re.compile(r"\#\{[^}]*\}", re.I),
            ],
            "confidence": 0.95,
        },
        {
            "name": "转义函数",
            "patterns": [
                re.compile(r"mysqli_real_escape_string", re.I),
                re.compile(r"pg_escape_string", re.I),
                re.compile(r"escape_string\s*\(", re.I),
                re.compile(r"addslashes\s*\(", re.I),
            ],
            "confidence": 0.7,
        },
    ],
    "xss": [
        {
            "name": "HTML转义",
            "patterns": [
                re.compile(r"HtmlUtils\.escape", re.I),
                re.compile(r"StringEscapeUtils\.escapeHtml", re.I),
                re.compile(r"ESAPI\.encoder\.", re.I),
                re.compile(r"encodeForHTML", re.I),
                re.compile(r"escapeHtml4", re.I),
                re.compile(r"htmlspecialchars\s*\(", re.I),
            ],
            "confidence": 0.9,
        },
        {
            "name": "内容净化",
            "patterns": [
                re.compile(r"DOMPurify\.sanitize", re.I),
                re.compile(r"sanitizeHtml\s*\(", re.I),
                re.compile(r"striptags\s*\(", re.I),
                re.compile(r"strip_tags\s*\(", re.I),
                re.compile(r"santize\s*\(", re.I),
                re.compile(r"cleanInput", re.I),
            ],
            "confidence": 0.95,
        },
        {
            "name": "安全输出",
            "patterns": [
                re.compile(r"text\s*\(", re.I),
                re.compile(r"\.text\s*\(", re.I),
                re.compile(r"innerText\s*=", re.I),
                re.compile(r"\.textContent\s*=", re.I),
                re.compile(r"React\..*encode", re.I),
            ],
            "confidence": 0.85,
        },
        {
            "name": "URL编码",
            "patterns": [
                re.compile(r"\.encodeURIComponent", re.I),
                re.compile(r"urlencode\s*\(", re.I),
                re.compile(r"escape\s*\(\s*[\$\w]", re.I),
                re.compile(r"_\.escape\s*\(", re.I),
                re.compile(r"lodash.*escape", re.I),
            ],
            "confidence": 0.75,
        },
        {
            "name": "模板引擎转义",
            "patterns": [
                re.compile(r"Handlebars\.escape", re.I),
                re.compile(r"template\.escape", re.I),
                re.compile(r"nunjucks\.escape", re.I),
                re.compile(r"ejs\.escape", re.I),
                re.compile(r"twig\.escape", re.I),
            ],
            "confidence": 0.8,
        },
    ],
    "cmd": [
        {
            "name": "参数数组执行",
            "patterns": [
                re.compile(r"subprocess\.run\s*\(\s*\[", re.I),
                re.compile(r"subprocess\.Popen\s*\(\s*\[", re.I),
                re.compile(r"ProcessBuilder\s*\(\s*\[", re.I),
            ],
            "confidence": 0.95,
        },
        {
            "name": "命令转义",
            "patterns": [
                re.compile(r"shlex\.quote\s*\(", re.I),
                re.compile(r"escapeshellarg\s*\(", re.I),
                re.compile(r"escapeshellcmd\s*\(", re.I),
            ],
            "confidence": 0.85,
        },
    ],
    "path": [
        {
            "name": "路径规范化",
            "patterns": [
                re.compile(r"Path\.normalize", re.I),
                re.compile(r"getCanonicalPath", re.I),
                re.compile(r"getAbsolutePath", re.I),
                re.compile(r"realpath\s*\(", re.I),
            ],
            "confidence": 0.9,
        },
        {
            "name": "安全路径拼接",
            "patterns": [
                re.compile(r"path\.join.*__dirname", re.I),
                re.compile(r"Path\.resolve.*__dirname", re.I),
                re.compile(r"os\.path\.join.*__file__", re.I),
            ],
            "confidence": 0.85,
        },
        {
            "name": "白名单验证",
            "patterns": [
                re.compile(r"whitelist|allowList", re.I),
                re.compile(r"validateEnum|isValidType", re.I),
                re.compile(r"extension.*in.*\[", re.I),
                re.compile(r"\.endsWith\(", re.I),
                re.compile(r"\.match\(.*ext", re.I),
            ],
            "confidence": 0.8,
        },
    ],
    "general": [
        {
            "name": "通用编码",
            "patterns": [
                re.compile(r"URLEncoder\.encode", re.I),
                re.compile(r"URLDecoder\.decode", re.I),
                re.compile(r"base64", re.I),
                re.compile(r"hexEncode", re.I),
                re.compile(r"unicodeEscape", re.I),
            ],
            "confidence": 0.7,
        },
    ],
}


# ═══════════════════════════════════════════════════════════════
# 按漏洞类型映射到对应净化分类
# ═══════════════════════════════════════════════════════════════

VULN_TO_SANITIZER_CATEGORY: Dict[str, List[str]] = {
    "SQL_INJECTION": ["sql"],
    "NOSQL_INJECTION": ["sql"],
    "XSS": ["xss"],
    "COMMAND_INJECTION": ["cmd"],
    "CODE_INJECTION": ["general"],
    "PATH_TRAVERSAL": ["path"],
    "SSRF": ["general"],
    "HARD_CODE_PASSWORD": [],
    "WEAK_CRYPTO": [],
    "WEAK_HASH": [],
    "DESERIALIZATION": ["general"],
    "FILE_UPLOAD": ["path"],
    "FILE_OPERATIONS": ["path"],
    "OPEN_REDIRECT": [],
    "LOG_INJECTION": [],
}


def get_sanitizer_patterns(vuln_type: str) -> List[re.Pattern]:
    """获取指定漏洞类型对应的所有净化检测正则。"""
    categories = VULN_TO_SANITIZER_CATEGORY.get(vuln_type, [])
    result: List[re.Pattern] = []
    for cat in categories:
        for entry in SANITIZER_PATTERNS.get(cat, []):
            result.extend(entry.get("patterns", []))
    return result


def count_sanitizer_matches(vuln_type: str, code_window: str) -> int:
    """统计代码窗口中净化函数的命中次数。"""
    patterns = get_sanitizer_patterns(vuln_type)
    return sum(1 for p in patterns if p.search(code_window))
