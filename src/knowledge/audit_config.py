# -*- coding: utf-8 -*-
"""审计配置 —— 整合自 gbt-codeagent。

包含文件扩展名映射、漏洞类型编码、CWE映射、组件漏洞规则、DKTSS评分等。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional


# === 文件扩展名到语言的映射 ===

FILE_EXTENSION_MAP: Dict[str, str] = {
    ".java": "java",
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "cpp",
    ".h": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".rb": "ruby",
    ".rbw": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sc": "scala",
    ".pl": "perl",
    ".pm": "perl",
    ".t": "perl",
    ".lua": "lua",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
    ".html": "html",
    ".sql": "sql",
}

# 语言到扩展名的反向映射
LANGUAGE_EXTENSIONS: Dict[str, List[str]] = {}
for _ext, _lang in FILE_EXTENSION_MAP.items():
    LANGUAGE_EXTENSIONS.setdefault(_lang, []).append(_ext)

# === 漏洞类型到 CWE 的映射 ===

VULN_CWE_MAP: Dict[str, str] = {
    "COMMAND_INJECTION": "CWE-78",
    "CODE_INJECTION": "CWE-94",
    "SQL_INJECTION": "CWE-89",
    "NOSQL_INJECTION": "CWE-89",
    "XPATH_INJECTION": "CWE-643",
    "PATH_TRAVERSAL": "CWE-22",
    "XSS": "CWE-79",
    "SSRF": "CWE-918",
    "CSRF": "CWE-352",
    "XXE": "CWE-611",
    "DESERIALIZATION": "CWE-502",
    "AUTH_BYPASS": "CWE-287",
    "IDOR": "CWE-639",
    "OPEN_REDIRECT": "CWE-601",
    "HARD_CODE_PASSWORD": "CWE-259",
    "PLAINTEXT_PASSWORD": "CWE-256",
    "WEAK_CRYPTO": "CWE-327",
    "WEAK_HASH": "CWE-328",
    "PREDICTABLE_RANDOM": "CWE-338",
    "WEAK_RANDOM": "CWE-338",
    "BUFFER_OVERFLOW": "CWE-120",
    "FORMAT_STRING": "CWE-134",
    "INTEGER_OVERFLOW": "CWE-190",
    "PROCESS_CONTROL": "CWE-114",
    "SESSION_FIXATION": "CWE-384",
    "COOKIE_MANIPULATION": "CWE-565",
    "REFERER_AUTH_BYPASS": "CWE-293",
    "AUTH_INFO_EXPOSURE": "CWE-204",
    "UNCONTROLLED_MEMORY": "CWE-770",
    "IMPROPER_EXCEPTION_HANDLING": "CWE-703",
    "WEAK_PASSWORD_POLICY": "CWE-521",
    "PLAINTEXT_TRANSMISSION": "CWE-319",
    "CORS_MISCONFIGURATION": "CWE-942",
    "LOG_INJECTION": "CWE-93",
    "SPEL_INJECTION": "CWE-94",
    "SSTI": "CWE-94",
    "RACE_CONDITION": "CWE-362",
    "INFINITE_LOOP": "CWE-835",
}

# === DKTSS 基础评分表 ===

DKTSS_BASE_SCORES: Dict[str, Any] = {
    "COMMAND_INJECTION": 10,
    "CODE_INJECTION": 10,
    "DESERIALIZATION": 10,
    "SQL_INJECTION": {"write": 8, "read": 6, "default": 7},
    "SSRF": {"internal": 7, "http_only": 4, "default": 5},
    "AUTH_BYPASS": 8,
    "IDOR": 7,
    "XSS": {"stored": 6, "reflected": 5, "default": 5},
    "XXE": 6,
    "PATH_TRAVERSAL": 6,
    "FILE_UPLOAD": 6,
    "WEAK_CRYPTO": 5,
    "WEAK_HASH": 4,
    "HARD_CODE_PASSWORD": 7,
    "LOG_INJECTION": 4,
    "default": 5,
}

DKTSS_FRICTION: Dict[str, Dict[str, int]] = {
    "accessPath": {"internet": 0, "intranet": -2, "physical": -4},
    "authRequired": {"none": 0, "lowPrivilege": -1, "highPrivilege": -3},
    "interaction": {"none": 0, "weak": -1, "strong": -3},
}

DKTSS_WEAPON: Dict[str, int] = {
    "matureExp": 1,
    "pocOnly": 0,
    "theoretical": -2,
}

# === Java 组件版本漏洞检测规则 ===

COMPONENT_VULN_RULES: Dict[str, List[Dict[str, Any]]] = {
    "critical": [
        {
            "name": "Log4j2 RCE漏洞 (CVE-2021-44228)",
            "function": "log4j-core:2.0-2.14.1",
            "description": "Log4j2 远程代码执行漏洞（Log4Shell），影响版本 2.0-2.14.1，建议升级到 2.17.1+",
            "pattern": r'log4j-core["\']?\s*[:_-]\s*["\']?2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.',
        },
        {
            "name": "Log4j 1.x SocketServer 反序列化漏洞 (CVE-2019-17571)",
            "function": "log4j:1.2.0-1.2.17",
            "description": "Log4j 1.x SocketServer 反序列化 RCE 漏洞，建议迁移到 Log4j 2.17.1+",
            "pattern": r'log4j["\']?\s*[:_-]\s*["\']?1\.2\.',
        },
        {
            "name": "Fastjson 反序列化漏洞 (CVE-2022-25845)",
            "function": "fastjson:1.2.0-1.2.80",
            "description": "Fastjson 反序列化远程代码执行漏洞，建议升级到 1.2.83+ 或使用 Fastjson2",
            "pattern": r'fastjson["\']?\s*[:_-]\s*["\']?1\.2\.([0-7][0-9]|80)["\']?',
        },
        {
            "name": "Spring Framework RCE漏洞 (CVE-2022-22965 Spring4Shell)",
            "function": "spring-beans:5.3.0-5.3.17 或 5.2.0-5.2.19",
            "description": "Spring Framework 远程代码执行漏洞，建议升级到 5.3.18+",
            "pattern": r'spring-(beans|core|context|web)["\']?\s*[:_-]\s*["\']?5\.(3\.(0|1|2|3|4|5|6|7|8|9|1[0-7])|2\.(0|1|2|3|4|5|6|7|8|9|1[0-9]))',
        },
        {
            "name": "Struts2 RCE漏洞 (S2-061 CVE-2020-17530)",
            "function": "struts2-core:2.0.0-2.5.25",
            "description": "Struts2 OGNL表达式注入漏洞，建议升级到 2.5.26+",
            "pattern": r'struts2-core["\']?\s*[:_-]\s*["\']?2\.[0-5]\.(0|1|2|3|4|5|6|7|8|9|1[0-9]|2[0-5])["\']?',
        },
        {
            "name": "Jackson 反序列化漏洞 (CVE-2020-36518)",
            "function": "jackson-databind:2.0.0-2.12.6.1",
            "description": "Jackson 反序列化漏洞，建议升级到 2.12.7+ 或 2.13.3+",
            "pattern": r'jackson-databind["\']?\s*[:_-]\s*["\']?2\.(0|1|2|3|4|5|6|7|8|9|10|11|12)\.',
        },
        {
            "name": "Commons Collections 反序列化漏洞",
            "function": "commons-collections:3.0-3.2.1",
            "description": "Apache Commons Collections 反序列化漏洞，建议升级到 3.2.2+",
            "pattern": r'commons-collections["\']?\s*[:_-]\s*["\']?3\.(0|1|2\.[01])["\']?',
        },
        {
            "name": "Apache Shiro 认证绕过漏洞 (CVE-2020-13933)",
            "function": "shiro-core:1.0.0-1.5.3",
            "description": "Apache Shiro 认证绕过漏洞，建议升级到 1.7.1+",
            "pattern": r'shiro-core["\']?\s*[:_-]\s*["\']?1\.[0-5]\.',
        },
        {
            "name": "Apache Shiro 反序列化漏洞 (CVE-2016-4437 SHIRO-550)",
            "function": "shiro-core:1.0.0-1.2.4",
            "description": "Apache Shiro RememberMe 反序列化漏洞，建议升级到 1.7.1+",
            "pattern": r'shiro-core["\']?\s*[:_-]\s*["\']?1\.[0-2]\.',
        },
    ],
    "high": [
        {
            "name": "Spring Boot Actuator 未授权访问",
            "function": "spring-boot-starter-actuator:1.x",
            "description": "Spring Boot 1.x Actuator 默认未授权访问，建议升级到 2.x",
            "pattern": r'spring-boot-starter-actuator["\']?\s*[:_-]\s*["\']?1\.',
        },
        {
            "name": "Spring Boot RCE漏洞 (CVE-2022-22963)",
            "function": "spring-cloud-function-context:3.0.0-3.2.2",
            "description": "Spring Cloud Function SpEL 表达式注入漏洞，建议升级到 3.2.3+",
            "pattern": r'spring-cloud-function-context["\']?\s*[:_-]\s*["\']?3\.[0-2]\.',
        },
        {
            "name": "XStream 反序列化漏洞 (CVE-2021-39139)",
            "function": "xstream:1.0.0-1.4.17",
            "description": "XStream 反序列化远程代码执行漏洞，建议升级到 1.4.18+",
            "pattern": r'xstream["\']?[-_:]\s*["\']?1\.[0-4]\.([0-9]|1[0-7])["\']?',
        },
        {
            "name": "SnakeYAML 反序列化漏洞 (CVE-2022-1471)",
            "function": "snakeyaml:1.0-1.32",
            "description": "SnakeYAML 反序列化远程代码执行漏洞，建议升级到 2.0+",
            "pattern": r'snakeyaml["\']?\s*[:_-]\s*["\']?1\.(0|[1-2][0-9]|3[0-2])["\']?',
        },
    ],
}


# === 抑制规则模式 ===
# 用于 CodeCommentParser 解析代码注释中的抑制标记

SUPPRESSION_PATTERNS: List[re.Pattern] = [
    re.compile(r"gbt:\s*disable\s+([\w\-]+)", re.I),
    re.compile(r"gbt-disable:\s*([\w\-]+)", re.I),
    re.compile(r"gbt:\s*ignore\s+([\w\-]+)", re.I),
    re.compile(r"ignore:\s*([\w\-]+)", re.I),
    re.compile(r"eslint-disable-next-line\s+([\w\-]+)", re.I),
    re.compile(r"eslint-disable-line\s+([\w\-]+)", re.I),
    re.compile(r"tslint:disable-next-line\s+([\w\-]+)", re.I),
    re.compile(r"tslint:disable\s+([\w\-]+)", re.I),
    re.compile(r"pylint:\s*disable\s*=\s*([\w\-]+)", re.I),
    re.compile(r"noinspection\s+([\w\-]+)", re.I),
]


# === 工具函数 ===

def detect_language(file_path: str) -> Optional[str]:
    """根据文件路径检测语言。"""
    _, ext = os.path.splitext(file_path)
    return FILE_EXTENSION_MAP.get(ext.lower())


def is_vulnerability_supported(vuln_type: str, language: str) -> bool:
    """判断漏洞类型是否与语言匹配。"""
    if not vuln_type or not language:
        return True

    from src.knowledge.language_audit_rules import LANGUAGE_VULN_MAP

    supported_vulns = LANGUAGE_VULN_MAP.get(language)
    if not supported_vulns:
        return True

    upper_vuln_type = vuln_type.upper()
    return any(v == upper_vuln_type or upper_vuln_type.includes(v) for v in supported_vulns)


def get_vuln_type_code(vuln_type: str) -> str:
    """获取漏洞类型编码。"""
    from src.knowledge.vuln_scoring import VULN_TYPE_CODES

    if not vuln_type:
        return "LOGIC"
    upper = vuln_type.upper()
    for key, code in VULN_TYPE_CODES.items():
        if upper == key.upper() or key.upper() in upper:
            return code
    return "LOGIC"


_SEVERITY_PREFIX = {
    "critical": "C", "严重": "C",
    "high": "H", "高危": "H",
    "medium": "M", "中危": "M",
    "low": "L", "低危": "L",
}


def generate_vuln_id(finding: Dict[str, Any], existing_findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """生成漏洞唯一编号。"""
    existing = existing_findings or []
    severity = _SEVERITY_PREFIX.get(str(finding.get("severity", "")).lower(), "L")
    type_code = get_vuln_type_code(finding.get("type", ""))
    count = sum(
        1 for f in existing
        if _SEVERITY_PREFIX.get(str(f.get("severity", "")).lower(), "L") == severity
        and get_vuln_type_code(f.get("type", "")) == type_code
    ) + 1
    return f"{severity}-{type_code}-{count:03d}"


def calculate_dktss(finding: Dict[str, Any]) -> float:
    """计算 DKTSS 评分。"""
    vuln_type = finding.get("type") or finding.get("vulnType") or ""
    base_score = DKTSS_BASE_SCORES.get(vuln_type, DKTSS_BASE_SCORES["default"])

    if isinstance(base_score, dict):
        detail = finding.get("detail", "")
        if "脱库" in detail or "写文件" in detail:
            base_score = base_score.get("write", base_score.get("default", 5))
        elif "读" in detail or "limited" in detail:
            base_score = base_score.get("read", base_score.get("default", 5))
        elif vuln_type == "SSRF":
            base_score = base_score.get("internal", base_score.get("default", 5))
        else:
            base_score = base_score.get("default", 5)

    access_path = finding.get("accessPath", "internet")
    auth_level = finding.get("authRequired", "none")
    interaction = finding.get("interaction", "none")

    friction = (
        DKTSS_FRICTION["accessPath"].get(access_path, 0)
        + DKTSS_FRICTION["authRequired"].get(auth_level, 0)
        + DKTSS_FRICTION["interaction"].get(interaction, 0)
    )

    weapon = DKTSS_WEAPON.get(finding.get("weaponLevel", "pocOnly"), 0)

    final_score = max(0, min(10, base_score - friction + weapon))
    return round(final_score, 1)


def get_dktss_severity(dktss_score: float) -> str:
    """获取 DKTSS 严重程度。"""
    if dktss_score >= 7:
        return "critical"
    if dktss_score >= 5:
        return "high"
    if dktss_score >= 3:
        return "medium"
    return "low"


# === 审计配置（整合自 audit-config.yaml）===

AUDIT_PROFILES: Dict[str, str] = {
    "default": "高质量标准检查，低误报率",
    "sensitive": "默认检查 + 更全面的检查，低误报率",
    "security": "针对潜在漏洞代码的检查，包含所有 SEI Cert 规则",
    "portability": "检测平台差异带来的代码问题（如32位和64位架构）",
    "extreme": "敏感检查 + 更全面的检查，可接受的误报率",
}

SEVERITY_LEVELS: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {"score": 9.5, "description": "危急漏洞，可导致系统完全被控"},
    "HIGH": {"score": 7.5, "description": "高危漏洞，可导致数据泄露或权限提升"},
    "MEDIUM": {"score": 5.0, "description": "中危漏洞，可导致部分功能受影响"},
    "LOW": {"score": 2.5, "description": "低危漏洞，潜在风险或代码质量问题"},
    "INFO": {"score": 0.0, "description": "信息性发现，不一定是漏洞"},
}

GUIDELINE_REFERENCES: Dict[str, str] = {
    "cwe-top-25-2024": "https://cwe.mitre.org/top25/",
    "sei-cert-c": "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard",
    "owasp-top-10-2021": "https://owasp.org/Top10/2021/",
    "gbt-34943": "GB/T 34943-2017 C/C++ 语言源代码漏洞测试规范",
    "gbt-34944": "GB/T 34944-2017 Java 语言源代码漏洞测试规范",
    "gbt-34946": "GB/T 34946-2017 C# 语言源代码漏洞测试规范",
    "gbt-39412": "GB/T 39412-2020 网络安全技术 源代码漏洞检测规则",
}

ANALYSIS_OPTIONS: Dict[str, Any] = {
    "maxLineLength": 10000,
    "maxFileSize": 10485760,
    "supportedExtensions": list(FILE_EXTENSION_MAP.keys()),
}

AUDIT_SCHEDULING: Dict[str, Any] = {
    "maxBatches": 32,
    "maxFilesPerBatch": 6,
    "maxCharsPerBatch": 35000,
    "maxParallelRequests": 5,
    "maxParallelProjects": 4,
    "embeddingMaxConcurrency": 5,
    "fetchTimeoutMs": 150000,
    "codeIndexMinFiles": 50,
    "codeIndexMaxFiles": 100,
    "checkpointInterval": 3,
}
