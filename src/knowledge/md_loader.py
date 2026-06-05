# -*- coding: utf-8 -*-
"""按需加载 security_reference / gbt_reference 中的 MD 文书，截断注入 LLM prompt。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Set

_KNOWLEDGE_DIR = Path(__file__).resolve().parent

# 漏洞类型 → 关联的领域 MD
_VULN_TO_DOMAINS: Dict[str, List[str]] = {
    "SQL_INJECTION": ["input_validation"],
    "COMMAND_INJECTION": ["input_validation"],
    "CODE_INJECTION": ["input_validation"],
    "SPEL_INJECTION": ["input_validation"],
    "SSTI": ["input_validation"],
    "NOSQL_INJECTION": ["input_validation"],
    "LDAP_INJECTION": ["input_validation"],
    "XPATH_INJECTION": ["input_validation"],
    "XSS": ["input_validation", "frontend_frameworks"],
    "PATH_TRAVERSAL": ["file_operations", "input_validation"],
    "FILE_UPLOAD": ["file_operations"],
    "FILE_OPERATIONS": ["file_operations"],
    "SSRF": ["api_security", "api_gateway_proxy"],
    "XXE": ["input_validation"],
    "DESERIALIZATION": ["input_validation"],
    "AUTH_BYPASS": ["authentication_authorization"],
    "AUTH_MISSING": ["authentication_authorization"],
    "IDOR": ["authentication_authorization", "business_logic"],
    "SESSION_FIXATION": ["authentication_authorization"],
    "CSRF": ["authentication_authorization"],
    "OPEN_REDIRECT": ["authentication_authorization"],
    "CORS_MISCONFIGURATION": ["api_security"],
    "WEAK_CRYPTO": ["cryptography"],
    "WEAK_HASH": ["cryptography"],
    "HARD_CODE_PASSWORD": ["cryptography"],
    "INSECURE_RANDOM": ["cryptography"],
    "INFORMATION_DISCLOSURE": ["logging_security"],
    "LOG_INJECTION": ["logging_security"],
    "BUSINESS_LOGIC": ["business_logic", "race_conditions"],
    "MASS_ASSIGNMENT": ["business_logic"],
    "COOKIE_SECURITY": ["cache_host_header"],
    "RATE_LIMIT": ["api_security"],
    "IDEMPOTENCY": ["business_logic"],
    "RACE_CONDITION": ["race_conditions"],
    "JWT_VULNERABILITIES": ["oauth_oidc_saml"],
    "OAUTH": ["oauth_oidc_saml"],
    "COMPONENT_VULNERABILITY": ["dependencies", "infra_supply_chain"],
    "MAIL_INJECTION": ["input_validation"],
    "REGEX_DOS": ["input_validation"],
}

# 语言 → 关联的框架 MD
_LANG_TO_FRAMEWORKS: Dict[str, List[str]] = {
    "java": ["spring", "java_web_framework", "mybatis_security"],
    "python": ["django", "flask", "fastapi"],
    "javascript": ["express", "koa", "nest_fastify"],
    "typescript": ["express", "koa", "nest_fastify"],
    "csharp": ["dotnet"],
    "ruby": ["rails", "laravel"],  # laravel 是 PHP 但 Ruby 也可以用
    "php": ["laravel"],
    "go": ["gin"],
    "rust": ["rust_web"],
}

# 通用领域 MD（始终注入，但限制总量）
_UNIVERSAL_DOMAINS: List[str] = []

# 缓存的 MD 内容
_cache: Dict[str, str] = {}

MAX_CONTENT_CHARS = 2500  # 单篇截断上限


def _load_md(domain_or_framework: str, subdir: str) -> Optional[str]:
    """加载并缓存单个 MD 文件内容。"""
    cache_key = f"{subdir}/{domain_or_framework}"
    if cache_key in _cache:
        text = _cache[cache_key]
    else:
        paths_to_try = [
            _KNOWLEDGE_DIR / "security_reference" / subdir / f"{domain_or_framework}.md",
            _KNOWLEDGE_DIR / "gbt_reference" / subdir / f"{domain_or_framework}.md",
        ]
        found = None
        for p in paths_to_try:
            if p.is_file():
                found = p
                break
        if not found:
            return None
        text = found.read_text(encoding="utf-8", errors="replace")
        _cache[cache_key] = text

    # 截断
    if len(text) > MAX_CONTENT_CHARS:
        # 保留开头，确保截断在段落边界
        cutoff = text.rfind("\n", 0, MAX_CONTENT_CHARS)
        if cutoff < MAX_CONTENT_CHARS // 2:
            cutoff = MAX_CONTENT_CHARS
        text = text[:cutoff] + "\n...(截断)"

    return text


def _match_vuln_keywords(vul_name: str) -> Set[str]:
    """从漏洞名称匹配领域 ID。"""
    matched: Set[str] = set()
    vuln_upper = vul_name.upper()
    for key, domains in _VULN_TO_DOMAINS.items():
        if key in vuln_upper or any(kw in vul_name for kw in [key]):
            matched.update(domains)
    # 通用回退：任何注入类都查 input_validation
    if "注入" in vul_name or "INJECTION" in vuln_upper:
        matched.add("input_validation")
    if "认证" in vul_name or "登录" in vul_name or "AUTH" in vuln_upper:
        matched.add("authentication_authorization")
    return matched


def inject_domain_knowledge(vul_name: str, max_domains: int = 3) -> str:
    """按漏洞类型注入安全领域 MD。

    Args:
        vul_name: 漏洞类型名称（如 "SQL注入" / "COMMAND_INJECTION"）
        max_domains: 最多注入几个领域
    Returns:
        注入文本（可能为空字符串）
    """
    domain_ids = list(_match_vuln_keywords(vul_name))[:max_domains]
    if not domain_ids:
        return ""

    parts: List[str] = []
    for did in domain_ids:
        text = _load_md(did, "domains")
        if text:
            parts.append(f"\n\n## 安全领域参考: {did}\n{text}")
    return "".join(parts)


def inject_framework_knowledge(language: str, max_frameworks: int = 2) -> str:
    """按语言注入框架安全 MD。

    Args:
        language: 编程语言（如 "java", "python"）
        max_frameworks: 最多注入几个框架
    Returns:
        注入文本（可能为空字符串）
    """
    lang_key = language.lower().lstrip(".")
    framework_ids = _LANG_TO_FRAMEWORKS.get(lang_key, [])[:max_frameworks]
    if not framework_ids:
        return ""

    parts: List[str] = []
    for fid in framework_ids:
        text = _load_md(fid, "frameworks")
        if text:
            parts.append(f"\n\n## 框架安全参考: {fid}\n{text}")
    return "".join(parts)


def inject_gbt_vuln_knowledge(vul_type: str) -> str:
    """按漏洞类型注入 GB/T 漏洞审计 MD。

    Args:
        vul_type: 漏洞类型（如 "command_injection", "sql_injection"）
    Returns:
        注入文本（可能为空字符串）
    """
    # 映射 vuln_profiles 中的 key 到 gbt_reference 文件名
    mapping = {
        "SQL_INJECTION": "sql_injection",
        "COMMAND_INJECTION": "command_injection",
        "CODE_INJECTION": "code_injection",
        "PATH_TRAVERSAL": "path_traversal",
        "DESERIALIZATION": "deserialization",
        "HARD_CODE_PASSWORD": "hardcoded_credentials",
        "WEAK_CRYPTO": "weak_crypto",
    }
    gbt_key = mapping.get(vul_type.upper())
    if not gbt_key:
        return ""

    text = _load_md(gbt_key, "vulnerabilities")
    if text:
        return f"\n\n## GB/T 漏洞审计细则: {gbt_key}\n{text}"
    return ""


def clear_cache() -> None:
    """清空缓存（任务结束时调用）。"""
    _cache.clear()
