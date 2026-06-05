# -*- coding: utf-8 -*-
"""组件漏洞数据 —— 整合自 gbt-codeagent 的已知组件漏洞信息。

提供常见有漏洞组件的检测规则和风险信息。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# 已知有漏洞的组件
COMPONENT_VULNS: Dict[str, Dict[str, Any]] = {
    "log4j-core": {
        "affected_versions": ["2.0-beta9", "2.14.1"],
        "fixed_version": "2.17.1",
        "cve": "CVE-2021-44228",
        "severity": "C",
        "name": "Log4Shell",
        "description": "Apache Log4j2 JNDI 远程代码执行漏洞",
        "detection_pattern": "org.apache.logging.log4j:log4j-core",
        "recommendation": "升级到 log4j-core 2.17.1+ 或设置 log4j2.formatMsgNoLookups=true",
    },
    "fastjson": {
        "affected_versions": ["1.2.80"],
        "fixed_version": "1.2.83",
        "cve": "CVE-2022-25845",
        "severity": "C",
        "name": "Fastjson 反序列化 RCE",
        "description": "Fastjson autoType 绕过导致远程代码执行",
        "detection_pattern": "com.alibaba:fastjson",
        "recommendation": "升级到 fastjson 1.2.83+ 或 fastjson2",
    },
    "jackson-databind": {
        "affected_versions": ["2.13.0"],
        "fixed_version": "2.13.2.1",
        "cve": "CVE-2020-36518",
        "severity": "H",
        "name": "Jackson Databind DoS",
        "description": "Jackson Databind 深度嵌套 JSON 拒绝服务",
        "detection_pattern": "com.fasterxml.jackson.core:jackson-databind",
        "recommendation": "升级到 jackson-databind 2.13.2.1+",
    },
    "spring-framework": {
        "affected_versions": ["5.3.0", "5.3.17"],
        "fixed_version": "5.3.18+",
        "cve": "CVE-2022-22965",
        "severity": "C",
        "name": "Spring4Shell",
        "description": "Spring Framework RCE via Data Binding",
        "detection_pattern": "org.springframework:spring-core",
        "recommendation": "升级到 Spring Framework 5.3.18+ / 5.2.20+",
    },
    "shiro-core": {
        "affected_versions": ["1.2.0", "1.7.1"],
        "fixed_version": "1.8.0",
        "cve": "CVE-2020-1957",
        "severity": "H",
        "name": "Shiro 认证绕过",
        "description": "Apache Shiro 权限绕过漏洞",
        "detection_pattern": "org.apache.shiro:shiro-core",
        "recommendation": "升级到 shiro-core 1.8.0+",
    },
    "xstream": {
        "affected_versions": ["1.4.0", "1.4.18"],
        "fixed_version": "1.4.19",
        "cve": "CVE-2021-39154",
        "severity": "H",
        "name": "XStream 反序列化 RCE",
        "description": "XStream 反序列化远程代码执行",
        "detection_pattern": "com.thoughtworks.xstream:xstream",
        "recommendation": "升级到 XStream 1.4.19+",
    },
    "commons-collections4": {
        "affected_versions": ["4.0", "4.3"],
        "fixed_version": "4.4",
        "cve": "CVE-2015-7501",
        "severity": "H",
        "name": "Commons Collections 反序列化",
        "description": "Apache Commons Collections InvokerTransformer 反序列化利用链",
        "detection_pattern": "org.apache.commons:commons-collections4",
        "recommendation": "升级到 commons-collections4 4.4+ 或使用 commons-collections3 安全版本",
    },
    "snakeyaml": {
        "affected_versions": ["1.0", "1.31"],
        "fixed_version": "1.32",
        "cve": "CVE-2022-1471",
        "severity": "H",
        "name": "SnakeYAML 反序列化 RCE",
        "description": "SnakeYAML Constructor 反序列化远程代码执行",
        "detection_pattern": "org.yaml:snakeyaml",
        "recommendation": "升级到 snakeyaml 1.32+ 或使用 SafeConstructor",
    },
    "express": {
        "affected_versions": ["4.0.0", "4.17.2"],
        "fixed_version": "4.17.3",
        "cve": "CVE-2022-24999",
        "severity": "H",
        "name": "Express QS 污染",
        "description": "Express.js querystring 原型污染",
        "detection_pattern": "express",
        "recommendation": "升级到 express 4.17.3+",
    },
    "lodash": {
        "affected_versions": ["4.0.0", "4.17.20"],
        "fixed_version": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": "M",
        "name": "Lodash 命令注入",
        "description": "Lodash template 命令注入",
        "detection_pattern": "lodash",
        "recommendation": "升级到 lodash 4.17.21+",
    },
    "django": {
        "affected_versions": ["3.2.0", "3.2.12"],
        "fixed_version": "3.2.13",
        "cve": "CVE-2022-28347",
        "severity": "H",
        "name": "Django SQL 注入",
        "description": "Django UnboundField SQL 注入",
        "detection_pattern": "django",
        "recommendation": "升级到 Django 3.2.13+ / 4.0.4+",
    },
    "flask": {
        "affected_versions": ["0.0", "2.2.2"],
        "fixed_version": "2.2.3",
        "cve": "CVE-2023-30861",
        "severity": "M",
        "name": "Flask Cookie 泄露",
        "description": "Flask Vary: Cookie 头导致会话 cookie 泄露",
        "detection_pattern": "flask",
        "recommendation": "升级到 Flask 2.2.3+ / 2.3.2+",
    },
}


def check_component_vuln(component_name: str, version: str = "") -> Optional[Dict[str, Any]]:
    """检查组件是否存在已知漏洞。

    Args:
        component_name: 组件名称（如 log4j-core、fastjson）
        version: 可选的版本号

    Returns:
        漏洞信息字典，无匹配时返回 None
    """
    name_lower = component_name.lower().strip()
    # 精确匹配
    if name_lower in COMPONENT_VULNS:
        return COMPONENT_VULNS[name_lower]
    # 部分匹配
    for key, vuln in COMPONENT_VULNS.items():
        if key in name_lower or name_lower in key:
            return vuln
    return None


def get_all_component_vuln_names() -> List[str]:
    """获取所有已知漏洞组件名称。"""
    return list(COMPONENT_VULNS.keys())


def format_component_vulns_for_prompt(language: str = "") -> str:
    """格式化组件漏洞信息为可注入 prompt 的文本。"""
    lines = ["\n## 已知漏洞组件参考\n"]
    for name, vuln in COMPONENT_VULNS.items():
        lines.append(
            f"- **{name}** ({vuln['cve']}): {vuln['description']} — "
            f"受影响 ≤{vuln['affected_versions'][-1]}，修复版本 {vuln['fixed_version']}"
        )
    return "\n".join(lines)
