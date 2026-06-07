# -*- coding: utf-8 -*-
"""PatternAnalyzer —— 独立于 sink 的模式匹配分析模块。

对标 gbt-codeagent/analyzers/patternAnalyzer.js。
对每个文件进行纯模式匹配，无需先找到 sink 点即可发现漏洞线索。

适用场景：
1. 单文件漏洞检测（硬编码密钥、危险函数调用、弱加密等）
2. 无需跨文件数据流的漏洞模式匹配
3. 作为 SinkFinder 的补充，提供前置线索供 LLM 参考

数据来源：
- VULN_PROFILES：每个漏洞类型按语言的 risk/safe 正则
- DETECTION_PATTERNS：Source→Sink→Safety 三段式检测模式
- QUICK_GREP_RULES：通用快速检索规则
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from bisect import bisect_right
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.vuln_profiles import VULN_PROFILES
from src.knowledge.detection_patterns import DETECTION_PATTERNS
from src.knowledge.security_domains import QUICK_GREP_RULES
from src.knowledge.vuln_scoring import VULN_TYPE_CODES
from src.knowledge.evidence_points import EVIDENCE_POINTS


# ── 严重等级排序 ──
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── 漏洞类型中文→英文映射 ──
_VULN_CN_TO_EN = {
    "命令注入": "COMMAND_INJECTION", "SQL注入": "SQL_INJECTION",
    "路径遍历": "PATH_TRAVERSAL", "SSRF": "SSRF",
    "反序列化": "DESERIALIZATION", "代码注入": "CODE_INJECTION",
    "JNDI注入": "JNDI_INJECTION", "SSTI": "SSTI",
    "XXE": "XXE", "XSS": "XSS",
    "认证绕过": "AUTH_BYPASS", "硬编码凭据": "HARDCODED_CREDENTIALS",
    "文件上传": "FILE_UPLOAD", "文件包含": "FILE_INCLUSION",
    "CORS": "CORS_MISCONFIGURATION", "NoSQL注入": "NOSQL_INJECTION",
    "原型链污染": "PROTOTYPE_POLLUTION", "缓冲区溢出": "BUFFER_OVERFLOW",
    "CSRF": "CSRF", "命令执行": "COMMAND_INJECTION",
    "弱加密": "WEAK_CRYPTO", "弱哈希": "WEAK_HASH",
    "会话固定": "SESSION_FIXATION", "开放重定向": "OPEN_REDIRECT",
    "信息泄露": "INFORMATION_DISCLOSURE", "日志注入": "LOG_INJECTION",
    "竞态条件": "RACE_CONDITION", "整数溢出": "INTEGER_OVERFLOW",
    "不安全随机": "INSECURE_RANDOM", "JWT漏洞": "JWT_VULNERABILITIES",
    "批量赋值": "MASS_ASSIGNMENT", "限速缺失": "RATE_LIMITING",
    "明文传输": "PLAINTEXT_TRANSMISSION", "资源泄漏": "RESOURCE_LEAK",
    "缺失认证": "MISSING_AUTHENTICATION", "缺失访问控制": "MISSING_ACCESS_CONTROL",
    "邮箱注入": "EMAIL_INJECTION",
}

_INVERSE_VULN_MAP = {v: k for k, v in _VULN_CN_TO_EN.items()}


def _build_line_offsets(content: str) -> List[int]:
    """预计算换行符位置表，用于 O(log n) 行号查找。"""
    offsets = []
    for i, ch in enumerate(content):
        if ch == "\n":
            offsets.append(i)
    return offsets


def _offset_to_line(offsets: List[int], pos: int) -> int:
    """根据换行位置表，用二分查找将字符偏移转为行号（1-based）。"""
    return bisect_right(offsets, pos) + 1


def _detect_language_from_ext(file_path: str) -> str:
    """从文件扩展名推断编程语言。"""
    ext_map = {
        ".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript",
        ".php": "php", ".rb": "ruby", ".go": "go", ".rs": "rust",
        ".cs": "csharp", ".cpp": "cpp", ".c": "cpp", ".h": "cpp",
        ".kt": "kotlin", ".swift": "swift", ".scala": "scala",
        ".vue": "javascript", ".jsx": "javascript", ".tsx": "typescript",
        ".yaml": "yaml", ".yml": "yaml", ".xml": "xml",
        ".sql": "sql", ".sh": "shell", ".bat": "batch", ".ps1": "powershell",
    }
    _, ext = os.path.splitext(file_path)
    return ext_map.get(ext.lower(), "unknown")


class PatternAnalyzer:
    """独立于 sink 的模式匹配分析器。

    对单个文件执行多层模式匹配，无需跨文件数据流分析。
    发现结果可直接用于审计报告，或作为 SinkFinder/LLM 的上下文线索。
    """

    def __init__(self) -> None:
        # 预编译 VULN_PROFILES 中的所有风险和安全模式
        # {vuln_type: {lang: {"risk": [Pattern], "safe": [Pattern], "remediation": str}}}
        self._risk_patterns: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._compile_vuln_profiles()

        # 从 DETECTION_PATTERNS 构建 sink 函数名匹配列表
        # {lang: [(pattern_regex, vuln_type, sink_desc)]}
        self._detection_patterns: Dict[str, List[Tuple[re.Pattern, str, str]]] = {}
        self._compile_detection_patterns()

        # 从 QUICK_GREP_RULES 构建通用规则
        self._common_grep_patterns: List[Tuple[re.Pattern, str, str]] = []
        self._compile_grep_rules()

        # 证据点映射 (evidence_type -> EVIDENCE_POINTS 列表)
        self._evidence_map: Dict[str, str] = {}
        self._build_evidence_map()

        # 计数统计
        self._total_scanned = 0
        self._total_findings = 0
        # 文件内容缓存（由上游 QuickScanService 预填充）
        self._file_content_cache: Dict[str, str] = {}

    def set_file_content_cache(self, cache: Dict[str, str]) -> None:
        """预填充文件内容缓存，避免重复 I/O（由 QuickScanService 的缓存注入）。"""
        self._file_content_cache = dict(cache)

    def _compile_vuln_profiles(self) -> None:
        """从 VULN_PROFILES 编译风险和安全模式。"""
        for vuln_type, config in VULN_PROFILES.items():
            languages = config.get("languages", {})
            for lang, lang_cfg in languages.items():
                risk_patterns = lang_cfg.get("risk", [])
                safe_patterns = lang_cfg.get("safe", [])
                remediation = lang_cfg.get("remediation", "")
                severity = config.get("default_severity", "MEDIUM")
                cwe = config.get("cwe", "")
                gbt = config.get("gbt", "")

                if not risk_patterns:
                    continue

                if vuln_type not in self._risk_patterns:
                    self._risk_patterns[vuln_type] = {}

                self._risk_patterns[vuln_type][lang] = {
                    "risk": risk_patterns,
                    "safe": safe_patterns,
                    "remediation": remediation,
                    "severity": severity,
                    "cwe": cwe,
                    "gbt": gbt,
                }

    def _compile_detection_patterns(self) -> None:
        """从 DETECTION_PATTERNS 编译 sink 匹配模式。

        将 DETECTION_PATTERNS 中的 sink 描述转为函数名正则，
        用于匹配代码中是否出现对应名称的函数调用。
        """
        for lang, vulns in DETECTION_PATTERNS.items():
            lang_patterns = []
            for vuln_cn, vuln_list in vulns.items():
                vuln_type = _VULN_CN_TO_EN.get(vuln_cn, vuln_cn.upper())
                for entry in vuln_list:
                    sink_str = entry.get("sink", "")
                    if not sink_str:
                        continue
                    sink_parts = [s.strip() for s in sink_str.split(",") if s.strip()]
                    for part in sink_parts:
                        name = re.match(r"([A-Za-z_]\w*)", part.strip())
                        if not name:
                            continue
                        # 构建函数名匹配正则
                        func_name = re.escape(name.group(1))
                        try:
                            regex = re.compile(r"\b" + func_name + r"\s*\(", re.IGNORECASE)
                        except re.error:
                            continue
                        lang_patterns.append((regex, vuln_type, part))
            if lang_patterns:
                self._detection_patterns[lang] = lang_patterns

    def _compile_grep_rules(self) -> None:
        """从 QUICK_GREP_RULES 编译通用 grep 规则。"""
        for vuln_type_key, rule_list in QUICK_GREP_RULES.items():
            for rule in rule_list:
                pattern_str = rule.get("pattern", "")
                description = rule.get("description", "")
                severity = rule.get("severity", "MEDIUM")
                if not pattern_str:
                    continue
                try:
                    regex = re.compile(pattern_str, re.IGNORECASE)
                except re.error:
                    continue
                self._common_grep_patterns.append(
                    (regex, vuln_type_key.upper(), description or pattern_str[:80])
                )

    def _build_evidence_map(self) -> None:
        """构建证据点映射：证据点ID -> 类型前缀。"""
        for etype, points in EVIDENCE_POINTS.items():
            for point in points:
                self._evidence_map[point] = etype

    def reset(self) -> None:
        """重置统计。"""
        self._total_scanned = 0
        self._total_findings = 0

    # ── 核心分析接口 ──

    def analyze_file(
        self,
        file_path: str,
        content: Optional[str] = None,
        language: Optional[str] = None,
    ) -> Dict[str, Any]:
        """分析单个文件的所有模式。

        Args:
            file_path: 文件路径
            content: 文件内容（可选，不传入则自动读取）
            language: 编程语言（可选，不传则从扩展名推断）

        Returns:
            {
                "success": bool,
                "file_path": str,
                "language": str,
                "findings": [{
                    "vuln_type": str,
                    "severity": str,
                    "line": int,
                    "evidence": str,
                    "remediation": str,
                    "pattern_type": str,  # "vuln_profile" | "detection_pattern" | "grep_rule"
                    "sink_details": str,
                    "has_safe_pattern": bool,
                    "safe_patterns": [str],
                }],
                "summary": {"CRITICAL": int, "HIGH": int, "MEDIUM": int, "LOW": int},
            }
        """
        # 读取文件内容
        if content is None:
            content = self._file_content_cache.get(file_path)
        if content is None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                return {"success": False, "file_path": file_path, "error": str(e), "findings": []}

        if not content.strip():
            return {"success": True, "file_path": file_path, "language": language, "findings": []}

        if language is None:
            language = _detect_language_from_ext(file_path)

        line_offsets = _build_line_offsets(content)
        findings = []

        # 1. 从 VULN_PROFILES 匹配风险模式
        findings.extend(self._match_vuln_profiles(content, language, line_offsets))

        # 2. 从 DETECTION_PATTERNS 匹配检测模式
        findings.extend(self._match_detection_patterns(content, language, line_offsets))

        # 3. 从 QUICK_GREP_RULES 匹配通用规则
        findings.extend(self._match_grep_rules(content, line_offsets))

        # 去重（基于 vuln_type + evidence）
        deduped = self._deduplicate_findings(findings)

        # 统计
        summary: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in deduped:
            sev = f.get("severity", "MEDIUM").upper()
            if sev not in summary:
                sev = "MEDIUM"
            summary[sev] += 1

        self._total_scanned += 1
        self._total_findings += len(deduped)

        return {
            "success": True,
            "file_path": file_path,
            "language": language,
            "findings": deduped,
            "summary": summary,
        }

    def _match_vuln_profiles(
        self,
        content: str,
        language: str,
        line_offsets: List[int],
    ) -> List[Dict[str, Any]]:
        """从 VULN_PROFILES 匹配风险模式。"""
        findings = []

        for vuln_type, lang_configs in self._risk_patterns.items():
            # 先匹配语言精确，再匹配通用（不限制语言）
            lang_cfg = lang_configs.get(language, lang_configs.get("", None))
            if lang_cfg is None:
                # 尝试匹配其他语言的通用模式（不限制语言的模式）
                continue

            risk_patterns = lang_cfg["risk"]
            safe_patterns = lang_cfg["safe"]
            remediation = lang_cfg["remediation"]
            severity = lang_cfg["severity"]
            cwe = lang_cfg["cwe"]
            gbt = lang_cfg["gbt"]

            for pattern in risk_patterns:
                for match in pattern.finditer(content):
                    line = _offset_to_line(line_offsets, match.start())
                    evidence = content[max(0, match.start()-10):match.end()+10]

                    # 检查同一行是否有安全模式
                    has_safe = any(
                        safe_pat.search(content, match.pos, match.endpos)
                        for safe_pat in safe_patterns
                    )

                    findings.append({
                        "vuln_type": vuln_type,
                        "severity": severity,
                        "line": line,
                        "evidence": evidence.strip(),
                        "remediation": remediation,
                        "pattern_type": "vuln_profile",
                        "sink_details": evidence.strip()[:80],
                        "has_safe_pattern": has_safe,
                        "cwe": cwe,
                        "gbt": gbt,
                    })

        return findings

    def _match_detection_patterns(
        self,
        content: str,
        language: str,
        line_offsets: List[int],
    ) -> List[Dict[str, Any]]:
        """从 DETECTION_PATTERNS 匹配 sink 函数名模式。"""
        findings = []
        lang_patterns = self._detection_patterns.get(language, [])

        for regex, vuln_type, sink_desc in lang_patterns:
            for match in regex.finditer(content):
                line = _offset_to_line(line_offsets, match.start())
                evidence = content[max(0, match.start()-5):match.end()+10]
                findings.append({
                    "vuln_type": vuln_type,
                    "severity": "HIGH" if vuln_type in (
                        "COMMAND_INJECTION", "CODE_INJECTION", "SQL_INJECTION",
                        "DESERIALIZATION", "XXE",
                    ) else "MEDIUM",
                    "line": line,
                    "evidence": evidence.strip(),
                    "remediation": f"注意：检测到 {sink_desc} 调用，需确认输入来源是否可控",
                    "pattern_type": "detection_pattern",
                    "sink_details": sink_desc,
                    "has_safe_pattern": False,
                    "cwe": "",
                    "gbt": "",
                })

        return findings

    def _match_grep_rules(
        self,
        content: str,
        line_offsets: List[int],
    ) -> List[Dict[str, Any]]:
        """从 QUICK_GREP_RULES 匹配通用规则。"""
        findings = []

        for regex, vuln_type, description in self._common_grep_patterns:
            for match in regex.finditer(content):
                line = _offset_to_line(line_offsets, match.start())
                evidence = content[max(0, match.start()-10):match.end()+10]
                if len(findings) >= 200:  # 单个文件最多 200 条规则匹配
                    break
                findings.append({
                    "vuln_type": vuln_type,
                    "severity": "MEDIUM",
                    "line": line,
                    "evidence": evidence.strip(),
                    "remediation": description,
                    "pattern_type": "grep_rule",
                    "sink_details": description,
                    "has_safe_pattern": False,
                    "cwe": "",
                    "gbt": "",
                })
            if len(findings) >= 200:
                break

        return findings

    def _deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """基于 vuln_type + line + evidence 去重。"""
        seen: Set[str] = set()
        deduped = []
        for f in findings:
            key = f"{f['vuln_type']}:{f['line']}:{f['evidence'][:40]}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    # ── 批量分析 ──

    def analyze_files(
        self,
        file_paths: List[str],
        max_workers: int = 4,
    ) -> Dict[str, Any]:
        """批量分析多个文件。

        Args:
            file_paths: 文件路径列表
            max_workers: 最大并行数

        Returns:
            {
                "success": bool,
                "total_files": int,
                "total_findings": int,
                "results": [单个文件结果],
                "aggregate_summary": {"CRITICAL": int, "HIGH": int, ...},
            }
        """
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self.analyze_file, fp): fp
                for fp in file_paths
            }
            for future in as_completed(future_map):
                try:
                    results.append(future.result())
                except Exception as e:
                    fp = future_map[future]
                    results.append({
                        "success": False,
                        "file_path": fp,
                        "error": str(e),
                        "findings": [],
                    })

        # 汇总
        aggregate: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_findings = 0
        for r in results:
            if r.get("findings"):
                for f in r["findings"]:
                    sev = f.get("severity", "MEDIUM").upper()
                    if sev in aggregate:
                        aggregate[sev] += 1
                total_findings += len(r["findings"])

        return {
            "success": True,
            "total_files": len(file_paths),
            "total_findings": total_findings,
            "results": results,
            "aggregate_summary": aggregate,
        }

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息。"""
        return {
            "scanned_files": self._total_scanned,
            "total_findings": self._total_findings,
        }
