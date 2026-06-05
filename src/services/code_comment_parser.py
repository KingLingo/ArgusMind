# -*- coding: utf-8 -*-
"""代码注释解析服务 —— 整合自 gbt-codeagent/services/codeCommentParser.js。

解析代码中的注释和抑制规则，用于：
- 在 ValidationService 中过滤被抑制的漏洞发现
- 在 CandidateFilter 中降低被抑制行的评分
- 在 LLM Optimizer 误报检测中识别抑制标记

调用链：Orchestrator → QuickScanService → CodeCommentParser（解析注释）
         Orchestrator → LLMOptimizer → CodeCommentParser（误报检测）
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.audit_config import SUPPRESSION_PATTERNS


# === 语言注释模式 ===

_SINGLE_LINE_PATTERNS: Dict[str, re.Pattern] = {
    "javascript": re.compile(r"//(.*)$"),
    "typescript": re.compile(r"//(.*)$"),
    "java": re.compile(r"//(.*)$"),
    "cpp": re.compile(r"//(.*)$"),
    "c": re.compile(r"//(.*)$"),
    "csharp": re.compile(r"//(.*)$"),
    "go": re.compile(r"//(.*)$"),
    "rust": re.compile(r"//(.*)$"),
    "kotlin": re.compile(r"//(.*)$"),
    "swift": re.compile(r"//(.*)$"),
    "python": re.compile(r"#(.*)$"),
    "ruby": re.compile(r"#(.*)$"),
    "php": re.compile(r"#(.*)$"),
    "yaml": re.compile(r"#(.*)$"),
    "sql": re.compile(r"--(.*)$"),
}

_MULTI_LINE_PATTERNS: Dict[str, Tuple[re.Pattern, re.Pattern]] = {
    "javascript": (re.compile(r"/\*"), re.compile(r"\*/")),
    "typescript": (re.compile(r"/\*"), re.compile(r"\*/")),
    "java": (re.compile(r"/\*"), re.compile(r"\*/")),
    "cpp": (re.compile(r"/\*"), re.compile(r"\*/")),
    "c": (re.compile(r"/\*"), re.compile(r"\*/")),
    "csharp": (re.compile(r"/\*"), re.compile(r"\*/")),
    "go": (re.compile(r"/\*"), re.compile(r"\*/")),
    "rust": (re.compile(r"/\*"), re.compile(r"\*/")),
    "html": (re.compile(r"<!--"), re.compile(r"-->")),
    "xml": (re.compile(r"<!--"), re.compile(r"-->")),
}


def _extract_suppressions(text: str) -> List[str]:
    """从注释文本中提取抑制规则。"""
    suppressions: List[str] = []
    for pattern in SUPPRESSION_PATTERNS:
        match = pattern.search(text)
        if match and match.lastindex:
            suppressions.append(match.group(1).upper())
    return suppressions


class CommentInfo:
    """注释解析结果。"""

    __slots__ = ("single_line", "multi_line", "suppressed_rules")

    def __init__(self) -> None:
        self.single_line: List[Dict[str, Any]] = []
        self.multi_line: List[Dict[str, Any]] = []
        self.suppressed_rules: Set[str] = set()


class CodeCommentParser:
    """代码注释解析器。

    在以下位置被调用：
    1. QuickScanService.scan_file() — 解析文件注释，标记抑制行
    2. LLMOptimizer.is_false_positive() — 检查发现是否被抑制
    3. ValidationService.validate_finding() — 过滤被抑制的发现
    """

    def __init__(self) -> None:
        self._cache: Dict[str, CommentInfo] = {}

    def parse_code_comments(self, code: str, language: str = "javascript") -> CommentInfo:
        """解析代码中的注释。

        Args:
            code: 代码内容
            language: 语言标识

        Returns:
            CommentInfo 包含单行注释、多行注释、抑制规则
        """
        info = CommentInfo()
        lines = code.split("\n")
        in_multi_line = False
        multi_line_start = -1
        multi_line_content: List[Dict[str, Any]] = []

        single_pattern = _SINGLE_LINE_PATTERNS.get(language.lower())
        multi_pattern = _MULTI_LINE_PATTERNS.get(language.lower())

        for i, line in enumerate(lines):
            line_num = i + 1

            # 多行注释处理
            if multi_pattern:
                start_pat, end_pat = multi_pattern
                start_match = start_pat.search(line)
                end_match = end_pat.search(line)

                if in_multi_line:
                    multi_line_content.append({"line": line_num, "content": line})
                    if end_match:
                        content_text = "\n".join(c["content"] for c in multi_line_content)
                        sups = _extract_suppressions(content_text)
                        info.multi_line.append({
                            "start_line": multi_line_start,
                            "end_line": line_num,
                            "suppressions": sups,
                        })
                        info.suppressed_rules.update(sups)
                        in_multi_line = False
                        multi_line_content = []
                elif start_match:
                    in_multi_line = True
                    multi_line_start = line_num
                    multi_line_content.append({"line": line_num, "content": line})
                    if end_match:
                        sups = _extract_suppressions(line)
                        info.multi_line.append({
                            "start_line": multi_line_start,
                            "end_line": line_num,
                            "suppressions": sups,
                        })
                        info.suppressed_rules.update(sups)
                        in_multi_line = False
                        multi_line_content = []

            # 单行注释处理
            if not in_multi_line and single_pattern:
                match = single_pattern.search(line)
                if match:
                    # 提取注释内容（// 或 # 之后的部分）
                    comment_start = match.start()
                    comment_text = line[comment_start:]
                    sups = _extract_suppressions(comment_text)
                    info.single_line.append({
                        "line": line_num,
                        "suppressions": sups,
                    })
                    info.suppressed_rules.update(sups)

        # 处理未闭合的多行注释
        if in_multi_line and multi_line_content:
            info.multi_line.append({
                "start_line": multi_line_start,
                "end_line": len(lines),
                "suppressions": [],
                "unclosed": True,
            })

        return info

    def is_line_suppressed(self, line_number: int, comments: CommentInfo) -> Dict[str, Any]:
        """检查某行是否被抑制。

        Args:
            line_number: 行号
            comments: 注释解析结果

        Returns:
            包含 suppressed / rules / source 的字典
        """
        # 检查单行注释
        for comment in comments.single_line:
            if comment["line"] == line_number and comment["suppressions"]:
                return {
                    "suppressed": True,
                    "rules": comment["suppressions"],
                    "source": "single_line",
                    "line": comment["line"],
                }

        # 检查多行注释
        for comment in comments.multi_line:
            if comment["start_line"] <= line_number <= comment["end_line"]:
                return {
                    "suppressed": bool(comment["suppressions"]),
                    "rules": comment.get("suppressions", []),
                    "source": "multi_line",
                    "start_line": comment["start_line"],
                    "end_line": comment["end_line"],
                }

        return {"suppressed": False}

    def is_finding_suppressed(self, finding: Dict[str, Any], comments: CommentInfo) -> bool:
        """检查漏洞发现是否被抑制。

        在 LLMOptimizer 和 ValidationService 中被调用。

        Args:
            finding: 漏洞发现
            comments: 注释解析结果

        Returns:
            是否被抑制
        """
        line = finding.get("line", 1)
        if isinstance(line, str):
            try:
                line = int(line)
            except (ValueError, TypeError):
                line = 1

        rule_id = (finding.get("vuln_type") or finding.get("vulnType") or "").upper()

        result = self.is_line_suppressed(line, comments)

        if not result["suppressed"]:
            return False

        rules = result.get("rules", [])
        if not rules:
            return True

        return any(
            rule == rule_id or rule == "ALL" or "*" in rule
            for rule in rules
        )

    def filter_suppressed_findings(
        self, findings: List[Dict[str, Any]], comments: CommentInfo
    ) -> Dict[str, List[Dict[str, Any]]]:
        """过滤被抑制的漏洞发现。

        在 QuickScanService 中被调用，将抑制发现从结果中分离。

        Args:
            findings: 漏洞发现列表
            comments: 注释解析结果

        Returns:
            包含 suppressed / active 两个列表的字典
        """
        result: Dict[str, List[Dict[str, Any]]] = {"suppressed": [], "active": []}

        for finding in findings:
            if self.is_finding_suppressed(finding, comments):
                finding_copy = dict(finding)
                finding_copy["suppressed_by"] = "code_comment"
                result["suppressed"].append(finding_copy)
            else:
                result["active"].append(finding)

        return result

    def get_comment_ranges(self, code: str, language: str = "javascript") -> List[Dict[str, Any]]:
        """获取注释范围列表。

        在 SmartFileFilter 中被调用，用于排除注释行。

        Args:
            code: 代码内容
            language: 语言标识

        Returns:
            注释范围列表，按起始行排序
        """
        info = self.parse_code_comments(code, language)
        ranges: List[Dict[str, Any]] = []

        for comment in info.single_line:
            ranges.append({
                "type": "single_line",
                "start_line": comment["line"],
                "end_line": comment["line"],
                "suppressions": comment["suppressions"],
            })

        for comment in info.multi_line:
            ranges.append({
                "type": "multi_line",
                "start_line": comment["start_line"],
                "end_line": comment["end_line"],
                "suppressions": comment.get("suppressions", []),
            })

        return sorted(ranges, key=lambda r: r["start_line"])
