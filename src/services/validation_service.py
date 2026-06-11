# -*- coding: utf-8 -*-
"""漏洞验证服务 —— 整合自 gbt-codeagent/services/validationService.js。

负责验证漏洞发现的准确性，包括：
- 代码片段验证（行号修正、内容匹配）
- 批量发现验证（幻觉检测）
- 净化措施检测
- 三维评分体系（可达性、影响范围、利用复杂度）
- 未解决风险检查
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.sanitizer_patterns import SANITIZER_PATTERNS

logger = logging.getLogger(__name__)

# 漏洞类型 → 语言支持映射
LANGUAGE_VULN_MAP: Dict[str, Dict[str, List[str]]] = {
    ".py": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION",
            "DESERIALIZATION", "SSRF", "XSS", "PATH_TRAVERSAL",
            "HARD_CODED_SECRET", "WEAK_CRYPTO", "INSECURE_RANDOM",
        ],
    },
    ".java": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION",
            "XXE", "SSRF", "PATH_TRAVERSAL", "AUTH_BYPASS",
            "SSTI", "SPEL_INJECTION", "JNDI_INJECTION",
        ],
    },
    ".js": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "XSS",
            "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION",
            "PROTOTYPE_POLLUTION",
        ],
    },
    ".go": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL",
            "SSRF", "CODE_INJECTION",
        ],
    },
    ".php": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "XSS",
            "PATH_TRAVERSAL", "FILE_UPLOAD", "DESERIALIZATION",
        ],
    },
    ".cs": {
        "supported": [
            "SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION",
            "XSS", "AUTH_BYPASS",
        ],
    },
}


def _detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return ext if ext in LANGUAGE_VULN_MAP else ""


def _is_vulnerability_supported(vuln_type: str, language: str) -> bool:
    """检查漏洞类型是否在该语言的预设白名单中。"""
    if not language or not vuln_type:
        return True  # 无法判断时保留
    lang_info = LANGUAGE_VULN_MAP.get(language)
    if not lang_info:
        return True
    return vuln_type.upper() in [v.upper() for v in lang_info.get("supported", [])]


@dataclass
class SnippetValidationResult:
    """代码片段验证结果。"""
    valid: bool = False
    actual_code: str = ""
    corrected_line: Optional[int] = None
    original_line: Optional[int] = None
    verified_by: str = ""
    error: str = ""


@dataclass
class FindingValidationResult:
    """单个发现的验证结果。"""
    finding: Dict[str, Any] = field(default_factory=dict)
    valid: bool = True
    corrected: bool = False
    original_line: Optional[int] = None
    corrected_line: Optional[int] = None
    note: str = ""
    is_hallucination: bool = False


@dataclass
class BatchValidationResult:
    """批量验证结果。"""
    validated: List[Dict[str, Any]] = field(default_factory=list)
    hallucinations: List[Dict[str, Any]] = field(default_factory=list)
    corrected: List[FindingValidationResult] = field(default_factory=list)

    def get_active_findings(self) -> List[Dict[str, Any]]:
        """获取活跃 findings（未被驳回）。"""
        from src.services.finding_postprocess import get_active_findings
        return get_active_findings(self.validated)

    def get_rejected_findings(self) -> List[Dict[str, Any]]:
        """获取被驳回的 findings。"""
        from src.services.finding_postprocess import get_rejected_findings
        return get_rejected_findings(self.validated)

    def get_severity_breakdown(self) -> Dict[str, int]:
        """获取严重等级分布（仅活跃 findings）。"""
        from src.services.finding_postprocess import get_effective_severity, is_active
        counts: Dict[str, int] = {}
        for f in self.validated:
            if not is_active(f):
                continue
            sev = get_effective_severity(f)
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def get_highest_severity(self) -> str:
        """获取最高等级（仅活跃 findings）。"""
        breakdown = self.get_severity_breakdown()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if breakdown.get(sev, 0) > 0:
                return sev
        return "UNKNOWN"


@dataclass
class RiskEntry:
    """未解决风险条目。"""
    vuln_id: str = ""
    type: str = ""
    severity: str = ""
    location: str = ""
    status: str = "已确认"
    priority: str = "low"
    reasons: List[str] = field(default_factory=list)
    score: int = 0
    reachability: str = "unknown"
    impact: str = "unknown"
    complexity: str = "unknown"
    recommendation: str = ""


class ValidationService:
    """漏洞验证服务。

    核心能力：
    1. 代码片段验证：确认 LLM 输出的代码确实存在于文件中
    2. 行号修正：自动修正 LLM 输出的错误行号
    3. 幻觉检测：识别 LLM 虚构的漏洞发现
    4. 净化措施检测：识别代码中的安全防护措施
    5. 三维评分：可达性、影响范围、利用复杂度
    """

    def __init__(self) -> None:
        self._sanitizer_patterns = SANITIZER_PATTERNS

    # ---------- 代码片段验证 ----------

    def validate_code_snippet(
        self,
        file_path: str,
        line: int,
        code_snippet: str,
        preloaded_lines: Optional[List[str]] = None,
    ) -> SnippetValidationResult:
        """验证代码片段是否存在于文件指定行号。"""
        try:
            lines = preloaded_lines
            if lines is None:
                if not os.path.isfile(file_path):
                    return SnippetValidationResult(
                        valid=False, error=f"文件不存在: {file_path}"
                    )
                content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                lines = content.split("\n")

            if line < 1 or line > len(lines):
                return SnippetValidationResult(
                    valid=False, error=f"行号 {line} 超出范围 (1-{len(lines)})"
                )

            code_lines = [l for l in code_snippet.split("\n") if l.strip()]
            keywords = [l.strip() for l in code_lines if len(l.strip()) > 3]

            if not keywords:
                return SnippetValidationResult(valid=False, error="代码片段为空")

            # 1. 精确行匹配
            target_line = lines[line - 1]
            if any(kw in target_line for kw in keywords):
                return SnippetValidationResult(
                    valid=True, actual_code=target_line.strip(), verified_by="exact_line_match"
                )

            # 2. 关键词搜索（优先匹配指定行附近）
            regex_pattern = re.escape(keywords[0])
            keyword_regex = re.compile(regex_pattern, re.IGNORECASE)

            grep_match_line = None
            grep_match_content = None
            grep_first_match_line = None
            grep_first_match_content = None

            for i, file_line in enumerate(lines):
                if keyword_regex.search(file_line):
                    if i + 1 == line:
                        grep_match_line = i + 1
                        grep_match_content = file_line.strip()
                    if grep_first_match_line is None:
                        grep_first_match_line = i + 1
                        grep_first_match_content = file_line.strip()
                    if grep_match_line is not None and grep_first_match_line is not None:
                        break

            if grep_match_line is not None:
                return SnippetValidationResult(
                    valid=True, actual_code=grep_match_content, verified_by="keyword_search"
                )

            if grep_first_match_line is not None:
                return SnippetValidationResult(
                    valid=True,
                    actual_code=grep_first_match_content,
                    corrected_line=grep_first_match_line,
                    original_line=line,
                    verified_by="keyword_search",
                )

            # 3. 模糊搜索（指定行前后 10 行）
            search_range = 10
            start = max(0, line - search_range - 1)
            end = min(len(lines), line + search_range)

            for i in range(start, end):
                if any(kw in lines[i] for kw in keywords):
                    return SnippetValidationResult(
                        valid=True,
                        actual_code=lines[i].strip(),
                        corrected_line=i + 1,
                        original_line=line,
                    )

            return SnippetValidationResult(
                valid=False,
                error="代码片段未在文件中找到",
            )

        except Exception as e:
            return SnippetValidationResult(valid=False, error=f"验证失败: {e}")

    # ---------- 批量验证 ----------

    def validate_findings(
        self,
        findings: List[Dict[str, Any]],
        project_root: str,
    ) -> BatchValidationResult:
        """批量验证漏洞发现，检测幻觉并修正行号。

        合并了原 AgentOutputValidator 的非空检查：
        - title/severity/location 缺失视为无效发现
        - evidence/description 缺失降级保留
        """
        result = BatchValidationResult()

        # 阶段 1：非空检查（原 AgentOutputValidator 逻辑）
        from src.core.enums import VerificationStatus
        checked_findings: List[Dict[str, Any]] = []
        for finding in findings:
            if not finding or not isinstance(finding, dict):
                result.hallucinations.append({
                    "validation_error": "finding 不是有效对象",
                })
                continue

            # 初始化验证状态
            finding.setdefault("verification_status", VerificationStatus.UNREVIEWED.value)

            # 必填字段检查
            title = finding.get("title", "")
            severity = finding.get("severity", "")
            location = finding.get("location", finding.get("filePath", finding.get("file", "")))
            line = finding.get("line", 0)

            if not title or not title.strip():
                result.hallucinations.append({
                    **finding,
                    "validation_error": "title 为空",
                })
                continue
            if not severity or not str(severity).strip():
                result.hallucinations.append({
                    **finding,
                    "validation_error": "severity 缺失",
                })
                continue
            if not location and not line:
                result.hallucinations.append({
                    **finding,
                    "validation_error": "location/filePath 缺失",
                })
                continue

            # evidence/description 缺失 → 降级保留
            evidence = finding.get("evidence", finding.get("description", ""))
            if not evidence and finding.get("confidence", 0) < 0.55:
                finding["confidence"] = 0.55

            checked_findings.append(finding)

        # 阶段 2：代码片段验证 + 行号修正 + 幻觉检测
        # 按文件分组，减少文件读取次数
        file_map: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
        for idx, finding in enumerate(checked_findings):
            file_path = self._extract_file_path(finding, project_root)
            if not file_path:
                result.hallucinations.append({
                    **finding,
                    "validation_error": "缺少文件路径信息",
                })
                continue

            if not os.path.isfile(file_path):
                # 文件可能已被清理（临时目录过期），保留发现但不做深层的代码验证
                finding["validation_note"] = "文件已不存在（临时目录已清理）"
                result.validated.append(finding)
                continue

            file_map.setdefault(file_path, []).append((idx, finding))

        # 逐文件验证
        for file_path, file_findings in file_map.items():
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="replace")
                lines = content.split("\n")
            except Exception as e:
                for _, finding in file_findings:
                    result.hallucinations.append({
                        **finding,
                        "validation_error": f"文件读取失败: {e}",
                    })
                continue

            for idx, finding in file_findings:
                val_result = self._validate_single_finding(finding, lines, file_path, project_root)
                if val_result.valid:
                    finding["verification_status"] = VerificationStatus.CONFIRMED.value
                    result.validated.append(val_result.finding)
                    if val_result.corrected:
                        result.corrected.append(val_result)
                else:
                    if val_result.is_hallucination:
                        finding["verification_status"] = VerificationStatus.REJECTED.value
                        result.hallucinations.append({
                            **val_result.finding,
                            "validation_error": val_result.note,
                        })
                    else:
                        # 验证失败但不确定是幻觉，标记为 uncertain
                        finding["verification_status"] = VerificationStatus.UNCERTAIN.value
                        val_result.finding["validation_note"] = val_result.note
                        result.validated.append(val_result.finding)

        return result

    def _validate_single_finding(
        self,
        finding: Dict[str, Any],
        lines: List[str],
        file_path: str,
        project_root: str,
    ) -> FindingValidationResult:
        """验证单个漏洞发现。"""
        line = finding.get("line", 0)
        code_snippet = finding.get("codeSnippet", finding.get("code_snippet", ""))

        # 从 location 提取行号
        if not line and finding.get("location"):
            location_parts = str(finding["location"]).split(":")
            if len(location_parts) >= 2:
                try:
                    line = int(location_parts[1])
                except ValueError:
                    pass

        # 如果没有代码片段，从文件内容提取
        if not code_snippet and 1 <= line <= len(lines):
            code_snippet = lines[line - 1]

        if not code_snippet:
            return FindingValidationResult(
                finding={**finding, "status": "有效"},
                valid=True,
                note="code_not_available",
            )

        # 如果没有行号，搜索代码片段
        if not line:
            relative_path = os.path.relpath(file_path, project_root).replace("\\", "/")
            val = self.validate_code_snippet(file_path, 1, code_snippet, lines)
            if val.valid and val.corrected_line:
                finding["line"] = val.corrected_line
                finding["location"] = f"{relative_path}:{val.corrected_line}"
            return FindingValidationResult(
                finding={**finding, "status": "有效"},
                valid=True,
                note="no_line_found",
            )

        # 技术栈一致性检查
        language = _detect_language(file_path)
        vuln_type = finding.get("vulnType", finding.get("type", ""))
        if not _is_vulnerability_supported(vuln_type, language):
            return FindingValidationResult(
                finding={**finding, "status": "有效"},
                valid=True,
                note=f"漏洞类型 '{vuln_type}' 不在语言 '{language}' 的预设白名单中，保留发现",
            )

        # 验证代码片段
        val = self.validate_code_snippet(file_path, line, code_snippet, lines)

        if val.valid:
            updated = {
                **finding,
                "status": "有效",
                "validated_code": val.actual_code,
            }
            if val.corrected_line:
                relative_path = os.path.relpath(file_path, project_root).replace("\\", "/")
                updated["line"] = val.corrected_line
                updated["location"] = f"{relative_path}:{val.corrected_line}"
                updated["corrected_from"] = val.original_line

            # 检测净化措施（复用 QuickScanFilter 已有的 guardContext，避免重复检测）
            guard_ctx = finding.get("guardContext", {})
            if guard_ctx and guard_ctx.get("hasGuardPattern"):
                # QuickScanFilter 已检测到守卫模式，直接复用
                updated["sanitizer_detected"] = {
                    "detected": True,
                    "sanitizers": guard_ctx.get("notes", []),
                    "note": f"复用快速扫描守卫检测结果: {', '.join(guard_ctx.get('notes', []))}",
                    "source": "quick_scan_filter",
                }
            else:
                sanitizer_info = self._check_sanitizers(updated, lines)
                if sanitizer_info:
                    updated["sanitizer_detected"] = sanitizer_info

            return FindingValidationResult(
                finding=updated,
                valid=True,
                corrected=bool(val.corrected_line),
                original_line=val.original_line,
                corrected_line=val.corrected_line,
            )

        # 代码片段未找到，但不确定是幻觉
        return FindingValidationResult(
            finding={**finding, "status": "有效"},
            valid=True,
            note=f"code_snippet_unverified: {val.error}",
        )

    # ---------- 净化措施检测 ----------

    # 漏洞类型 → sanitizer_patterns 分类映射
    _VULN_TO_SANITIZER_KEY = {
        "SQL_INJECTION": "sql", "NOSQL_INJECTION": "sql",
        "XSS": "xss",
        "COMMAND_INJECTION": "command", "CODE_INJECTION": "command",
        "PATH_TRAVERSAL": "path",
        "SSRF": "ssrf",
        "XXE": "xxe",
        "DESERIALIZATION": "deserialization",
        "SSTI": "ssti",
        "OPEN_REDIRECT": "redirect",
    }

    def _check_sanitizers(self, finding: Dict[str, Any], lines: List[str]) -> Optional[Dict[str, Any]]:
        """检测代码中是否存在净化/防护措施。

        增强版：使用 SANITIZER_PATTERNS 中按分类组织的丰富模式，
        并根据置信度加权判断是否应降低风险。
        """
        line = finding.get("line", 0)
        if line < 1:
            return None

        # 检查漏洞行前后 10 行
        start = max(0, line - 11)
        end = min(len(lines), line + 10)
        context = "\n".join(lines[start:end])

        vuln_type = finding.get("vulnType", finding.get("type", ""))
        detected = []
        max_confidence = 0.0

        # 1. 精确匹配：漏洞类型 → sanitizer 分类
        sanitizer_key = self._VULN_TO_SANITIZER_KEY.get(vuln_type.upper(), "")
        if sanitizer_key:
            patterns_list = self._sanitizer_patterns.get(sanitizer_key, [])
            for pattern_info in patterns_list:
                if not isinstance(pattern_info, dict):
                    continue
                for compiled_pat in pattern_info.get("patterns", []):
                    if compiled_pat.search(context):
                        name = pattern_info.get("name", "")
                        conf = pattern_info.get("confidence", 0.5)
                        if name and name not in [d["name"] for d in detected]:
                            detected.append({"name": name, "confidence": conf})
                            max_confidence = max(max_confidence, conf)
                        break

        # 2. 通用匹配：检查所有分类中的高置信度净化模式
        for cat_key, patterns_list in self._sanitizer_patterns.items():
            if cat_key == sanitizer_key:
                continue  # 已经检查过
            for pattern_info in patterns_list:
                if not isinstance(pattern_info, dict):
                    continue
                conf = pattern_info.get("confidence", 0.5)
                if conf < 0.8:
                    continue  # 只检查高置信度的通用净化模式
                for compiled_pat in pattern_info.get("patterns", []):
                    if compiled_pat.search(context):
                        name = pattern_info.get("name", "")
                        if name and name not in [d["name"] for d in detected]:
                            detected.append({"name": name, "confidence": conf})
                            max_confidence = max(max_confidence, conf)
                        break

        if detected:
            # 根据净化措施置信度建议降低 severity
            suggested_severity = None
            current_severity = finding.get("severity", "").upper()
            if max_confidence >= 0.9 and current_severity in ("CRITICAL", "HIGH"):
                suggested_severity = "MEDIUM" if current_severity == "CRITICAL" else "LOW"
            elif max_confidence >= 0.7 and current_severity == "CRITICAL":
                suggested_severity = "HIGH"

            result = {
                "detected": True,
                "sanitizers": [d["name"] for d in detected],
                "max_confidence": max_confidence,
                "note": f"检测到净化措施: {', '.join(d['name'] for d in detected)}，可能降低风险",
            }
            if suggested_severity:
                result["suggested_severity"] = suggested_severity
            return result

        return None

    # ---------- 三维评分 ----------

    def check_unresolved_risks(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[RiskEntry]:
        """检查未解决风险，使用三维评分体系。"""
        risks = []

        for finding in findings:
            risk = RiskEntry(
                vuln_id=finding.get("vulnId", finding.get("title", "")),
                type=finding.get("vulnType", finding.get("type", "")),
                severity=finding.get("severity", "medium"),
                location=finding.get("location", finding.get("file", "")),
            )

            score = 0

            # 可达性评分 (0-3)
            reachability_score = self._calculate_reachability_score(finding)
            risk.reachability = self._get_reachability_label(reachability_score)
            score += reachability_score * 40 / 3

            # 影响范围评分 (0-3)
            impact_score = self._calculate_impact_score(finding)
            risk.impact = self._get_impact_label(impact_score)
            score += impact_score * 35 / 3

            # 利用复杂度评分 (0-3)
            complexity_score = self._calculate_complexity_score(finding)
            risk.complexity = self._get_complexity_label(complexity_score)
            score += complexity_score * 25 / 3

            # 严重程度加权
            severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
            score += severity_weights.get(finding.get("severity", ""), 0)

            # 净化措施减分
            if finding.get("sanitizer_detected", {}).get("detected"):
                score -= 15
                risk.reasons.append("存在净化措施（风险降低）")

            risk.score = min(max(round(score), 0), 100)

            # 优先级判定
            if risk.score >= 70:
                risk.priority = "high"
                risk.recommendation = "立即进行人工复核"
            elif risk.score >= 40:
                risk.priority = "medium"
                risk.recommendation = "建议在本次审计周期内完成复核"
            else:
                risk.priority = "low"
                risk.recommendation = "可延后处理"

            risks.append(risk)

        return sorted(risks, key=lambda r: r.score, reverse=True)

    def _calculate_reachability_score(self, finding: Dict[str, Any]) -> int:
        """可达性评分 (0-3)：互联网直接可达=3, 内网=2, 需认证=1, 需管理员=0"""
        access_path = str(finding.get("accessPath", finding.get("reachability", "unknown")))
        if "internet" in access_path or "public" in access_path:
            return 3
        if "intranet" in access_path or "internal" in access_path:
            return 2
        if "auth" in access_path or "login" in access_path:
            return 1
        if "admin" in access_path or "privileged" in access_path:
            return 0

        vuln_type = (finding.get("type", finding.get("vulnType", ""))).upper()
        if any(t in vuln_type for t in ["SSRF", "XSS", "OPEN_REDIRECT"]):
            return 3
        if any(t in vuln_type for t in ["AUTH_BYPASS", "IDOR"]):
            return 2
        return 1

    def _calculate_impact_score(self, finding: Dict[str, Any]) -> int:
        """影响范围评分 (0-3)：RCE=3, SQL注入/路径遍历=2, XSS/信息泄露=1"""
        vuln_type = (finding.get("type", finding.get("vulnType", ""))).upper()
        if any(t in vuln_type for t in ["COMMAND_INJECTION", "CODE_INJECTION", "DESERIALIZATION"]):
            return 3
        if any(t in vuln_type for t in ["SQL_INJECTION", "PATH_TRAVERSAL"]):
            return 2
        if any(t in vuln_type for t in ["XSS", "INFO_LEAK", "HARD_CODE"]):
            return 1
        return 0

    def _calculate_complexity_score(self, finding: Dict[str, Any]) -> int:
        """利用复杂度评分 (0-3)：单次请求=3, 需特定条件=2, 多步骤=1"""
        vuln_type = (finding.get("type", finding.get("vulnType", ""))).upper()
        if any(t in vuln_type for t in ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"]):
            return 3
        if any(t in vuln_type for t in ["XSS", "OPEN_REDIRECT"]):
            return 2
        if any(t in vuln_type for t in ["CSRF", "IDOR"]):
            return 1
        return 0

    def _get_reachability_label(self, score: int) -> str:
        return ["admin_required", "auth_required", "intranet", "internet"][score] if 0 <= score <= 3 else "unknown"

    def _get_impact_label(self, score: int) -> str:
        return ["none", "limited_leak", "data_breach", "system_compromise"][score] if 0 <= score <= 3 else "unknown"

    def _get_complexity_label(self, score: int) -> str:
        return ["complex", "multi_step", "conditional", "single_request"][score] if 0 <= score <= 3 else "unknown"

    # ---------- 辅助方法 ----------

    @staticmethod
    def _extract_file_path(finding: Dict[str, Any], project_root: str) -> str:
        """从发现中提取完整文件路径。"""
        file = finding.get("file", "")
        if file:
            return os.path.join(project_root, file)

        location = finding.get("location", "")
        if location:
            parts = location.split(":")
            if parts:
                return os.path.join(project_root, parts[0])

        return ""

    # ---------- Guard Pattern 检测（上下文感知假阳性过滤）----------

    # 对照 gbt-codeagent 的 contextAwareFilter.js GUARD_WINDOW_LINES=5
    _GUARD_WINDOW_LINES = 5

    _GUARD_PATTERNS: Dict[str, List[re.Pattern]] = {
        "COMMAND_INJECTION": [
            re.compile(r'shlex\.quote|escapeshellarg|escapeshellcmd'),
            re.compile(r'ProcessBuilder\s*\([^)]*List|\.command\s*\(\s*"[^"]*"\s*\)'),
        ],
        "SQL_INJECTION": [
            re.compile(r'PreparedStatement|prepareStatement'),
            re.compile(r'setParameter|setString|setInt|setLong'),
            re.compile(r'NamedParameterJdbcTemplate|JdbcTemplate\s*\(\s*dataSource'),
            re.compile(r'createQuery\s*\([^)]*\.class'),
        ],
        "CODE_INJECTION": [
            re.compile(r'\.replace\s*\(.*pattern', re.IGNORECASE),
            re.compile(r'\.sanitize|\.escape|htmlspecialchars|strip_tags'),
            re.compile(r'JSON\.parse\s*\('),
        ],
        "XSS": [
            re.compile(r'\.textContent\s*=|\.innerText\s*='),
            re.compile(r'\.replace\s*\(.*<[^>]*>'),
            re.compile(r'escapeHtml|sanitizeHtml|DOMPurify|xss-filters'),
            re.compile(r'Content-Security-Policy'),
        ],
        "PATH_TRAVERSAL": [
            re.compile(r'\.normalize\s*\(|\.resolve\s*\('),
            re.compile(r'path\.join\s*\(|os\.path\.join\s*\('),
            re.compile(r'AccessController\.checkPermission|SecurityManager'),
            re.compile(r'FilenameUtils\.getName|Paths\.get'),
        ],
        "DESERIALIZATION": [
            re.compile(r'ValidatingObjectInputStream|LookAheadObjectInputStream'),
            re.compile(r'resolveClass\s*\('),
            re.compile(r'setAcceptClasses|setRejectClasses|setAllowedTypes'),
            re.compile(r'ObjectInputFilter|serialFilter|jdk\.serialFilter'),
        ],
        "SSRF": [
            re.compile(r'ALLOWED_HOSTS|ALLOWED_DOMAINS|whitelist|blocklist', re.IGNORECASE),
            re.compile(r'\.startsWith\s*\(\s*["\']/[^"\']+["\']|\.includes\s*\(\s*["\']/[^"\']+'),
            re.compile(r'isSafeUrl|validateUrl|checkHost|isInternal'),
            re.compile(r'InetAddress\.getByName|isLoopbackAddress|isSiteLocalAddress'),
        ],
        "HARDCODED_CREDENTIALS": [
            re.compile(r'process\.env\.|os\.environ|System\.getenv|getenv\s*\('),
            re.compile(r'config\[|config\.get\s*\(|getConfig\s*\('),
            re.compile(r'keyVault|secretManager|vault|credentialsFromFile', re.IGNORECASE),
            re.compile(r'@Value\s*\(\s*"\$\{'),
        ],
        "XXE": [
            re.compile(r'setFeature\s*\(.*disallow-doctype|setFeature\s*\(.*external-general-entities'),
            re.compile(r'setFeature\s*\(.*external-parameter-entities|setFeature\s*\(.*load-external-dtd'),
            re.compile(r'XMLConstants\.FEATURE_SECURE_PROCESSING'),
            re.compile(r'setExpandEntityReferences\s*\(\s*false'),
        ],
        "CORS_MISCONFIGURATION": [
            re.compile(r'ALLOWED_ORIGINS|allowedOrigins|CORS_ORIGIN_WHITELIST'),
            re.compile(r'originWhitelist|corsWhitelist|corsAllowedOrigins'),
            re.compile(r'@CrossOrigin\s*\(\s*origins\s*=\s*"[^"]+"'),
            re.compile(r'corsConfigurationSource\s*\('),
        ],
        "SESSION_FIXATION": [
            re.compile(r'session\.invalidate\s*\('),
            re.compile(r'request\.changeSessionId\s*\('),
            re.compile(r'session_regenerate_id'),
        ],
        "RACE_CONDITION": [
            re.compile(r'@Version|@Lock\s*\('),
            re.compile(r'ReentrantLock|synchronized\s*\('),
            re.compile(r'AtomicInteger|AtomicBoolean|AtomicReference'),
            re.compile(r'UPDATE\s+.*WHERE\s+.*version'),
        ],
        "WEAK_CRYPTO": [
            re.compile(r'AES/GCM|AES/CBC/PKCS5Padding'),
            re.compile(r'SecureRandom'),
            re.compile(r'SHA-256|SHA-512|SHA3'),
            re.compile(r'secrets\.token|secrets\.choice'),
        ],
    }

    # 字符串字面量参数模式（如 func("literal_string")）
    _STRING_LITERAL_PATTERN = re.compile(r'^["\'][^"\'{}]*["\']\s*$')
    _METHOD_CALL_PATTERN = re.compile(r'^\s*\w+\s*\(\s*["\'][^"\']*["\']\s*\)\s*$')

    @classmethod
    def _extract_guard_window(cls, lines: List[str], line_idx: int) -> str:
        """提取发现行上下 N 行的 Guard Window。"""
        start = max(0, line_idx - cls._GUARD_WINDOW_LINES)
        end = min(len(lines), line_idx + cls._GUARD_WINDOW_LINES + 1)
        return "\n".join(lines[start:end])

    @classmethod
    def _has_guard_pattern(cls, window_text: str, vuln_type: str) -> bool:
        """检查 Guard Window 内是否包含安全防护模式。"""
        patterns = cls._GUARD_PATTERNS.get(vuln_type, [])
        if not patterns:
            return False
        return any(p.search(window_text) for p in patterns)

    @classmethod
    def _is_string_literal_arg(cls, line_content: str) -> bool:
        """检查该行是否为字符串字面量参数（大概率是测试/配置，非用户输入）。"""
        trimmed = line_content.strip()
        return bool(cls._STRING_LITERAL_PATTERN.search(trimmed)
                    or cls._METHOD_CALL_PATTERN.search(trimmed))

    @classmethod
    def evaluate_guard_context(
        cls,
        lines: List[str],
        line_idx: int,
        vuln_type: str,
    ) -> Dict[str, Any]:
        """评估发现行的 Guard Context，返回置信度调整建议。

        对应 gbt-codeagent 的 evaluateGuardContext：
        - 字符串字面量参数 + 无防护 → confidence 降至 0.2
        - 有防护模式 → confidence 降至 0.3
        - 两者都有 → confidence 降至 0.1
        """
        window_text = cls._extract_guard_window(lines, line_idx)
        line_content = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""

        has_string_arg = cls._is_string_literal_arg(line_content)
        has_guard = cls._has_guard_pattern(window_text, vuln_type)
        notes = []
        new_confidence = None

        if has_string_arg:
            notes.append("argument_appears_to_be_string_literal")
        if has_guard:
            notes.append("security_guard_pattern_detected")

        if has_string_arg and has_guard:
            new_confidence = 0.1
            notes.append("doubly_mitigated")
        elif has_string_arg and not has_guard:
            new_confidence = 0.2
            notes.append("probably_false_positive_string_arg")
        elif has_guard and not has_string_arg:
            new_confidence = 0.3
            notes.append("mitigated_by_guard")

        return {
            "has_string_literal_arg": has_string_arg,
            "has_guard_pattern": has_guard,
            "adjusted_confidence": new_confidence,
            "notes": notes,
        }
