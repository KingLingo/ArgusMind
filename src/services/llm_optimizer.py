# -*- coding: utf-8 -*-
"""LLM 审计优化器 —— 整合自 gbt-codeagent/services/llmOptimizer.js。

核心能力：
1. 结果缓存 —— 基于文件 hash 避免重复审计
2. 增量审计 —— 只审计变更文件
3. Token 预算控制 —— 智能上下文管理
4. 误报检测 —— 多维度验证（测试文件/框架代码/安全模式/注释行/仅导入/断言）
5. 发现验证 —— 检查 location/evidence/remediation/confidence/severity 完整性
6. 发现增强 —— 自动补充 CVSS/置信度/GB/T 映射
7. 去重 —— 基于文件+类型+行号桶的 MD5 去重
8. 排序 —— 严重等级 → 置信度 → CVSS
9. 文件优先级排序 —— 基于文件名/路径/关联发现的启发式评分
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------- 误报检测模式 ----------

_FALSE_POSITIVE_PATTERNS = {
    "test": [
        # 仅匹配明确的测试目录/文件名，避免误伤 TestController、latest 等业务代码
        re.compile(r"[\\/]test[\\/]", re.I),
        re.compile(r"[\\/]tests[\\/]", re.I),
        re.compile(r"[\\/]__tests__[\\/]", re.I),
        re.compile(r"[\\/]spec[\\/]", re.I),
        re.compile(r"[\\/]mock[\\/]", re.I),
        re.compile(r"[\\/]fixture[s]?[\\/]", re.I),
        re.compile(r"[\\/]example[s]?[\\/]", re.I),
        re.compile(r"[\\/]demo[\\/]", re.I),
        re.compile(r"[\\/]stub[s]?[\\/]", re.I),
        re.compile(r"[\\/]placeholder[\\/]", re.I),
        re.compile(r"[\\/]dummy[\\/]", re.I),
        re.compile(r"\.test\.", re.I),
        re.compile(r"\.spec\.", re.I),
        re.compile(r"_test\.", re.I),
        re.compile(r"_spec\.", re.I),
    ],
    "framework": [
        re.compile(r"[\\/]node_modules[\\/]", re.I),
        re.compile(r"[\\/]vendor[\\/]", re.I),
        re.compile(r"[\\/]\.git[\\/]", re.I),
        re.compile(r"[\\/]dist[\\/]", re.I),
        re.compile(r"[\\/]target[\\/]", re.I),
        re.compile(r"[\\/]coverage[\\/]", re.I),
        re.compile(r"[\\/]__pycache__[\\/]", re.I),
        # build 仅匹配独立目录，不匹配 builder/BuildConfig 等
        re.compile(r"[\\/]build[\\/]", re.I),
    ],
    "safe": [
        # 安全模式仅匹配明确的纯调试/日志占位行，避免误伤真实漏洞证据行
        re.compile(r"^\s*//\s*(skip|todo|FIXME)\s*$", re.I),
        re.compile(r"^\s*#\s*(skip|todo|FIXME)\s*$", re.I),
    ],
}

# 置信度阈值（按严重等级）
_CONFIDENCE_THRESHOLDS: Dict[str, float] = {
    "critical": 0.7,
    "high": 0.75,
    "medium": 0.8,
    "low": 0.85,
}

# CWE → GB/T 映射
_CWE_GBT_MAP: Dict[str, str] = {
    "CWE-78": "GB/T34944-6.1.1.6 命令注入",
    "CWE-79": "GB/T34944-6.1.1.2 XSS",
    "CWE-89": "GB/T34944-6.1.1.1 SQL注入",
    "CWE-287": "GB/T34944-6.3.1.2 身份认证绕过",
    "CWE-502": "GB/T34944-6.1.1.7 不安全反序列化",
    "CWE-22": "GB/T34944-6.1.1.4 路径遍历",
    "CWE-94": "GB/T34944-6.1.1.3 代码注入",
    "CWE-918": "GB/T39412-6.4.1 SSRF",
    "CWE-798": "GB/T39412-6.1.1.10 硬编码敏感信息",
    "CWE-611": "GB/T34944-6.1.1.5 XXE",
    "CWE-352": "GB/T34944-6.3.1.3 CSRF",
    "CWE-601": "GB/T34944-6.1.1.8 开放重定向",
    "CWE-327": "GB/T34944-6.2.1.1 弱加密",
    "CWE-330": "GB/T34944-6.2.1.2 不安全随机数",
}

# 严重等级 → CVSS 映射
_SEVERITY_CVSS: Dict[str, float] = {
    "critical": 9.5, "严重": 9.5,
    "high": 7.5, "高危": 7.5,
    "medium": 5.0, "中危": 5.0,
    "low": 2.5, "低危": 2.5,
    "info": 0.1,
}

# 严重等级排序权重
_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0, "严重": 0, "c": 0,
    "high": 1, "高危": 1, "h": 1,
    "medium": 2, "中危": 2, "m": 2,
    "low": 3, "低危": 3, "l": 3,
    "info": 4,
}


# ---------- 数据类 ----------

@dataclass
class FalsePositiveResult:
    """误报检测结果。"""
    is_fp: bool = False
    reason: str = ""
    confidence: float = 1.0


@dataclass
class FindingValidationResult:
    """发现验证结果。"""
    is_valid: bool = True
    is_actionable: bool = True
    issues: List[str] = field(default_factory=list)


@dataclass
class TokenBudget:
    """Token 预算。"""
    max_tokens: int = 128000
    used_tokens: int = 0
    warning_threshold: float = 0.8

    @property
    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    @property
    def safe_budget(self) -> int:
        return int(self.remaining * 0.9)

    @property
    def usage_ratio(self) -> float:
        return self.used_tokens / self.max_tokens if self.max_tokens > 0 else 0.0


@dataclass
class CacheEntry:
    """缓存条目。"""
    project_hash: str = ""
    file_hashes: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    cached_at: str = ""
    version: str = "1.0"


# ---------- LLMOptimizer ----------

class LLMOptimizer:
    """LLM 审计优化器。

    在 Orchestrator 中被调用：
    - 快速扫描后：对发现进行误报检测、去重、排序
    - LLM 审计后：对 LLM 输出进行验证、增强、去重
    - 增量审计：基于文件 hash 跳过未变更文件
    """

    def __init__(self, cache_dir: str = "", max_tokens: int = 128000) -> None:
        self._cache_dir = cache_dir or os.path.join(os.getcwd(), "data", "llm_cache")
        self._cache: Dict[str, CacheEntry] = {}
        self._audit_history: Dict[str, Dict[str, Any]] = {}
        self._token_budget = TokenBudget(max_tokens=max_tokens)
        # 启动时加载持久化缓存
        self._load_cache_from_disk()

    # ---------- 文件 Hash ----------

    @staticmethod
    def compute_file_hash(content: str) -> str:
        """计算文件内容 SHA256 前 16 位。"""
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]

    @staticmethod
    def compute_project_hash(files: List[Dict[str, Any]]) -> str:
        """计算项目级 hash（基于所有文件路径+内容hash）。"""
        parts = []
        for f in sorted(files, key=lambda x: x.get("relativePath", x.get("file", ""))):
            path = f.get("relativePath", f.get("file", ""))
            content = f.get("content", "")
            h = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]
            parts.append(f"{path}:{h}")
        combined = "|".join(parts)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32]

    # ---------- 缓存 ----------

    def get_cached_results(
        self,
        project_hash: str,
        files: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """获取缓存结果，返回缓存命中信息。"""
        cached = self._cache.get(project_hash)
        if not cached:
            return None

        cached_file_hashes = set(cached.file_hashes)
        current = [
            {
                "path": f.get("relativePath", f.get("file", "")),
                "hash": self.compute_file_hash(f.get("content", "")),
            }
            for f in files
        ]

        unchanged = [c for c in current if f"{c['path']}:{c['hash']}" in cached_file_hashes]
        changed = [c for c in current if f"{c['path']}:{c['hash']}" not in cached_file_hashes]

        return {
            "cached_findings": cached.findings,
            "unchanged_count": len(unchanged),
            "changed_files": [c["path"] for c in changed],
            "is_cache_hit": len(changed) == 0,
        }

    def cache_results(
        self,
        project_hash: str,
        files: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> None:
        """缓存审计结果。"""
        file_hashes = [
            f"{f.get('relativePath', f.get('file', ''))}:{self.compute_file_hash(f.get('content', ''))}"
            for f in files
        ]
        self._cache[project_hash] = CacheEntry(
            project_hash=project_hash,
            file_hashes=file_hashes,
            findings=findings,
            cached_at=datetime.now().isoformat(),
        )
        # 持久化到磁盘
        self._save_cache_to_disk()

    @staticmethod
    def filter_unchanged_files(
        files: List[Dict[str, Any]],
        changed_files: List[str],
    ) -> List[Dict[str, Any]]:
        """过滤出变更文件。"""
        if not changed_files:
            return files
        changed_set = set(changed_files)
        return [
            f for f in files
            if f.get("relativePath", f.get("file", "")) in changed_set
        ]

    # ---------- 缓存持久化 ----------

    def _cache_file_path(self) -> str:
        """缓存文件路径。"""
        return os.path.join(self._cache_dir, "audit_cache.json")

    def _load_cache_from_disk(self) -> None:
        """从磁盘加载缓存，支持跨会话增量审计。"""
        cache_path = self._cache_file_path()
        if not os.path.isfile(cache_path):
            return
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for project_hash, entry_data in data.get("cache", {}).items():
                self._cache[project_hash] = CacheEntry(
                    project_hash=project_hash,
                    file_hashes=entry_data.get("file_hashes", []),
                    findings=entry_data.get("findings", []),
                    cached_at=entry_data.get("cached_at", ""),
                )
            self._audit_history = data.get("audit_history", {})
            logger.info(f"从磁盘加载缓存: {len(self._cache)} 条记录")
        except Exception as e:
            logger.warning(f"加载缓存失败: {e}")

    def _save_cache_to_disk(self) -> None:
        """将缓存持久化到磁盘。"""
        try:
            os.makedirs(self._cache_dir, exist_ok=True)
            data = {
                "cache": {
                    ph: {
                        "project_hash": entry.project_hash,
                        "file_hashes": entry.file_hashes,
                        "findings": entry.findings,
                        "cached_at": entry.cached_at,
                    }
                    for ph, entry in self._cache.items()
                },
                "audit_history": self._audit_history,
            }
            with open(self._cache_file_path(), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"缓存已持久化: {len(self._cache)} 条记录")
        except Exception as e:
            logger.warning(f"持久化缓存失败: {e}")

    # ---------- Token 预算 ----------

    def set_model_max_tokens(self, max_tokens: int) -> None:
        self._token_budget.max_tokens = max_tokens or 128000

    def calculate_token_budget(
        self,
        files: List[Dict[str, Any]],
        priority_files: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """计算 token 预算。"""
        total_chars = sum(len(f.get("content", "")) for f in files)
        estimated_tokens = total_chars // 4

        priority_set = set(priority_files or [])
        priority_chars = sum(
            len(f.get("content", ""))
            for f in files
            if f.get("relativePath", f.get("file", "")) in priority_set
        )
        priority_tokens = priority_chars // 4

        remaining = self._token_budget.remaining
        safe = int(remaining * 0.9)

        return {
            "total_estimated": estimated_tokens,
            "priority_tokens": priority_tokens,
            "remaining_budget": remaining,
            "safe_budget": safe,
            "needs_compression": estimated_tokens > safe,
            "compression_ratio": safe / max(estimated_tokens, 1),
        }

    # ---------- 文件优先级排序 ----------

    @staticmethod
    def prioritize_files(
        files: List[Dict[str, Any]],
        heuristic_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """按安全风险启发式排序文件。"""
        heuristic_findings = heuristic_findings or []

        def _score(file: Dict[str, Any]) -> int:
            s = 0
            name = file.get("relativePath", file.get("file", "")).lower()
            if re.search(r"auth|login|user|permission|role|admin|security", name):
                s += 10
            if re.search(r"api|controller|handler|service", name):
                s += 8
            if re.search(r"config|settings|env", name):
                s += 6
            if re.search(r"\.(java|py|js|ts|go|php)$", name):
                s += 5
            if re.search(r"test|spec|mock", name):
                s -= 20
            if re.search(r"node_modules|vendor", name):
                s -= 30

            # 关联发现加分
            related = [
                hf for hf in heuristic_findings
                if hf.get("location", hf.get("file", "")) and
                (hf.get("location", "").startswith(name) or hf.get("file", "") == name)
            ]
            s += len(related) * 3

            # 文件大小适中加分
            content_len = len(file.get("content", ""))
            if 1000 < content_len < 50000:
                s += 3

            return s

        return sorted(files, key=_score, reverse=True)

    # ---------- 误报检测 ----------

    def is_false_positive(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> FalsePositiveResult:
        """多维度误报检测。"""
        context = context or {}
        file_path = context.get("filePath", finding.get("location", finding.get("file", "")))
        code = context.get("code", finding.get("codeSnippet", finding.get("code_snippet", "")))

        # 测试文件
        if any(p.search(file_path) for p in _FALSE_POSITIVE_PATTERNS["test"]):
            return FalsePositiveResult(is_fp=True, reason="test_file", confidence=0.9)

        # 框架/第三方代码
        if any(p.search(file_path) for p in _FALSE_POSITIVE_PATTERNS["framework"]):
            return FalsePositiveResult(is_fp=True, reason="framework_code", confidence=0.95)

        # 安全模式（日志/跳过/TODO）
        if any(p.search(code) for p in _FALSE_POSITIVE_PATTERNS["safe"]):
            return FalsePositiveResult(is_fp=True, reason="safe_pattern", confidence=0.8)

        # 注释行
        if self._is_comment_line(code):
            return FalsePositiveResult(is_fp=True, reason="comment_line", confidence=0.95)

        # 仅导入
        if self._is_import_only(finding, code):
            return FalsePositiveResult(is_fp=True, reason="import_only", confidence=0.85)

        # 测试断言
        if self._is_test_assertion(code):
            return FalsePositiveResult(is_fp=True, reason="test_assertion", confidence=0.9)

        return FalsePositiveResult(is_fp=False, confidence=1.0)

    @staticmethod
    def _is_comment_line(code: str) -> bool:
        trimmed = (code or "").strip()
        return bool(re.match(r"^(//|/\*|\*|#|<!--)", trimmed))

    @staticmethod
    def _is_import_only(finding: Dict[str, Any], code: str) -> bool:
        if not finding.get("vulnType") and not finding.get("vuln_type"):
            return False
        import_patterns = [
            re.compile(r"import\s+.*from\s+['\"]"),
            re.compile(r"require\s*\("),
            re.compile(r"using\s+.*;"),
            re.compile(r"include\s*<"),
        ]
        return any(p.search(code) for p in import_patterns) and "(" not in code

    @staticmethod
    def _is_test_assertion(code: str) -> bool:
        return bool(re.search(r"\b(assert|expect|should\.be|should\.eq|jest\.fn|sinon)\b", code))

    # ---------- 发现验证 ----------

    def validate_finding(self, finding: Dict[str, Any]) -> FindingValidationResult:
        """验证单个发现的完整性和有效性。

        对于快速扫描（规则引擎）产出的 finding，remediation 和 severity 格式
        通常不完整，因此仅将缺失这些字段标记为非关键问题，不直接丢弃。
        """
        issues: List[str] = []

        location = finding.get("location", finding.get("file", ""))
        if not location:
            issues.append("missing_location")
        else:
            parts = str(location).split(":")
            if not parts[0]:
                issues.append("invalid_location_format")
            # 行号缺失不标记为 invalid，快速扫描可能不提供行号

        evidence = finding.get("evidence", finding.get("description", ""))
        if not evidence or len(str(evidence)) < 8:
            issues.append("evidence_too_short")

        remediation = finding.get("remediation", "")
        if not remediation or len(str(remediation)) < 15:
            issues.append("remediation_too_short")

        confidence = finding.get("confidence", 0)
        if not confidence or confidence < 0.3:
            issues.append("low_confidence")

        severity = str(finding.get("severity", "")).lower()
        valid_severities = {"critical", "high", "medium", "low", "info", "c", "h", "m", "l", "严重", "高危", "中危", "低危"}
        if severity not in valid_severities:
            issues.append("invalid_severity")

        # 仅 missing_location 和 invalid_location_format 为关键问题（直接丢弃）
        # 其他问题为非关键（保留但标记）
        critical_issues = {"missing_location", "invalid_location_format"}
        non_actionable = {"low_confidence", "evidence_too_short", "remediation_too_short", "invalid_severity", "invalid_line_number"}

        return FindingValidationResult(
            is_valid=len(issues) == 0,
            is_actionable=len([i for i in issues if i in critical_issues]) == 0,
            issues=issues,
        )

    # ---------- 发现增强 ----------

    def enhance_finding_with_context(
        self,
        finding: Dict[str, Any],
        project_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """自动补充 CVSS/置信度/GB/T 映射。"""
        project_context = project_context or {}
        enhanced = {**finding}

        # 补充 CVSS
        if not enhanced.get("cvssScore") and not enhanced.get("cvss_score"):
            severity = str(enhanced.get("severity", "")).lower()
            enhanced["cvss_score"] = _SEVERITY_CVSS.get(severity, 5.0)

        # 补充置信度
        if not enhanced.get("confidence"):
            enhanced["confidence"] = self._estimate_confidence(finding)

        # 补充语言
        if project_context.get("language") and not enhanced.get("language"):
            enhanced["language"] = project_context["language"]

        # 补充 GB/T 映射
        if not enhanced.get("gbtMapping") and not enhanced.get("gbt_mapping"):
            cwe = finding.get("cwe", finding.get("cweId", ""))
            if cwe:
                gbt = _CWE_GBT_MAP.get(cwe)
                if gbt:
                    enhanced["gbt_mapping"] = gbt

        return enhanced

    def _estimate_confidence(self, finding: Dict[str, Any]) -> float:
        confidence = 0.6
        evidence = finding.get("evidence", finding.get("description", ""))
        if evidence and len(str(evidence)) > 100:
            confidence += 0.1
        remediation = finding.get("remediation", "")
        if remediation and "具体" in str(remediation):
            confidence += 0.1
        location = finding.get("location", finding.get("file", ""))
        if location and ":" in str(location):
            confidence += 0.1

        fp = self.is_false_positive(finding)
        if fp.is_fp:
            confidence *= 0.3

        return min(1.0, max(0.0, confidence))

    # ---------- 去重 ----------

    def deduplicate_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """基于文件+类型+行号桶去重，保留置信度最高的。"""
        seen: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            key = self._generate_finding_key(finding)
            if key in seen:
                existing = seen[key]
                if finding.get("confidence", 0) > existing.get("confidence", 0):
                    seen[key] = finding
            else:
                seen[key] = finding

        return list(seen.values())

    @staticmethod
    def _generate_finding_key(finding: Dict[str, Any]) -> str:
        raw_file = finding.get("location", finding.get("file", ""))
        file_part = str(raw_file).split(":")[0].strip() if raw_file else ""
        # 取文件名部分
        slash_idx = file_part.rfind("/")
        file_name = file_part[slash_idx + 1:].lower() if slash_idx >= 0 else file_part.lower()

        line = finding.get("line", 0)
        if not line and finding.get("location"):
            parts = str(finding["location"]).split(":")
            if len(parts) >= 2:
                try:
                    line = int(re.match(r"\d+", parts[1].strip()).group())
                except (ValueError, AttributeError):
                    line = 0
        line_bucket = (line // 5) * 5

        vuln_type = finding.get("vulnType", finding.get("vuln_type", finding.get("type", "")))
        parts_str = f"{file_name}|{vuln_type}|{line_bucket}"
        return hashlib.md5(parts_str.encode("utf-8")).hexdigest()

    # ---------- 置信度过滤 ----------

    @staticmethod
    def filter_by_confidence(
        findings: List[Dict[str, Any]],
        threshold: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """过滤低置信度发现。"""
        return [f for f in findings if f.get("confidence", 0) >= threshold]

    # ---------- 排序 ----------

    @staticmethod
    def rank_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按严重等级 → 置信度 → CVSS 排序。"""
        return sorted(
            findings,
            key=lambda f: (
                _SEVERITY_ORDER.get(str(f.get("severity", "")).lower(), 5),
                -(f.get("confidence", 0) or 0),
                -(f.get("cvssScore", f.get("cvss_score", 0)) or 0),
            ),
        )

    # ---------- 完整优化管线 ----------

    def optimize_findings(
        self,
        findings: List[Dict[str, Any]],
        project_root: str = "",
        confidence_threshold: float = 0.5,
    ) -> Dict[str, Any]:
        """完整优化管线：验证 → 误报检测 → 增强 → 去重 → 排序。

        在 Orchestrator 中快速扫描后和 LLM 审计后调用。

        Returns:
            包含 optimized_findings, stats 的字典
        """
        total_in = len(findings)
        fp_count = 0
        invalid_count = 0
        enhanced_count = 0

        # 1. 验证 + 误报检测 + 增强
        processed: List[Dict[str, Any]] = []
        for f in findings:
            # 验证
            validation = self.validate_finding(f)
            if not validation.is_valid and not validation.is_actionable:
                invalid_count += 1
                continue

            # 误报检测
            fp = self.is_false_positive(f, {"filePath": f.get("location", f.get("file", ""))})
            if fp.is_fp:
                fp_count += 1
                continue

            # 增强
            enhanced = self.enhance_finding_with_context(f, {"projectId": project_root})
            enhanced_count += 1
            processed.append(enhanced)

        # 2. 置信度过滤
        confidence_filtered = self.filter_by_confidence(processed, confidence_threshold)

        # 3. 去重
        deduped = self.deduplicate_findings(confidence_filtered)

        # 4. 排序
        ranked = self.rank_findings(deduped)

        return {
            "optimized_findings": ranked,
            "stats": {
                "total_in": total_in,
                "false_positives": fp_count,
                "invalid": invalid_count,
                "enhanced": enhanced_count,
                "after_confidence_filter": len(confidence_filtered),
                "after_dedup": len(deduped),
                "final_count": len(ranked),
            },
        }

    # ---------- 审计历史 ----------

    def record_audit_result(
        self,
        project_id: str,
        findings_count: int,
        success: bool,
    ) -> None:
        """记录审计结果。"""
        self._audit_history[project_id] = {
            "projectId": project_id,
            "findingsCount": findings_count,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        }

    def get_stats(self) -> Dict[str, Any]:
        """获取优化器统计。"""
        total = len(self._audit_history)
        failed = sum(1 for v in self._audit_history.values() if not v.get("success"))
        return {
            "cacheSize": len(self._cache),
            "historySize": total,
            "tokenBudget": {
                "maxTokens": self._token_budget.max_tokens,
                "usedTokens": self._token_budget.used_tokens,
            },
            "falsePositiveRate": failed / total if total > 0 else 0.0,
        }
