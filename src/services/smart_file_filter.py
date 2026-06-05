# -*- coding: utf-8 -*-
"""智能文件过滤 —— 整合自 gbt-codeagent。

根据文件扩展名、路径模式、风险等级智能判断哪些文件需要审计。
支持分层风险评估（T1/T2/T3）和缓存。
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

LOW_RISK_EXTENSIONS: Set[str] = {
    ".md", ".txt", ".json", ".yaml", ".yml", ".xml",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".css", ".scss", ".less",
    ".lock", ".gitignore", ".dockerignore",
    ".md5", ".sha256",
    ".log", ".tmp", ".bak",
}

HIGH_RISK_EXTENSIONS: Set[str] = {
    ".java", ".py", ".js", ".ts", ".tsx", ".jsx",
    ".php", ".go", ".rs", ".rb",
    ".cpp", ".c", ".cxx", ".h", ".hpp",
    ".cs", ".vb", ".asp", ".aspx",
    ".sql", ".pl", ".pm", ".tpl",
}

HIGH_RISK_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"controller", r"service", r"handler", r"api",
        r"auth", r"security", r"login", r"admin",
        r"payment", r"encrypt", r"decrypt", r"config",
        r"secret", r"token", r"session", r"jdbc",
        r"orm", r"dto", r"entity", r"model",
    ]
]

LOW_RISK_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"test", r"spec", r"mock", r"fixture",
        r"sample", r"example", r"demo", r"doc",
        r"docs", r"readme", r"changelog", r"license",
    ]
]

# 分层模式
TIER_PATTERNS: Dict[str, List[re.Pattern]] = {
    "T1": [re.compile(p, re.IGNORECASE) for p in [
        r"controller", r"filter", r"interceptor", r"gateway",
        r"securityconfig", r"webconfig", r"route", r"router",
        r"DispatchServlet", r"DispatchFilter", r"MvcConfig",
        r"AuthFilter", r"CorsFilter", r"RateLimitFilter",
    ]],
    "T2": [re.compile(p, re.IGNORECASE) for p in [
        r"service", r"dao", r"mapper", r"repository",
        r"util", r"helper", r"manager", r"handler",
        r"config", r"properties", r"application",
        r"business", r"core", r"common",
    ]],
    "T3": [re.compile(p, re.IGNORECASE) for p in [
        r"entity", r"dto", r"vo", r"pojo", r"model",
        r"domain", r"bean", r"object",
        r"request", r"response", r"param",
    ]],
}

TIER_WEIGHTS: Dict[str, float] = {"T1": 1.0, "T2": 0.5, "T3": 0.1}


def _matches_any(text: str, patterns: List[re.Pattern]) -> bool:
    return any(p.search(text) for p in patterns)


def _get_tier(name: str) -> str:
    for tier, patterns in TIER_PATTERNS.items():
        if _matches_any(name, patterns):
            return tier
    return ""


@dataclass
class FileEvaluation:
    """文件评估结果。"""
    should_audit: bool = True
    reason: str = ""
    confidence: float = 0.5
    risk_score: float = 0.5
    tier: str = ""


@dataclass
class FilterResult:
    """过滤结果。"""
    to_audit: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


class SmartFileFilter:
    """智能文件过滤器。"""

    # EALOC 权重：不同分层的等效审计行数系数
    TIER_EALOC_WEIGHT: Dict[str, float] = {"T1": 2.0, "T2": 1.0, "T3": 0.3}

    def __init__(
        self,
        cache_ttl: float = 300.0,
        max_cache_size: int = 5000,
        project_path: str = "",
    ) -> None:
        self._cache: OrderedDict = OrderedDict()
        self._cache_ttl = cache_ttl
        self._max_cache_size = max_cache_size
        self._project_path = project_path

    def should_audit_file(
        self,
        file_path: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> FileEvaluation:
        opts = options or {}

        cache_key = file_path
        cached = self._cache.get(cache_key)
        if cached and time.time() < cached["expires"]:
            return cached["result"]

        result = self._evaluate_file(file_path, opts)
        self._add_to_cache(cache_key, {"result": result, "expires": time.time() + self._cache_ttl})
        return result

    def _add_to_cache(self, key: str, entry: Dict[str, Any]) -> None:
        if len(self._cache) >= self._max_cache_size:
            self._cache.popitem(last=False)
        self._cache[key] = entry

    def _evaluate_file(self, file_path: str, options: Dict[str, Any]) -> FileEvaluation:
        basename = os.path.basename(file_path).lower()
        ext = os.path.splitext(file_path)[1].lower()
        dirname = os.path.dirname(file_path).lower()

        # 低风险扩展名
        if ext in LOW_RISK_EXTENSIONS:
            return FileEvaluation(should_audit=False, reason="low_risk_extension", confidence=0.9)

        # 测试文件
        if options.get("skip_tests") and _matches_any(basename, LOW_RISK_PATTERNS):
            return FileEvaluation(should_audit=False, reason="test_file", confidence=0.85)

        # 测试目录
        if options.get("skip_tests") and any(
            seg in dirname for seg in ("/test/", "/tests/", "/spec/", "\\test\\", "\\tests\\", "\\spec\\")
        ):
            return FileEvaluation(should_audit=False, reason="test_directory", confidence=0.9)

        # 第三方代码
        if any(seg in dirname for seg in ("/node_modules/", "/vendor/", "/dist/", "/build/",
                                           "\\node_modules\\", "\\vendor\\", "\\dist\\", "\\build\\")):
            return FileEvaluation(should_audit=False, reason="third_party_code", confidence=0.95)

        # 文档目录
        if any(seg in dirname for seg in ("/docs/", "/documentation/", "\\docs\\", "\\documentation\\")):
            return FileEvaluation(should_audit=False, reason="documentation", confidence=0.95)

        # 计算风险分数
        score = 0.5
        if ext in HIGH_RISK_EXTENSIONS:
            score += 0.3
        if _matches_any(basename, HIGH_RISK_PATTERNS):
            score += 0.2
        if _matches_any(dirname, HIGH_RISK_PATTERNS):
            score += 0.1
        score = min(score, 0.95)

        # 分层
        tier = _get_tier(basename)
        if tier:
            score = max(score, TIER_WEIGHTS.get(tier, 0.5))

        min_score = options.get("min_score", 0.6)
        return FileEvaluation(
            should_audit=score >= min_score,
            reason="high_risk" if score >= 0.8 else ("medium_risk" if score >= 0.6 else "low_risk"),
            confidence=score,
            risk_score=score,
            tier=tier,
        )

    def filter_files(
        self,
        files: List[Any],
        options: Optional[Dict[str, Any]] = None,
    ) -> FilterResult:
        opts = options or {}
        result = FilterResult()
        total_risk = 0.0

        for file_entry in files:
            if isinstance(file_entry, str):
                file_path = file_entry
                entry: Dict[str, Any] = {"path": file_path}
            else:
                file_path = file_entry.get("path", file_entry.get("fullPath", ""))
                entry = dict(file_entry) if isinstance(file_entry, dict) else {"path": str(file_entry)}

            evaluation = self.should_audit_file(file_path, opts)

            if evaluation.should_audit:
                entry["risk_score"] = evaluation.risk_score
                entry["tier"] = evaluation.tier
                result.to_audit.append(entry)
                total_risk += evaluation.risk_score
            else:
                entry["skip_reason"] = evaluation.reason
                result.skipped.append(entry)

        # 按风险分数降序
        result.to_audit.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        audit_count = len(result.to_audit)
        result.stats = {
            "total": len(files),
            "to_audit": audit_count,
            "skipped": len(result.skipped),
            "avg_risk_score": round(total_risk / audit_count, 2) if audit_count > 0 else 0,
        }

        return result

    def get_high_risk_files(self, file_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """获取项目中的高风险文件列表（供 orchestrator 调用）。

        Args:
            file_list: 可选的相对路径文件列表，为空时自动 os.walk

        Returns:
            高风险文件列表，每项包含 path, risk_score, tier, ealoc
        """
        if not self._project_path or not os.path.isdir(self._project_path):
            return []

        # 收集文件（复用外部传入的文件列表，避免重复 os.walk）
        if file_list is not None:
            all_files = [os.path.join(self._project_path, rel) for rel in file_list]
        else:
            skip_dirs = {
                "node_modules", ".git", "__pycache__", ".idea", ".vscode",
                "target", "build", "dist", ".next", ".nuxt", "vendor",
                ".gradle", ".mvn", "venv", ".env", "env",
            }
            all_files = []
            for root, dirs, filenames in os.walk(self._project_path):
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
                for fname in filenames:
                    abs_path = os.path.join(root, fname)
                    all_files.append(abs_path)

        # 过滤
        filter_result = self.filter_files(all_files, options={"skip_tests": True})

        # 计算 EALOC
        for entry in filter_result.to_audit:
            entry["ealoc"] = self._compute_ealoc(entry.get("path", ""))

        # 统计 EALOC
        total_ealoc = sum(e.get("ealoc", 0) for e in filter_result.to_audit)
        filter_result.stats["total_ealoc"] = total_ealoc

        # 建议批次大小：每批约 500 EALOC
        if total_ealoc > 0:
            suggested_batch = max(3, min(15, int(500 / (total_ealoc / len(filter_result.to_audit)))))
            filter_result.stats["suggested_batch_size"] = suggested_batch

        return filter_result.to_audit

    def _compute_ealoc(self, file_path: str) -> int:
        """计算文件的等效审计行数（EALOC）。

        EALOC = 实际行数 × 分层权重 × 风险系数
        T1 文件（Controller/Filter 等）权重 2.0，T2 权重 1.0，T3 权重 0.3
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                line_count = sum(1 for _ in f)
        except (OSError, IOError):
            return 0

        basename = os.path.basename(file_path)
        tier = _get_tier(basename)
        tier_weight = self.TIER_EALOC_WEIGHT.get(tier, 1.0)

        # 评估风险系数
        evaluation = self.should_audit_file(file_path)
        risk_factor = evaluation.risk_score if evaluation.risk_score > 0 else 0.5

        ealoc = int(line_count * tier_weight * risk_factor)
        return ealoc
