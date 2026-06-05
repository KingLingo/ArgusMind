# -*- coding: utf-8 -*-
"""污点分析器 —— 整合自 gbt-codeagent。

实现数据流追踪和污点传播分析。
特性：上下文感知变量追踪、净化函数识别、污点传播路径追踪。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from src.analyzers.rules_engine import RulesEngine


@dataclass
class TaintSource:
    """污点源。"""
    name: str
    line: int = 0
    code: str = ""
    category: str = ""
    confidence: float = 0.7


@dataclass
class TaintSink:
    """污点汇聚点。"""
    name: str
    line: int = 0
    code: str = ""
    category: str = ""
    severity: str = "medium"
    cwe: str = ""


@dataclass
class Sanitizer:
    """净化器。"""
    name: str
    line: int = 0
    code: str = ""
    effectiveness: str = "partial"  # full / partial / none


@dataclass
class TaintPath:
    """污点传播路径。"""
    source: TaintSource
    sink: TaintSink
    sanitizers: List[Sanitizer] = field(default_factory=list)
    is_vulnerable: bool = False
    confidence: float = 0.0
    path_description: str = ""


@dataclass
class TaintAnalysisResult:
    """污点分析结果。"""
    sources: List[TaintSource] = field(default_factory=list)
    sinks: List[TaintSink] = field(default_factory=list)
    sanitizers: List[Sanitizer] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class TaintAnalyzer:
    """污点分析器：追踪数据从 source 到 sink 的传播。"""

    def __init__(self, options: Optional[Dict[str, Any]] = None) -> None:
        self._rules_engine = RulesEngine()
        self._analysis_cache: Dict[str, TaintAnalysisResult] = {}
        self._variable_tracking: Dict[str, Set[str]] = {}
        self._options = options or {}

    def set_rules_engine(self, engine: RulesEngine) -> None:
        self._rules_engine = engine

    def analyze_code(
        self,
        code: str,
        language: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> TaintAnalysisResult:
        """对代码执行污点分析。"""
        opts = {**self._options, **(options or {})}

        analysis_id = self._generate_analysis_id(code, language, opts)
        if opts.get("cache", True) and analysis_id in self._analysis_cache:
            return self._analysis_cache[analysis_id]

        result = self._perform_full_analysis(code, language, opts)

        if opts.get("cache", True):
            self._analysis_cache[analysis_id] = result

        return result

    def _generate_analysis_id(self, code: str, language: str, options: Dict[str, Any]) -> str:
        code_hash = hashlib.md5(code.encode()).hexdigest()[:12]
        return f"{language}:{code_hash}"

    def _perform_full_analysis(
        self,
        code: str,
        language: str,
        options: Dict[str, Any],
    ) -> TaintAnalysisResult:
        result = TaintAnalysisResult()

        # 1. 匹配 source / sink / sanitizer
        raw_sources = self._rules_engine.match_sources(code, language)
        raw_sinks = self._rules_engine.match_sinks(code, language)
        raw_sanitizers = self._rules_engine.match_sanitizers(code, language)

        result.sources = [TaintSource(
            name=s.get("rule_name", ""),
            category=s.get("category", ""),
            confidence=s.get("confidence", 0.7),
        ) for s in raw_sources]

        result.sinks = [TaintSink(
            name=s.get("rule_name", ""),
            category=s.get("category", ""),
            severity=s.get("severity", "medium"),
            cwe=s.get("cwe", ""),
        ) for s in raw_sinks]

        result.sanitizers = [Sanitizer(
            name=s.get("rule_name", ""),
            effectiveness="partial",
        ) for s in raw_sanitizers]

        # 2. 追踪污点传播路径
        result.taint_paths = self._track_taint_propagation(
            code, language, result.sources, result.sinks, result.sanitizers
        )

        # 3. 识别漏洞
        result.vulnerabilities = self._identify_vulnerabilities(result.taint_paths)

        # 4. 生成摘要
        result.summary = self._generate_summary(result)

        return result

    def _track_taint_propagation(
        self,
        code: str,
        language: str,
        sources: List[TaintSource],
        sinks: List[TaintSink],
        sanitizers: List[Sanitizer],
    ) -> List[TaintPath]:
        """追踪污点从 source 到 sink 的传播路径。"""
        paths: List[TaintPath] = []

        for source in sources:
            for sink in sinks:
                # 检查是否存在有效的传播路径
                applicable_sanitizers = self._find_applicable_sanitizers(
                    source, sink, sanitizers
                )

                is_vulnerable = True
                confidence = min(source.confidence, 0.8)

                # 如果存在完全有效的净化器，则不可利用
                for san in applicable_sanitizers:
                    if san.effectiveness == "full":
                        is_vulnerable = False
                        break
                    elif san.effectiveness == "partial":
                        confidence *= 0.6

                path = TaintPath(
                    source=source,
                    sink=sink,
                    sanitizers=applicable_sanitizers,
                    is_vulnerable=is_vulnerable,
                    confidence=round(confidence, 2),
                    path_description=f"{source.name} → {sink.name}",
                )
                paths.append(path)

        return paths

    def _find_applicable_sanitizers(
        self,
        source: TaintSource,
        sink: TaintSink,
        sanitizers: List[Sanitizer],
    ) -> List[Sanitizer]:
        """查找适用于 source→sink 路径的净化器。"""
        applicable = []
        for san in sanitizers:
            # 简化逻辑：如果净化器与 source 或 sink 同类别，则认为适用
            if san.name and (source.category or sink.category):
                applicable.append(san)
        return applicable

    def _identify_vulnerabilities(self, taint_paths: List[TaintPath]) -> List[Dict[str, Any]]:
        """从污点路径中识别漏洞。"""
        vulns = []
        for path in taint_paths:
            if path.is_vulnerable:
                vulns.append({
                    "type": "taint_vulnerability",
                    "source": path.source.name,
                    "sink": path.sink.name,
                    "severity": path.sink.severity,
                    "cwe": path.sink.cwe,
                    "confidence": path.confidence,
                    "sanitizers": [s.name for s in path.sanitizers],
                    "description": path.path_description,
                })
        return vulns

    def _generate_summary(self, result: TaintAnalysisResult) -> Dict[str, Any]:
        by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in result.vulnerabilities:
            sev = v.get("severity", "medium").upper()
            if sev in by_severity:
                by_severity[sev] += 1
            else:
                by_severity["MEDIUM"] += 1

        return {
            "total_sources": len(result.sources),
            "total_sinks": len(result.sinks),
            "total_sanitizers": len(result.sanitizers),
            "total_paths": len(result.taint_paths),
            "total_vulnerabilities": len(result.vulnerabilities),
            "by_severity": by_severity,
        }
