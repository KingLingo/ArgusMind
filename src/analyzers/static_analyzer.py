# -*- coding: utf-8 -*-
"""静态分析器 —— 整合自 gbt-codeagent。

综合模式匹配和污点分析的静态代码分析器。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.analyzers.rules_engine import RulesEngine
from src.analyzers.taint_analyzer import TaintAnalyzer


@dataclass
class StaticAnalysisResult:
    """静态分析结果。"""
    success: bool = True
    language: str = ""
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    analysis_details: Dict[str, Any] = field(default_factory=dict)


class StaticAnalyzer:
    """静态代码分析器：组合模式匹配与污点分析。"""

    def __init__(
        self,
        rules_engine: Optional[RulesEngine] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._rules_engine = rules_engine or RulesEngine()
        self._taint_analyzer = TaintAnalyzer(options)
        self._taint_analyzer.set_rules_engine(self._rules_engine)
        self._options = {
            "enable_pattern_analysis": True,
            "enable_taint_analysis": True,
            **(options or {}),
        }

    def set_rules_engine(self, engine: RulesEngine) -> None:
        self._rules_engine = engine
        self._taint_analyzer.set_rules_engine(engine)

    def analyze(self, code: str, context: Optional[Dict[str, Any]] = None) -> StaticAnalysisResult:
        """对代码执行综合静态分析。"""
        ctx = context or {}
        language = ctx.get("language", "unknown")

        result = StaticAnalysisResult(language=language)

        if self._options.get("enable_pattern_analysis", True):
            try:
                pattern_result = self._run_pattern_analysis(code, language, ctx)
                result.analysis_details["pattern"] = pattern_result
            except Exception as e:
                result.analysis_details["pattern"] = {"error": str(e)}

        if self._options.get("enable_taint_analysis", True):
            try:
                taint_result = self._run_taint_analysis(code, language, ctx)
                result.analysis_details["taint"] = taint_result
            except Exception as e:
                result.analysis_details["taint"] = {"error": str(e)}

        self._merge_results(result)
        return result

    def _run_pattern_analysis(self, code: str, language: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """运行模式匹配分析。"""
        sources = self._rules_engine.match_sources(code, language)
        sinks = self._rules_engine.match_sinks(code, language)
        sanitizers = self._rules_engine.match_sanitizers(code, language)

        vulnerabilities = []
        for sink in sinks:
            has_sanitizer = any(
                s.get("category") == sink.get("category") for s in sanitizers
            )
            if not has_sanitizer:
                vulnerabilities.append({
                    **sink,
                    "source": "pattern",
                    "has_sanitizer": False,
                })

        return {
            "vulnerabilities": vulnerabilities,
            "sources": sources,
            "sinks": sinks,
            "sanitizers": sanitizers,
        }

    def _run_taint_analysis(self, code: str, language: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """运行污点分析。"""
        taint_result = self._taint_analyzer.analyze_code(code, language, context)
        return {
            "vulnerabilities": taint_result.vulnerabilities,
            "sources": [{"name": s.name, "category": s.category} for s in taint_result.sources],
            "sinks": [{"name": s.name, "severity": s.severity, "cwe": s.cwe} for s in taint_result.sinks],
            "summary": taint_result.summary,
        }

    def _merge_results(self, result: StaticAnalysisResult) -> None:
        """合并各分析结果。"""
        all_vulns: List[Dict[str, Any]] = []
        seen_keys: set = set()

        for detail_key in ("pattern", "taint"):
            detail = result.analysis_details.get(detail_key, {})
            vulns = detail.get("vulnerabilities", [])
            for v in vulns:
                # 去重：基于 rule_id + pattern_type + severity
                key = f"{v.get('rule_id', '')}:{v.get('pattern_type', '')}:{v.get('severity', '')}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_vulns.append({**v, "analysis_source": detail_key})

        result.vulnerabilities = all_vulns

        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_type: Dict[str, int] = {}
        for v in all_vulns:
            sev = v.get("severity", "medium").lower()
            if sev in by_severity:
                by_severity[sev] += 1
            else:
                by_severity["medium"] += 1
            cat = v.get("category", "unknown")
            by_type[cat] = by_type.get(cat, 0) + 1

        result.summary = {
            "total": len(all_vulns),
            **by_severity,
            "by_type": by_type,
        }
