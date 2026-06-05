# -*- coding: utf-8 -*-
"""规则引擎 —— 整合自 gbt-codeagent。

负责加载和管理检测规则，提供模式匹配能力。
特性：LRU 正则缓存、上下文感知误报过滤、置信度计算。
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml


class LRUCache:
    """简单的 LRU 缓存。"""

    def __init__(self, max_size: int = 1000) -> None:
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size

    def get(self, key: str) -> Any:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, key: str, value: Any) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
        self._cache[key] = value

    def has(self, key: str) -> bool:
        return key in self._cache

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


@dataclass
class DetectionRule:
    """单条检测规则。"""

    id: str
    name: str
    severity: str = "medium"
    category: str = ""
    language: List[str] = field(default_factory=list)
    source_patterns: List[str] = field(default_factory=list)
    sink_patterns: List[str] = field(default_factory=list)
    sanitizer_patterns: List[str] = field(default_factory=list)
    description: str = ""
    cwe: str = ""
    confidence: float = 0.7
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    _compiled_source: List[re.Pattern] = field(default_factory=list, repr=False)
    _compiled_sink: List[re.Pattern] = field(default_factory=list, repr=False)
    _compiled_sanitizer: List[re.Pattern] = field(default_factory=list, repr=False)

    def compile_patterns(self) -> None:
        self._compiled_source = [re.compile(p, re.IGNORECASE) for p in self.source_patterns]
        self._compiled_sink = [re.compile(p, re.IGNORECASE) for p in self.sink_patterns]
        self._compiled_sanitizer = [re.compile(p, re.IGNORECASE) for p in self.sanitizer_patterns]


class RulesEngine:
    """规则引擎：加载 YAML 规则并提供模式匹配。"""

    def __init__(self, regex_cache_size: int = 2000) -> None:
        self._rules: List[DetectionRule] = []
        self._rules_by_language: Dict[str, List[DetectionRule]] = {}
        self._regex_cache = LRUCache(regex_cache_size)
        self._initialized = False
        self._stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "total_matches": 0,
        }

    @property
    def rules(self) -> List[DetectionRule]:
        return self._rules

    def load_from_file(self, filepath: str) -> None:
        """从 YAML 文件加载规则。"""
        if not os.path.isfile(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self._parse_rules(data)

    def load_from_dict(self, data: Dict[str, Any]) -> None:
        """从字典加载规则。"""
        self._parse_rules(data)

    def _parse_rules(self, data: Dict[str, Any]) -> None:
        rules_data = data.get("rules", data.get("detection_rules", []))
        if isinstance(rules_data, list):
            for rule_data in rules_data:
                rule = self._create_rule(rule_data)
                if rule:
                    self._rules.append(rule)
                    for lang in rule.language or ["*"]:
                        self._rules_by_language.setdefault(lang, []).append(rule)
        self._initialized = True

    def _create_rule(self, data: Dict[str, Any]) -> Optional[DetectionRule]:
        if not data:
            return None
        rule = DetectionRule(
            id=data.get("id", ""),
            name=data.get("name", ""),
            severity=data.get("severity", "medium"),
            category=data.get("category", ""),
            language=data.get("language", []),
            source_patterns=data.get("source_patterns", data.get("sources", [])),
            sink_patterns=data.get("sink_patterns", data.get("sinks", [])),
            sanitizer_patterns=data.get("sanitizer_patterns", data.get("sanitizers", [])),
            description=data.get("description", ""),
            cwe=data.get("cwe", ""),
            confidence=data.get("confidence", 0.7),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
        )
        rule.compile_patterns()
        return rule

    def get_supported_languages(self) -> List[str]:
        return list(self._rules_by_language.keys())

    def match_sources(self, code: str, language: str) -> List[Dict[str, Any]]:
        """匹配代码中的 source 模式。"""
        return self._match_patterns(code, language, "source")

    def match_sinks(self, code: str, language: str) -> List[Dict[str, Any]]:
        """匹配代码中的 sink 模式。"""
        return self._match_patterns(code, language, "sink")

    def match_sanitizers(self, code: str, language: str) -> List[Dict[str, Any]]:
        """匹配代码中的 sanitizer 模式。"""
        return self._match_patterns(code, language, "sanitizer")

    def _match_patterns(self, code: str, language: str, pattern_type: str) -> List[Dict[str, Any]]:
        results = []
        applicable_rules = self._get_applicable_rules(language)

        for rule in applicable_rules:
            if not rule.enabled:
                continue

            patterns = []
            if pattern_type == "source":
                patterns = rule._compiled_source
            elif pattern_type == "sink":
                patterns = rule._compiled_sink
            elif pattern_type == "sanitizer":
                patterns = rule._compiled_sanitizer

            for pattern in patterns:
                cache_key = f"{pattern.pattern}:{hashlib.sha256(code.encode('utf-8', errors='replace')).hexdigest()[:12]}"
                cached = self._regex_cache.get(cache_key)
                if cached is not None:
                    self._stats["cache_hits"] += 1
                    if cached:
                        results.append(self._format_match(rule, pattern.pattern, pattern_type))
                else:
                    self._stats["cache_misses"] += 1
                    match = pattern.search(code)
                    self._regex_cache.set(cache_key, bool(match))
                    if match:
                        self._stats["total_matches"] += 1
                        results.append(self._format_match(rule, pattern.pattern, pattern_type))

        return results

    def _get_applicable_rules(self, language: str) -> List[DetectionRule]:
        lang_rules = self._rules_by_language.get(language, [])
        wildcard_rules = self._rules_by_language.get("*", [])
        return lang_rules + wildcard_rules

    def _format_match(self, rule: DetectionRule, pattern: str, pattern_type: str) -> Dict[str, Any]:
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "category": rule.category,
            "severity": rule.severity,
            "cwe": rule.cwe,
            "confidence": rule.confidence,
            "pattern": pattern,
            "pattern_type": pattern_type,
        }

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)
