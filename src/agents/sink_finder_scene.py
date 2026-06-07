"""
Sink Finder 场景判断器

根据项目复杂度、语言分布、漏洞类型等特征，
智能判断是否需要使用 OpenCode 增强模式。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from src.agents.brain import Brain
from src.agents.sink_finder_config import SinkFinderHybridConfig

logger = logging.getLogger(__name__)


class SceneAnalysisResult:
    """场景分析结果"""

    def __init__(
        self,
        should_use_opencode: bool,
        project_complexity: str,
        reason: str,
        details: Dict[str, Any] = None,
    ):
        self.should_use_opencode = should_use_opencode
        self.project_complexity = project_complexity  # low / medium / high
        self.reason = reason
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "should_use_opencode": self.should_use_opencode,
            "project_complexity": self.project_complexity,
            "reason": self.reason,
            "details": self.details,
        }


class SceneAnalyzer:
    """场景判断器：分析项目特征，决定是否启用 OpenCode 增强模式"""

    def __init__(self, brain: Brain, config: SinkFinderHybridConfig):
        self._brain = brain
        self._config = config

    def analyze(self, language: str, vul_name: str) -> SceneAnalysisResult:
        """
        综合分析项目特征，判断是否应使用 OpenCode。

        判断维度：
        1. 项目规模（文件数、代码行数）
        2. 语言多样性
        3. 框架复杂度
        4. 漏洞类型风险等级
        5. OpenCode 可用性
        """
        # 如果禁用混合模式或 OpenCode，直接返回
        if not self._config.enable_hybrid_mode or not self._config.enable_opencode:
            return SceneAnalysisResult(
                should_use_opencode=False,
                project_complexity="unknown",
                reason="混合模式或 OpenCode 已禁用",
            )

        # 检查 OpenCode 是否可用
        if not self._is_opencode_available():
            return SceneAnalysisResult(
                should_use_opencode=False,
                project_complexity="unknown",
                reason="OpenCode 不可用（脱机模式或初始化失败）",
            )

        # 收集项目统计信息
        stats = self._collect_project_stats()

        # 逐项判断
        reasons: List[str] = []
        use_opencode = False

        # 1. 项目规模判断
        file_count = stats.get("file_count", 0)
        line_count = stats.get("line_count", 0)
        if file_count > self._config.complex_project_file_threshold:
            use_opencode = True
            reasons.append(f"项目文件数({file_count})超过阈值({self._config.complex_project_file_threshold})")
        if line_count > self._config.complex_project_line_threshold:
            use_opencode = True
            reasons.append(f"项目代码行数({line_count})超过阈值({self._config.complex_project_line_threshold})")

        # 2. 语言多样性判断
        lang_count = stats.get("language_count", 0)
        if lang_count > self._config.multilingual_threshold:
            use_opencode = True
            reasons.append(f"项目语言数({lang_count})超过阈值({self._config.multilingual_threshold})")

        # 3. 框架复杂度判断
        framework_count = stats.get("framework_count", 0)
        if framework_count > self._config.framework_threshold:
            use_opencode = True
            reasons.append(f"框架依赖数({framework_count})超过阈值({self._config.framework_threshold})")

        # 4. 漏洞类型风险等级判断
        vul_type_match = self._check_vuln_type(vul_name)
        if vul_type_match:
            use_opencode = True
            reasons.append(f"漏洞类型'{vul_name}'属于高风险类型，建议使用 OpenCode 深度分析")

        # 确定项目复杂度
        complexity = self._determine_complexity(stats)

        reason = "; ".join(reasons) if reasons else "项目特征不需要 OpenCode 增强"

        return SceneAnalysisResult(
            should_use_opencode=use_opencode,
            project_complexity=complexity,
            reason=reason,
            details=stats,
        )

    def _is_opencode_available(self) -> bool:
        """检查 OpenCode 工具是否可用"""
        if self._brain.offline_mode:
            return False
        code_agent = self._brain.tools.get("code_agent")
        if code_agent is None:
            return False
        return getattr(code_agent, "status", False)

    def _collect_project_stats(self) -> Dict[str, Any]:
        """收集项目统计信息"""
        stats: Dict[str, Any] = {
            "file_count": 0,
            "line_count": 0,
            "language_count": 0,
            "framework_count": 0,
            "languages": [],
        }

        # 从 Tokei 统计中获取信息
        code_count_json = getattr(self._brain, "code_count_json", {})
        if isinstance(code_count_json, dict):
            # Tokei 输出格式: {"Python": {"lines": 1000, "code": 800, ...}, ...}
            languages = []
            total_lines = 0
            for lang_name, lang_data in code_count_json.items():
                if isinstance(lang_data, dict):
                    lines = lang_data.get("code", 0) or 0
                    total_lines += lines
                    if lines > 0:
                        languages.append(lang_name)
            stats["line_count"] = total_lines
            stats["language_count"] = len(languages)
            stats["languages"] = languages

        # 从 project_info 中估算文件数
        code_count_str = getattr(self._brain, "code_count_str", "")
        if code_count_str:
            # code_count_str 通常包含文件数信息
            import re
            file_match = re.search(r"(\d+)\s*files?", code_count_str, re.IGNORECASE)
            if file_match:
                stats["file_count"] = int(file_match.group(1))

        # 检测框架数量
        try:
            from src.knowledge.framework_rules import detect_framework
            detected = detect_framework(self._brain.project_path)
            if isinstance(detected, list):
                stats["framework_count"] = len(detected)
            elif isinstance(detected, dict):
                stats["framework_count"] = len(detected)
        except Exception:
            pass

        return stats

    def _check_vuln_type(self, vul_name: str) -> bool:
        """检查漏洞类型是否在 OpenCode 增强列表中"""
        for target_type in self._config.use_opencode_for_vuln_types:
            # 支持模糊匹配：如 "sql-injection" 匹配 "SQL注入"
            if target_type.lower() in vul_name.lower():
                return True
            # 中文关键词映射
            cn_mapping = {
                "sql-injection": ["SQL注入", "SQL 注入"],
                "command-injection": ["命令注入", "命令执行", "命令执行注入"],
                "deserialization": ["反序列化", "不安全反序列化"],
                "rce": ["远程代码执行", "代码执行", "RCE"],
                "path-traversal-advanced": ["路径遍历", "目录遍历"],
            }
            cn_keywords = cn_mapping.get(target_type, [])
            if any(kw in vul_name for kw in cn_keywords):
                return True
        return False

    def _determine_complexity(self, stats: Dict[str, Any]) -> str:
        """根据统计数据确定项目复杂度"""
        file_count = stats.get("file_count", 0)
        line_count = stats.get("line_count", 0)
        lang_count = stats.get("language_count", 0)

        score = 0
        if file_count > self._config.complex_project_file_threshold:
            score += 2
        elif file_count > self._config.complex_project_file_threshold // 2:
            score += 1

        if line_count > self._config.complex_project_line_threshold:
            score += 2
        elif line_count > self._config.complex_project_line_threshold // 2:
            score += 1

        if lang_count > self._config.multilingual_threshold:
            score += 1

        if score >= 3:
            return "high"
        elif score >= 1:
            return "medium"
        return "low"
