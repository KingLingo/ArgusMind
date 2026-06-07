"""
Sink Finder 混合控制器

协调原生 LLM 循环与 OpenCode 增强模式的协同工作。
支持三种策略：parallel / serial-enhanced / divide-conquer。
"""
from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional

from src.agents.brain import Brain
from src.agents.sink_finder_config import SinkFinderHybridConfig
from src.agents.sink_finder_scene import SceneAnalyzer, SceneAnalysisResult
from src.agents.sink_finder_opencode import OpenCodeSinkFinder
from src.agents.sink_finder import (
    _normalize_file_for_key,
    _sink_node_id,
)

logger = logging.getLogger(__name__)


class HybridSinkFinder:
    """
    混合 Sink 发现控制器。

    根据场景分析结果，智能选择或组合原生 LLM 循环与 OpenCode 两种方式：
    - serial-enhanced（默认）：先用原生 LLM，再用 OpenCode 验证高风险结果
    - parallel：同时运行两种方式，合并结果
    - divide-conquer：按漏洞类型分配给不同方式
    """

    MODULE_NAME = "sink_finder_hybrid"

    def __init__(self, brain: Brain, config: SinkFinderHybridConfig = None):
        self._brain = brain
        self._config = config or SinkFinderHybridConfig.default_config()
        self._scene_analyzer = SceneAnalyzer(brain, self._config)
        self._opencode_finder = OpenCodeSinkFinder(brain, self._config)

    def should_use_opencode(self, language: str, vul_name: str) -> SceneAnalysisResult:
        """判断是否应使用 OpenCode 增强模式"""
        return self._scene_analyzer.analyze(language, vul_name)

    def enhance_with_opencode(
        self,
        native_sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
        scene: SceneAnalysisResult,
    ) -> List[Dict[str, Any]]:
        """
        根据策略和场景分析结果，使用 OpenCode 增强原生 LLM 的结果。

        Args:
            native_sinks: 原生 LLM 循环发现的 sink 列表
            language: 编程语言
            vul_name: 漏洞类型名称
            risk_description: 风险描述
            reasoning_basis: 审计依据
            scene: 场景分析结果

        Returns:
            增强后的 sink 列表
        """
        if not self._config.enable_hybrid_mode:
            return native_sinks

        if not scene.should_use_opencode:
            self._publish_log(
                "INFO",
                f"[HybridSinkFinder] 场景分析不建议使用 OpenCode: {scene.reason}",
            )
            return native_sinks

        if not self._opencode_finder.is_available():
            self._publish_log(
                "INFO",
                "[HybridSinkFinder] OpenCode 不可用，使用原生结果",
            )
            return native_sinks

        strategy = self._config.strategy_mode

        self._publish_log(
            "INFO",
            f"[HybridSinkFinder] 启用混合模式 | strategy={strategy} "
            f"complexity={scene.project_complexity} reason={scene.reason}",
        )

        if strategy == "serial-enhanced":
            return self._run_serial_enhanced(
                native_sinks, language, vul_name, risk_description, reasoning_basis
            )
        elif strategy == "parallel":
            return self._run_parallel(
                native_sinks, language, vul_name, risk_description, reasoning_basis
            )
        elif strategy == "divide-conquer":
            return self._run_divide_conquer(
                native_sinks, language, vul_name, risk_description, reasoning_basis
            )
        else:
            self._publish_log(
                "WARNING",
                f"[HybridSinkFinder] 未知策略模式: {strategy}，回退到 serial-enhanced",
            )
            return self._run_serial_enhanced(
                native_sinks, language, vul_name, risk_description, reasoning_basis
            )

    # ── 策略实现 ──

    def _run_serial_enhanced(
        self,
        native_sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
    ) -> List[Dict[str, Any]]:
        """
        串行增强策略：
        1. 使用原生 LLM 结果作为基础
        2. 对高风险 sink 用 OpenCode 深度验证
        3. 合并验证结果
        """
        if not native_sinks:
            # 原生方式未发现 sink，尝试用 OpenCode 独立发现
            self._publish_log(
                "INFO",
                "[HybridSinkFinder] 原生方式未发现 sink，尝试 OpenCode 独立发现",
            )
            opencode_sinks = self._opencode_finder.find_sinks(
                language, vul_name, risk_description, reasoning_basis
            )
            if opencode_sinks:
                self._publish_log(
                    "INFO",
                    f"[HybridSinkFinder] OpenCode 独立发现 {len(opencode_sinks)} 条 sink",
                )
                return opencode_sinks
            return native_sinks

        # 对原生结果进行 OpenCode 验证
        self._publish_log(
            "INFO",
            f"[HybridSinkFinder] 使用 OpenCode 验证 {len(native_sinks)} 条原生 sink",
        )

        verified = self._opencode_finder.verify_sinks(
            native_sinks, language, vul_name, risk_description
        )

        if verified is not None:
            # 合并：以验证结果为主，补充原生中未被验证排除的
            merged = self._merge_results(native_sinks, verified)
            self._publish_log(
                "INFO",
                f"[HybridSinkFinder] 串行增强完成 | "
                f"native={len(native_sinks)} verified={len(verified)} merged={len(merged)}",
            )
            return merged

        # 验证失败，返回原生结果
        self._publish_log(
            "WARNING",
            "[HybridSinkFinder] OpenCode 验证失败，使用原生结果",
        )
        return native_sinks

    def _run_parallel(
        self,
        native_sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
    ) -> List[Dict[str, Any]]:
        """
        并行策略：
        使用 OpenCode 独立发现 sink，然后与原生结果合并。

        注意：真正的并行需要异步执行，这里采用串行模拟（先原生后 OpenCode），
        因为原生结果已经在上层调用中获取。
        """
        self._publish_log(
            "INFO",
            "[HybridSinkFinder] 并行模式：OpenCode 独立发现 + 原生结果合并",
        )

        opencode_sinks = self._opencode_finder.find_sinks(
            language, vul_name, risk_description, reasoning_basis
        )

        if opencode_sinks is None:
            self._publish_log(
                "WARNING",
                "[HybridSinkFinder] OpenCode 独立发现失败，使用原生结果",
            )
            return native_sinks

        # 合并两种方式的结果
        merged = self._merge_results(native_sinks, opencode_sinks)
        self._publish_log(
            "INFO",
            f"[HybridSinkFinder] 并行合并完成 | "
            f"native={len(native_sinks)} opencode={len(opencode_sinks)} merged={len(merged)}",
        )
        return merged

    def _run_divide_conquer(
        self,
        native_sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
    ) -> List[Dict[str, Any]]:
        """
        分工协作策略：
        根据漏洞类型决定是否使用 OpenCode 补充发现。

        对于高风险漏洞类型，使用 OpenCode 补充发现；
        对于低风险漏洞类型，仅使用原生结果。
        """
        # 检查当前漏洞类型是否需要 OpenCode 补充
        need_opencode = self._scene_analyzer._check_vuln_type(vul_name)

        if not need_opencode:
            self._publish_log(
                "INFO",
                f"[HybridSinkFinder] 分工模式：漏洞类型'{vul_name}'不需要 OpenCode 补充",
            )
            return native_sinks

        self._publish_log(
            "INFO",
            f"[HybridSinkFinder] 分工模式：漏洞类型'{vul_name}'需要 OpenCode 补充发现",
        )

        opencode_sinks = self._opencode_finder.find_sinks(
            language, vul_name, risk_description, reasoning_basis
        )

        if opencode_sinks is None:
            return native_sinks

        # 合并：取并集
        merged = self._merge_results(native_sinks, opencode_sinks)
        self._publish_log(
            "INFO",
            f"[HybridSinkFinder] 分工合并完成 | "
            f"native={len(native_sinks)} opencode={len(opencode_sinks)} merged={len(merged)}",
        )
        return merged

    # ── 结果合并 ──

    def _merge_results(
        self,
        native_sinks: List[Dict[str, Any]],
        opencode_sinks: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        合并原生 LLM 和 OpenCode 的结果。

        合并规则：
        1. 以 sink_node_id (file:line:function) 去重
        2. 同一位置优先使用 OpenCode 的结果（更详细）
        3. 保留两种方式独有的发现
        """
        if not self._config.enable_result_merging:
            # 不合并，直接拼接
            return native_sinks + opencode_sinks

        # 按 sink_node_id 建立索引
        seen_ids: Dict[str, Dict[str, Any]] = {}

        # 先添加原生结果
        for sink in native_sinks:
            sink_id = self._get_sink_id(sink)
            if sink_id not in seen_ids:
                seen_ids[sink_id] = deepcopy(sink)
                seen_ids[sink_id]["_source"] = "native"

        # 再添加 OpenCode 结果（同 ID 时覆盖，因为 OpenCode 验证后更详细）
        for sink in opencode_sinks:
            sink_id = self._get_sink_id(sink)
            if sink_id in seen_ids:
                # 合并信息：保留原生来源标记，但用 OpenCode 的详细信息
                existing = seen_ids[sink_id]
                merged_sink = deepcopy(sink)
                merged_sink["_source"] = "both"
                # 如果 OpenCode 的 reason 更详细，使用 OpenCode 的
                if len(sink.get("reason", "")) > len(existing.get("reason", "")):
                    merged_sink["reason"] = sink.get("reason", "")
                # 如果原生有 related_exec 而 OpenCode 没有，保留原生的
                if existing.get("related_exec") and not sink.get("related_exec"):
                    merged_sink["related_exec"] = existing["related_exec"]
                seen_ids[sink_id] = merged_sink
            else:
                seen_ids[sink_id] = deepcopy(sink)
                seen_ids[sink_id]["_source"] = "opencode"

        # 清理内部标记字段
        result = []
        for sink in seen_ids.values():
            sink.pop("_source", None)
            result.append(sink)

        return result

    @staticmethod
    def _get_sink_id(sink: Dict[str, Any]) -> str:
        """获取 sink 的唯一标识"""
        file_v = _normalize_file_for_key(sink.get("file", ""))
        line_v = int(sink.get("line", 0))
        func_v = (sink.get("function") or "").strip()
        return f"{file_v}:{line_v}:{func_v}"

    def _publish_log(self, level: str, message: str) -> None:
        """发布日志"""
        try:
            from src.core.event_bus import get_event_bus
            from src.core.events import LogEvent
            get_event_bus().publish_async(
                LogEvent(level=level, module=self.MODULE_NAME, message=message, task_id=self._brain.task_id)
            )
        except Exception:
            logger.log(getattr(logging, level.upper(), logging.INFO), "[%s] %s", self.MODULE_NAME, message)
