"""
Sink Finder OpenCode 封装器

将 OpenCode (code_agent) 封装为可选的增强工具，
提供独立的 sink 发现和 sink 验证能力。
"""
from __future__ import annotations

import json
import logging
import os
import traceback
from typing import Any, Dict, List, Optional

from src.agents.brain import Brain
from src.agents.sink_finder_config import SinkFinderHybridConfig
from src.core.enums import ActionType
from src.core.event_span import start_event_span
from src.utils.ids import generate_uuid

logger = logging.getLogger(__name__)

# 复用 sink_finder 中的校验函数
from src.agents.sink_finder import _validate_and_normalize_sink_res, _SINK_RES_SCHEMA_HINT


class OpenCodeSinkFinder:
    """OpenCode 封装器：使用 OpenCode 进行 sink 发现或验证"""

    MODULE_NAME = "sink_finder_opencode"

    def __init__(self, brain: Brain, config: SinkFinderHybridConfig):
        self._brain = brain
        self._config = config
        self._code_agent = None
        self._init_opencode()

    def _init_opencode(self) -> None:
        """初始化 OpenCode 工具引用"""
        if self._brain.offline_mode:
            return
        code_agent = self._brain.tools.get("code_agent")
        if code_agent is not None:
            self._code_agent = code_agent

    def is_available(self) -> bool:
        """检查 OpenCode 是否可用"""
        return self._code_agent is not None

    def find_sinks(
        self,
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        使用 OpenCode 独立发现 sink 点。

        返回:
            成功时返回 sink 列表，失败或不可用时返回 None
        """
        if not self.is_available():
            return None

        result_file_path = str(self._brain.tmp_dir / f"opencode_sinks_{generate_uuid()}.txt")

        # 构建 OpenCode 提示词
        msg = self._build_find_sinks_prompt(language, vul_name, risk_description, reasoning_basis)

        self._publish_log(
            "INFO",
            f"[OpenCodeSinkFinder] 开始 OpenCode sink 发现 | "
            f"language={language} vul_name={vul_name}",
        )

        opencode_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.SINK_DISCOVERY,
            reason=f"OpenCode 增强模式：寻找 {language} 语言的 {vul_name} 类型的 sink 触发点",
        )

        try:
            result = self._code_agent.run(
                msg=msg,
                result_file_flag=True,
                result_file_path=result_file_path,
                output=(
                    "请按以下 JSON 格式返回结果，每个项包含："
                    "file（文件路径）、line（行号）、end_line（结束行号）、"
                    "function（函数名）、related_exec（相关执行路径，可为空）、"
                    "reason（原因说明）。顶层为数组。"
                ),
                task_id=self._brain.task_id,
            )

            # 提取 Token 用量
            data = dict((result or {}).get("data") or {})
            token_input = data.pop("token_input", 0) or 0
            token_output = data.pop("token_output", 0) or 0
            if token_input or token_output:
                opencode_span.add_code_agent_tokens(token_input, token_output)

            if not result.success:
                self._publish_log(
                    "WARNING",
                    f"[OpenCodeSinkFinder] OpenCode 执行失败: {result.error}",
                )
                opencode_span.mark_failed(f"OpenCode 执行失败: {result.error}")
                return None

            # 读取结果文件
            if not os.path.exists(result_file_path):
                self._publish_log(
                    "WARNING",
                    f"[OpenCodeSinkFinder] 结果文件不存在: {result_file_path}",
                )
                opencode_span.mark_failed("结果文件不存在")
                return None

            with open(result_file_path, "r", encoding="utf-8", errors="replace") as f:
                raw_content = f.read()

            # 尝试从文件内容中提取 JSON
            sinks = self._parse_result(raw_content)
            if sinks is not None:
                self._publish_log(
                    "INFO",
                    f"[OpenCodeSinkFinder] OpenCode 发现 {len(sinks)} 条 sink",
                )
                opencode_span.finish()
                return sinks

            # 如果文件内容不是纯 JSON，尝试从 response_text 中提取
            response_text = ""
            if hasattr(result, "data") and isinstance(result.data, tuple):
                response_text = result.data[0] if result.data[0] else ""

            if response_text:
                sinks = self._parse_result(response_text)
                if sinks is not None:
                    self._publish_log(
                        "INFO",
                        f"[OpenCodeSinkFinder] OpenCode 从响应中发现 {len(sinks)} 条 sink",
                    )
                    opencode_span.finish()
                    return sinks

            self._publish_log(
                "WARNING",
                "[OpenCodeSinkFinder] 无法从 OpenCode 结果中解析出有效的 sink 数据",
            )
            opencode_span.mark_failed("无法解析 sink 数据")
            return None

        except Exception as e:
            tb = traceback.format_exc()
            tail = tb[-2000:] if len(tb) > 2000 else tb
            self._publish_log(
                "ERROR",
                f"[OpenCodeSinkFinder] OpenCode 执行异常: {e!r}\n{tail}",
            )
            opencode_span.mark_failed(f"OpenCode 执行异常: {e}")
            return None

    def verify_sinks(
        self,
        sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        使用 OpenCode 验证已发现的 sink 点。

        对原生 LLM 发现的 sink 进行深度验证，确认是否为真实漏洞。

        返回:
            验证后的 sink 列表（可能比输入少），失败时返回 None
        """
        if not self.is_available():
            return None

        if not sinks:
            return None

        # 限制验证数量，避免 OpenCode 调用过久
        sinks_to_verify = sinks[:self._config.max_verify_sinks]

        msg = self._build_verify_sinks_prompt(sinks_to_verify, language, vul_name, risk_description)

        self._publish_log(
            "INFO",
            f"[OpenCodeSinkFinder] 开始 OpenCode sink 验证 | "
            f"language={language} vul_name={vul_name} count={len(sinks_to_verify)}",
        )

        opencode_span = start_event_span(
            task_id=self._brain.task_id,
            module=self.MODULE_NAME,
            action_type=ActionType.SINK_DISCOVERY,
            reason=f"OpenCode 增强验证：验证 {language} 语言的 {vul_name} 类型的 {len(sinks_to_verify)} 条 sink",
        )

        try:
            result = self._code_agent.run(
                msg=msg,
                task_id=self._brain.task_id,
            )

            # 提取 Token 用量
            data = dict((result or {}).get("data") or {})
            token_input = data.pop("token_input", 0) or 0
            token_output = data.pop("token_output", 0) or 0
            if token_input or token_output:
                opencode_span.add_code_agent_tokens(token_input, token_output)

            if not result.success:
                self._publish_log(
                    "WARNING",
                    f"[OpenCodeSinkFinder] OpenCode 验证执行失败: {result.error}",
                )
                opencode_span.mark_failed(f"OpenCode 验证失败: {result.error}")
                return None

            # 从响应中提取验证结果
            response_text = ""
            if hasattr(result, "data") and isinstance(result.data, tuple):
                response_text = result.data[0] if result.data[0] else ""

            if not response_text:
                self._publish_log(
                    "WARNING",
                    "[OpenCodeSinkFinder] OpenCode 验证响应为空",
                )
                opencode_span.mark_failed("验证响应为空")
                return None

            # 解析验证结果
            verified = self._parse_verify_result(response_text, sinks_to_verify)
            if verified is not None:
                self._publish_log(
                    "INFO",
                    f"[OpenCodeSinkFinder] OpenCode 验证完成 | "
                    f"before={len(sinks_to_verify)} after={len(verified)}",
                )
                opencode_span.finish()
                return verified

            opencode_span.mark_failed("无法解析验证结果")
            return None

        except Exception as e:
            tb = traceback.format_exc()
            tail = tb[-2000:] if len(tb) > 2000 else tb
            self._publish_log(
                "ERROR",
                f"[OpenCodeSinkFinder] OpenCode 验证异常: {e!r}\n{tail}",
            )
            opencode_span.mark_failed(f"OpenCode 验证异常: {e}")
            return None

    # ── 提示词构建 ──

    def _build_find_sinks_prompt(
        self,
        language: str,
        vul_name: str,
        risk_description: str,
        reasoning_basis: str,
    ) -> str:
        """构建 OpenCode sink 发现的提示词"""
        return (
            f"你是一个专业的代码安全审计专家。请分析项目代码，找出所有可能的 sink 触发点。\n\n"
            f"## 审计目标\n"
            f"- 编程语言: {language}\n"
            f"- 漏洞类型: {vul_name}\n"
            f"- 漏洞描述: {risk_description}\n"
            f"- 审计依据: {reasoning_basis}\n\n"
            f"## 要求\n"
            f"1. 在项目根目录中搜索所有可能的 {vul_name} 类型的 sink 触发点\n"
            f"2. 对每个 sink 点，提供：文件路径、行号范围、函数名、相关执行路径、原因说明\n"
            f"3. 文件路径必须是项目根目录下的相对路径\n"
            f"4. 行号必须是正整数，end_line >= line\n"
            f"5. related_exec 格式为 file:line:function 或 <file:line:function>，无关联时留空\n"
            f"6. reason 必须为非空字符串，说明该 sink 的安全风险原因\n\n"
            f"## 项目信息\n"
            f"{self._brain.project_info_compact}\n"
        )

    def _build_verify_sinks_prompt(
        self,
        sinks: List[Dict[str, Any]],
        language: str,
        vul_name: str,
        risk_description: str,
    ) -> str:
        """构建 OpenCode sink 验证的提示词"""
        sinks_text = ""
        for i, sink in enumerate(sinks, 1):
            sinks_text += (
                f"\n### Sink #{i}\n"
                f"- 文件: {sink.get('file', '')}\n"
                f"- 行号: {sink.get('line', '')}-{sink.get('end_line', '')}\n"
                f"- 函数: {sink.get('function', '')}\n"
                f"- 原因: {sink.get('reason', '')}\n"
            )
            related = sink.get("related_exec", "")
            if related:
                sinks_text += f"- 关联执行: {related}\n"

        return (
            f"你是一个专业的代码安全审计专家。请验证以下 sink 触发点是否为真实的安全风险。\n\n"
            f"## 审计目标\n"
            f"- 编程语言: {language}\n"
            f"- 漏洞类型: {vul_name}\n"
            f"- 漏洞描述: {risk_description}\n\n"
            f"## 待验证的 Sink 列表\n"
            f"{sinks_text}\n"
            f"## 验证要求\n"
            f"1. 逐一检查上述 sink 点，确认是否为真实的安全风险\n"
            f"2. 排除误报（如：输入已经过消毒、存在安全检查、不可达代码等）\n"
            f"3. 对每个确认的 sink，补充更详细的原因说明\n"
            f"4. 返回确认的 sink 列表（JSON 数组格式）\n\n"
            f"## 项目信息\n"
            f"{self._brain.project_info_compact}\n"
        )

    # ── 结果解析 ──

    def _parse_result(self, raw_content: str) -> Optional[List[Dict[str, Any]]]:
        """
        从原始内容中解析 sink 列表。

        支持多种格式：
        1. 纯 JSON 数组
        2. 包含 JSON 数组的文本
        3. Markdown 代码块中的 JSON
        """
        if not raw_content or not raw_content.strip():
            return None

        # 尝试直接解析
        try:
            data = json.loads(raw_content.strip())
            if isinstance(data, list):
                normalized, err = _validate_and_normalize_sink_res(data, self._brain.project_path)
                if normalized is not None:
                    return normalized
        except (json.JSONDecodeError, ValueError):
            pass

        # 尝试从文本中提取 JSON 数组
        import re
        # 匹配 ```json ... ``` 代码块
        json_block_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_content, re.DOTALL)
        if json_block_match:
            try:
                data = json.loads(json_block_match.group(1).strip())
                if isinstance(data, list):
                    normalized, err = _validate_and_normalize_sink_res(data, self._brain.project_path)
                    if normalized is not None:
                        return normalized
            except (json.JSONDecodeError, ValueError):
                pass

        # 尝试匹配最外层的 [...] 结构
        bracket_match = re.search(r"\[[\s\S]*\]", raw_content)
        if bracket_match:
            try:
                data = json.loads(bracket_match.group(0))
                if isinstance(data, list):
                    normalized, err = _validate_and_normalize_sink_res(data, self._brain.project_path)
                    if normalized is not None:
                        return normalized
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    def _parse_verify_result(
        self,
        response_text: str,
        original_sinks: List[Dict[str, Any]],
    ) -> Optional[List[Dict[str, Any]]]:
        """
        解析验证结果。

        如果 OpenCode 返回了有效的 sink 列表，使用该列表；
        否则尝试根据响应内容过滤原始列表。
        """
        # 首先尝试解析为标准 sink 列表
        parsed = self._parse_result(response_text)
        if parsed is not None:
            return parsed

        # 尝试解析为包含验证信息的结构
        try:
            data = json.loads(response_text.strip())
            if isinstance(data, dict):
                # 可能有 "verified_sinks" 或 "confirmed" 字段
                for key in ("verified_sinks", "confirmed", "sinks", "results"):
                    if key in data and isinstance(data[key], list):
                        normalized, err = _validate_and_normalize_sink_res(
                            data[key], self._brain.project_path
                        )
                        if normalized is not None:
                            return normalized

                # 可能有 "rejected" 字段，从中推断确认的
                rejected_indices = set()
                if "rejected" in data and isinstance(data["rejected"], list):
                    for item in data["rejected"]:
                        if isinstance(item, dict) and "index" in item:
                            rejected_indices.add(int(item["index"]))

                if rejected_indices:
                    return [
                        sink for i, sink in enumerate(original_sinks)
                        if i not in rejected_indices
                    ]
        except (json.JSONDecodeError, ValueError):
            pass

        return None

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
