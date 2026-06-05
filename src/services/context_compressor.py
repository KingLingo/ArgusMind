# -*- coding: utf-8 -*-
"""上下文压缩服务 —— 借鉴 gbt-codeagent 的 ContextCompressor。

在 LLM 多轮对话中，累积的消息历史会快速膨胀到 token 上限。
当对话超过阈值时，调用轻量 LLM 将历史压缩为结构化摘要，
释放 token 预算以容纳新内容。

压缩维度：
1. Identified Issues — 已确认的安全问题
2. Tool Call Conclusions — 工具调用的关键发现
3. Completed Tasks — 已完成无需跟进
4. Pending Tasks — 进行中仍需关注
5. Current Focus — 当前焦点
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

COMPRESSION_SYSTEM_PROMPT = """## Goal
You are a code security auditor conversation summarizer. Compress the conversation history into a structured summary so the audit can continue without losing context.

## Output Format
Use these five dimensions with explicit headings:

### Identified Code Issues
List confirmed issues sorted by severity. Each: file path, issue type, verdict, key detail.
- file:line — SQL injection confirmed — user input reaches query without parameterization

### Tool Call Conclusions
Key findings from tool calls (read_file, search_code, etc.). Example:
- read_file(UserService.java:45): confirmed input enters createNativeQuery without preprocessing
- search_code("execute.*+"): found 3 files with SQL string concatenation

### Completed Tasks
Items completed that need no follow-up.

### Pending Tasks
Items started but not yet completed, still need attention.

### Current Focus
One sentence: the core matter currently being investigated.

## Rules
1. Use file paths and issue types, not full code snippets
2. No repetitive or redundant info
3. Omit any dimension with no relevant content
4. current_focus: no more than one sentence
5. Return ONLY the structured summary, no preamble"""


class ContextCompressor:
    """LLM 对话上下文压缩器。

    用法：
        compressor = ContextCompressor(llm_ask_callable)
        compressed = await compressor.compress(messages, model_name)
    """

    def __init__(self, ask_fn, max_history_tokens: int = 8000):
        """
        Args:
            ask_fn: 可调用对象，签名为 (messages: list) -> (content: str, in_tok: int, out_tok: int)
            max_history_tokens: 触发压缩的历史 token 阈值
        """
        self._ask = ask_fn
        self._max_history_tokens = max_history_tokens
        self._token_estimator = _default_token_estimator

    def should_compress(self, messages: List[Dict[str, str]]) -> bool:
        """判断是否需要进行上下文压缩。"""
        estimated = sum(self._token_estimator(m) for m in messages)
        return estimated >= self._max_history_tokens

    def compress(
        self,
        messages: List[Dict[str, str]],
    ) -> Tuple[str, int, int]:
        """
        压缩消息历史为结构化摘要。

        Returns:
            (compressed_summary_text, input_tokens, output_tokens)
        """
        history_text = _format_messages_for_compression(messages)
        compress_messages = [
            {"role": "system", "content": COMPRESSION_SYSTEM_PROMPT},
            {"role": "user", "content": f"Compress the following conversation history:\n\n{history_text}"},
        ]
        content, input_tokens, output_tokens = self._ask(compress_messages)
        return content, input_tokens, output_tokens

    def apply_compression(
        self,
        messages: List[Dict[str, str]],
        system_message: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, str]]:
        """
        压缩并重建对话，保留 system 消息 + 压缩摘要 + 最近几条最新消息。

        Args:
            messages: 完整消息历史
            system_message: 原始 system 消息（会被放在最前面）
        Returns:
            压缩后的新消息列表
        """
        summary, _, _ = self.compress(messages)

        # 保留最近 4 条（tool 结果 + assistant 响应）
        keep_tail = min(4, len(messages))
        tail = messages[-keep_tail:]

        new_messages: List[Dict[str, str]] = []
        if system_message:
            new_messages.append({
                "role": "system",
                "content": system_message["content"] + "\n\n## Context Summary\n" + summary,
            })
        else:
            new_messages.append({"role": "system", "content": summary})

        new_messages.extend(tail)
        return new_messages


def _format_messages_for_compression(messages: List[Dict[str, str]]) -> str:
    """将消息历史格式化为压缩请求的文本块。"""
    parts = []
    for i, msg in enumerate(messages):
        content = msg.get("content", "")
        if isinstance(content, dict):
            content = json.dumps(content, ensure_ascii=False)
        # 截断过长内容
        if len(content) > 3000:
            content = content[:1500] + "\n...(truncated)...\n" + content[-500:]
        parts.append(f'<message id="{i}" role="{msg.get("role", "")}">\n{content}\n</message>')
    return "\n".join(parts)


def _default_token_estimator(message: Dict[str, str]) -> int:
    """简易 token 估算（1 token ≈ 1.5 中文字符 ≈ 2 英文字符）。"""
    content = message.get("content", "")
    if isinstance(content, (list, dict)):
        content = json.dumps(content, ensure_ascii=False)
    # 中文字符约 1.5 token，英文约 0.5 token
    chinese_chars = sum(1 for c in content if "\u4e00" <= c <= "\u9fff")
    other_chars = len(content) - chinese_chars
    return int(chinese_chars * 1.5 + other_chars * 0.5) + 4  # +4 消息开销
