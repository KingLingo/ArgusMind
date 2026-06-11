# -*- coding: utf-8 -*-
"""上下文压缩策略 —— 参考 CodeScan 的自动推导机制。

根据 context_window_tokens 自动推导各级压缩阈值：
- Micro压缩：清理旧工具结果，保留最近N轮
- Full压缩：摘要压缩，保留关键信息
- Hard压缩：强制截断防溢出

用法：
    policy = ContextCompressionPolicy(context_window_tokens=128000)
    # policy.micro_limit_tokens, policy.full_limit_tokens, policy.hard_limit_tokens
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

_DEFAULT_CONTEXT_WINDOW_TOKENS = 128000
_DEFAULT_SUMMARY_WINDOW_MESSAGES = 12
_DEFAULT_MICROCOMPACT_KEEP_RECENT = 2
_DEFAULT_COMPACT_MIN_TAIL_MESSAGES = 4


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(value, hi))


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


@dataclass
class ContextCompressionPolicy:
    """上下文压缩策略：只需配置 context_window_tokens，其余阈值自动推导。

    环境变量覆盖：
      ARGUSMIND_CONTEXT_WINDOW_TOKENS   - 模型上下文窗口 token 数，默认 128000
      ARGUSMIND_SUMMARY_WINDOW_MESSAGES - 摘要保留的消息轮数，默认 12
      ARGUSMIND_MICROCOMPACT_KEEP_RECENT - Micro压缩保留最近N轮，默认 2
    """
    context_window_tokens: int = field(
        default_factory=lambda: _env_int("ARGUSMIND_CONTEXT_WINDOW_TOKENS", _DEFAULT_CONTEXT_WINDOW_TOKENS)
    )
    summary_window_messages: int = field(
        default_factory=lambda: _env_int("ARGUSMIND_SUMMARY_WINDOW_MESSAGES", _DEFAULT_SUMMARY_WINDOW_MESSAGES)
    )
    microcompact_keep_recent: int = field(
        default_factory=lambda: _env_int("ARGUSMIND_MICROCOMPACT_KEEP_RECENT", _DEFAULT_MICROCOMPACT_KEEP_RECENT)
    )
    compact_min_tail_messages: int = _DEFAULT_COMPACT_MIN_TAIL_MESSAGES

    # 自动推导的阈值（__post_init__ 计算）
    summary_reserved_tokens: int = field(init=False)
    safety_buffer_tokens: int = field(init=False)
    effective_limit_tokens: int = field(init=False)
    micro_limit_tokens: int = field(init=False)
    full_limit_tokens: int = field(init=False)
    hard_limit_tokens: int = field(init=False)
    target_after_compact_tokens: int = field(init=False)
    hard_limit_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        if self.context_window_tokens <= 0:
            self.context_window_tokens = _DEFAULT_CONTEXT_WINDOW_TOKENS

        # 摘要预留：窗口的12%，夹在 8000~20000
        self.summary_reserved_tokens = _clamp(
            self.context_window_tokens * 12 // 100, 8000, 20000
        )
        # 安全缓冲：窗口的4%，夹在 4000~12000
        self.safety_buffer_tokens = _clamp(
            self.context_window_tokens * 4 // 100, 4000, 12000
        )
        # 有效限制 = 窗口 - 摘要预留 - 安全缓冲
        self.effective_limit_tokens = max(
            1, self.context_window_tokens - self.summary_reserved_tokens - self.safety_buffer_tokens
        )
        # Micro阈值：有效限制的70%
        self.micro_limit_tokens = self.effective_limit_tokens * 70 // 100
        # Full阈值：有效限制的85%
        self.full_limit_tokens = self.effective_limit_tokens * 85 // 100
        # Hard阈值：有效限制的100%
        self.hard_limit_tokens = self.effective_limit_tokens
        # 压缩目标：有效限制的60%
        self.target_after_compact_tokens = self.effective_limit_tokens * 60 // 100
        # 字节回退阈值：token * 4（粗估 1 token ≈ 4 bytes）
        self.hard_limit_bytes = self.hard_limit_tokens * 4

    def pressure_level(self, prompt_tokens: int) -> str:
        """根据当前 prompt token 数判断压力级别。"""
        if self.hard_limit_tokens > 0 and prompt_tokens >= self.hard_limit_tokens:
            return "hard"
        if prompt_tokens >= self.full_limit_tokens:
            return "full"
        if prompt_tokens >= self.micro_limit_tokens:
            return "micro"
        return "safe"

    def needs_compaction(self, prompt_tokens: int) -> bool:
        """是否需要压缩。"""
        return self.pressure_level(prompt_tokens) != "safe"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context_window_tokens": self.context_window_tokens,
            "summary_reserved_tokens": self.summary_reserved_tokens,
            "safety_buffer_tokens": self.safety_buffer_tokens,
            "effective_limit_tokens": self.effective_limit_tokens,
            "micro_limit_tokens": self.micro_limit_tokens,
            "full_limit_tokens": self.full_limit_tokens,
            "hard_limit_tokens": self.hard_limit_tokens,
            "target_after_compact_tokens": self.target_after_compact_tokens,
            "hard_limit_bytes": self.hard_limit_bytes,
            "summary_window_messages": self.summary_window_messages,
            "microcompact_keep_recent": self.microcompact_keep_recent,
        }


# 全局单例
_default_policy: Optional[ContextCompressionPolicy] = None


def get_compression_policy() -> ContextCompressionPolicy:
    """获取全局压缩策略单例。"""
    global _default_policy
    if _default_policy is None:
        _default_policy = ContextCompressionPolicy()
    return _default_policy


def estimate_tokens_from_text(text: str) -> int:
    """粗估文本 token 数（1 token ≈ 4 bytes 中文 / 4 chars 英文）。"""
    return max(1, len(text.encode("utf-8")) // 4)


def estimate_messages_tokens(messages: List[Dict[str, str]]) -> int:
    """粗估消息列表的 token 总数。"""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += estimate_tokens_from_text(content)
        # role 等开销
        total += 4
    return total
