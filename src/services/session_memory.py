# -*- coding: utf-8 -*-
"""Session Memory 持久化服务 —— 参考 CodeScan 的 runtime_compaction.go。

功能：
1. 将对话增量摘要写入本地文件（memory.md）
2. 上下文压缩时优先使用 session memory 恢复

用法：
    memory = SessionMemory(task_id, agent_tag)
    memory.write_summary(summary)  # 写入记忆摘要
    ctx = memory.get_session_context()  # 获取格式化上下文
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _get_session_dir(task_id: str, agent_tag: str) -> Path:
    """获取 session 存储目录。"""
    import tempfile
    base = Path(tempfile.gettempdir()) / "ArgusMind" / task_id / "sessions" / agent_tag
    base.mkdir(parents=True, exist_ok=True)
    return base


class SessionMemory:
    """会话记忆持久化管理器。

    参考 CodeScan 的 session memory 机制：
    - 将对话增量摘要写入 memory.md
    - 上下文压缩时优先使用 session memory 恢复
    """

    def __init__(self, task_id: str, agent_tag: str = "default"):
        self.task_id = task_id
        self.agent_tag = agent_tag
        self._session_dir = _get_session_dir(task_id, agent_tag)
        self._memory_path = self._session_dir / "memory.md"

    def get_summary(self) -> str:
        """获取当前记忆摘要。"""
        try:
            if self._memory_path.exists():
                return self._memory_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
        return ""

    def write_summary(self, summary: str) -> None:
        """写入记忆摘要。"""
        try:
            self._memory_path.write_text(summary.strip(), encoding="utf-8")
        except Exception as e:
            logger.debug("写入 session memory 失败: %s", e)

    def get_session_context(self) -> Optional[str]:
        """获取 session memory 上下文（用于压缩时注入）。

        返回格式化的 session memory 文本，如果为空返回 None。
        """
        summary = self.get_summary()
        if not summary:
            return None
        return f"SESSION MEMORY SNAPSHOT:\n{summary}"

    def cleanup(self) -> None:
        """清理 session 文件。"""
        try:
            if self._memory_path.exists():
                self._memory_path.unlink()
            if self._session_dir.exists():
                self._session_dir.rmdir()
        except Exception:
            pass


def build_memory_update_prompt(existing_memory: str, transcript_text: str) -> str:
    """构建 session memory 更新提示词（参考 CodeScan memoryUpdatePrompt）。"""
    return f"""You are maintaining a persistent markdown session memory for an autonomous code-scanning agent.
Update the memory so a future agent can resume work without losing key context.

Output markdown only with these sections:
- Session Title
- Current State
- Task Spec
- Files and Functions
- Workflow
- Errors and Corrections
- Findings
- Next Steps
- Worklog

Current memory:
{existing_memory.strip()}

New transcript delta:
{transcript_text.strip()}"""
