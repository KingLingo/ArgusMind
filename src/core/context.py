"""执行上下文"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from src.config import LLMConfig, OpenCodeConfig


@dataclass
class ExecutionContext:
    task_id: str
    project_id: str
    project_name: str
    project_path: Path
    llm_config: LLMConfig
    opencode_config: Optional[OpenCodeConfig] = None
    offline_mode: bool = False
    token_budget: int = 0  # 任务级 token 预算上限；0 表示不限
    extra: Dict[str, Any] = field(default_factory=dict)
