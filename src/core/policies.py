"""编排策略与规则"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


@dataclass
class OrchestratorPolicy:
    """编排全局策略，支持环境变量覆盖。

    环境变量：
      ARGUSMIND_TASK_TIMEOUT_MINUTES  - 任务全局超时（分钟），0=不限时，默认 120
      ARGUSMIND_AGENT_TIMEOUT_MINUTES - 单个 Agent（SinkFinder/ChainAnalyzer）超时（分钟），0=不限时，默认 30
    """

    task_timeout_minutes: int = field(
        default_factory=lambda: _env_int("ARGUSMIND_TASK_TIMEOUT_MINUTES", 120)
    )
    agent_timeout_minutes: int = field(
        default_factory=lambda: _env_int("ARGUSMIND_AGENT_TIMEOUT_MINUTES", 30)
    )
    max_concurrent_agents: int = 1
    reuse_plan_when_exists: bool = True
    reuse_project_node_when_exists: bool = True
