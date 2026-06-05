# -*- coding: utf-8 -*-
"""审计状态管理器 —— 整合自 gbt-codeagent。

管理审计 Agent 的完整生命周期状态，包括迭代计数、进度追踪、
性能统计、检查点保存/恢复等。
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AgentStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    STOPPING = "stopping"
    TIMEOUT = "timeout"


@dataclass
class ProgressInfo:
    current_step: int = 0
    total_steps: int = 0
    step_name: str = ""
    estimated_time_remaining: Optional[float] = None


@dataclass
class PerformanceInfo:
    iteration_times: List[float] = field(default_factory=list)
    avg_iteration_time: float = 0.0
    max_iteration_time: float = 0.0
    total_processing_time: float = 0.0


class AuditState:
    """审计 Agent 状态管理。"""

    def __init__(self, max_iterations: int = 50) -> None:
        self.agent_id = f"agent_{int(time.time())}_{id(self) & 0xFFFF:x}"
        self.agent_name = "ArgusMind Audit Agent"
        self.agent_type = "code-audit"

        self.task: str = ""
        self.task_context: Dict[str, Any] = {}

        self.status = AgentStatus.CREATED
        self.iteration: int = 0
        self.max_iterations = max_iterations

        self.messages: List[Dict[str, Any]] = []
        self.system_prompt: str = ""

        self.actions_taken: List[Dict[str, Any]] = []
        self.observations: List[str] = []
        self.errors: List[str] = []

        self.findings: List[Dict[str, Any]] = []

        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.last_updated = self.created_at
        self.finished_at: Optional[float] = None

        self.waiting_for_input: bool = False
        self.waiting_reason: str = ""
        self.waiting_timeout_seconds: float = 600.0

        self.final_result: Optional[Dict[str, Any]] = None

        self.total_tokens: int = 0
        self.tool_calls: int = 0

        self.stop_requested: bool = False
        self.max_iterations_warning_sent: bool = False

        self.progress = ProgressInfo()
        self.performance = PerformanceInfo()

    def start(self) -> None:
        self.status = AgentStatus.RUNNING
        self.started_at = time.time()
        self._update_timestamp()

    def increment_iteration(self, start_time: Optional[float] = None) -> None:
        self.iteration += 1

        if start_time is not None:
            iteration_time = time.time() - start_time
            self.performance.iteration_times.append(iteration_time)
            self.performance.max_iteration_time = max(
                self.performance.max_iteration_time, iteration_time
            )
            self.performance.total_processing_time += iteration_time
            if self.performance.iteration_times:
                self.performance.avg_iteration_time = (
                    self.performance.total_processing_time / len(self.performance.iteration_times)
                )

        self._update_timestamp()

        if self.iteration >= self.max_iterations and not self.max_iterations_warning_sent:
            self.max_iterations_warning_sent = True

    def update_progress(self, current_step: int, total_steps: int, step_name: str = "") -> None:
        self.progress = ProgressInfo(
            current_step=current_step,
            total_steps=total_steps,
            step_name=step_name,
            estimated_time_remaining=self._calculate_estimated_time(current_step, total_steps),
        )
        self._update_timestamp()

    def _calculate_estimated_time(self, current_step: int, total_steps: int) -> Optional[float]:
        if current_step == 0 or self.performance.avg_iteration_time == 0:
            return None
        remaining = total_steps - current_step
        return remaining * self.performance.avg_iteration_time

    def get_duration(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return end - self.started_at

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)
        self._update_timestamp()

    def add_error(self, error: str) -> None:
        self.errors.append(error)
        self._update_timestamp()

    def add_action(self, action: Dict[str, Any]) -> None:
        self.actions_taken.append(action)
        self._update_timestamp()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.status = AgentStatus.STOPPING
        self._update_timestamp()

    def complete(self, result: Optional[Dict[str, Any]] = None) -> None:
        self.status = AgentStatus.COMPLETED
        self.finished_at = time.time()
        self.final_result = result
        self._update_timestamp()

    def fail(self, error: str = "") -> None:
        self.status = AgentStatus.FAILED
        self.finished_at = time.time()
        if error:
            self.errors.append(error)
        self._update_timestamp()

    def pause(self, reason: str = "") -> None:
        self.status = AgentStatus.PAUSED
        self.waiting_for_input = True
        self.waiting_reason = reason
        self._update_timestamp()

    def resume(self) -> None:
        self.status = AgentStatus.RUNNING
        self.waiting_for_input = False
        self.waiting_reason = ""
        self._update_timestamp()

    def checkpoint(self) -> Dict[str, Any]:
        """生成检查点快照。"""
        return {
            "agent_id": self.agent_id,
            "status": self.status.value,
            "iteration": self.iteration,
            "findings": list(self.findings),
            "errors": list(self.errors),
            "total_tokens": self.total_tokens,
            "tool_calls": self.tool_calls,
            "progress": {
                "current_step": self.progress.current_step,
                "total_steps": self.progress.total_steps,
                "step_name": self.progress.step_name,
            },
            "performance": {
                "avg_iteration_time": self.performance.avg_iteration_time,
                "max_iteration_time": self.performance.max_iteration_time,
                "total_processing_time": self.performance.total_processing_time,
            },
            "timestamp": time.time(),
        }

    def restore(self, data: Dict[str, Any]) -> None:
        """从检查点恢复。"""
        self.agent_id = data.get("agent_id", self.agent_id)
        self.status = AgentStatus(data.get("status", "created"))
        self.iteration = data.get("iteration", 0)
        self.findings = data.get("findings", [])
        self.errors = data.get("errors", [])
        self.total_tokens = data.get("total_tokens", 0)
        self.tool_calls = data.get("tool_calls", 0)

        progress_data = data.get("progress", {})
        self.progress.current_step = progress_data.get("current_step", 0)
        self.progress.total_steps = progress_data.get("total_steps", 0)
        self.progress.step_name = progress_data.get("step_name", "")

        perf_data = data.get("performance", {})
        self.performance.avg_iteration_time = perf_data.get("avg_iteration_time", 0.0)
        self.performance.max_iteration_time = perf_data.get("max_iteration_time", 0.0)
        self.performance.total_processing_time = perf_data.get("total_processing_time", 0.0)

    def _update_timestamp(self) -> None:
        self.last_updated = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "status": self.status.value,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "findings_count": len(self.findings),
            "errors_count": len(self.errors),
            "total_tokens": self.total_tokens,
            "tool_calls": self.tool_calls,
            "duration": self.get_duration(),
            "progress": {
                "current_step": self.progress.current_step,
                "total_steps": self.progress.total_steps,
                "step_name": self.progress.step_name,
            },
        }
