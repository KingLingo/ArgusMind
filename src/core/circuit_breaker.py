# -*- coding: utf-8 -*-
"""熔断器 —— 整合自 gbt-codeagent。

防止级联故障，支持 CLOSED → OPEN → HALF_OPEN 状态转换。
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, List, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """熔断器配置。"""
    failure_threshold: int = 5
    success_threshold: int = 3
    recovery_timeout: float = 30.0  # 秒
    half_open_max_calls: int = 3
    min_samples: int = 10
    failure_rate_threshold: float = 0.5
    on_state_change: Optional[Callable[[str, CircuitState, CircuitState], None]] = None
    on_rejection: Optional[Callable[[str, CircuitState], None]] = None


class CircuitStats:
    """熔断器统计。"""

    def __init__(self, rolling_window_seconds: float = 60.0) -> None:
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.rejected_calls = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None
        self._rolling_window = rolling_window_seconds
        self._rolling_failures: List[float] = []
        self._rolling_successes: List[float] = []

    @property
    def failure_rate(self) -> float:
        return self.failed_calls / self.total_calls if self.total_calls > 0 else 0.0

    @property
    def rolling_failure_rate(self) -> float:
        total = len(self._rolling_failures) + len(self._rolling_successes)
        return len(self._rolling_failures) / total if total > 0 else 0.0

    def record_success(self) -> None:
        self.total_calls += 1
        self.successful_calls += 1
        self.consecutive_successes += 1
        self.consecutive_failures = 0
        self.last_success_time = time.time()
        self._update_rolling_window("success")

    def record_failure(self) -> None:
        self.total_calls += 1
        self.failed_calls += 1
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.last_failure_time = time.time()
        self._update_rolling_window("failure")

    def record_rejection(self) -> None:
        self.rejected_calls += 1

    def _update_rolling_window(self, result_type: str) -> None:
        now = time.time()
        if result_type == "failure":
            self._rolling_failures.append(now)
        else:
            self._rolling_successes.append(now)
        cutoff = now - self._rolling_window
        self._rolling_failures = [t for t in self._rolling_failures if t > cutoff]
        self._rolling_successes = [t for t in self._rolling_successes if t > cutoff]

    def reset(self) -> None:
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self._rolling_failures.clear()
        self._rolling_successes.clear()


class CircuitBreaker:
    """熔断器：保护下游服务。"""

    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> None:
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self.stats = CircuitStats()
        self._half_open_calls = 0
        self._last_state_change = time.time()
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.time() - self._last_state_change
                if elapsed >= self.config.recovery_timeout:
                    self._transition_to(CircuitState.HALF_OPEN)
                    self._half_open_calls = 0
            return self._state

    def call(self, fn: Callable[[], T]) -> T:
        """同步调用，受熔断器保护。"""
        current_state = self.state

        if current_state == CircuitState.OPEN:
            self.stats.record_rejection()
            if self.config.on_rejection:
                self.config.on_rejection(self.name, current_state)
            raise CircuitOpenError(f"熔断器 [{self.name}] 处于 OPEN 状态，拒绝请求")

        with self._lock:
            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self.stats.record_rejection()
                    raise CircuitOpenError(f"熔断器 [{self.name}] HALF_OPEN 已达最大试探次数")
                self._half_open_calls += 1

        try:
            result = fn()
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    async def call_async(self, fn: Callable[[], Awaitable[T]]) -> T:
        """异步调用，受熔断器保护。"""
        current_state = self.state

        if current_state == CircuitState.OPEN:
            self.stats.record_rejection()
            if self.config.on_rejection:
                self.config.on_rejection(self.name, current_state)
            raise CircuitOpenError(f"熔断器 [{self.name}] 处于 OPEN 状态，拒绝请求")

        with self._lock:
            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self.stats.record_rejection()
                    raise CircuitOpenError(f"熔断器 [{self.name}] HALF_OPEN 已达最大试探次数")
                self._half_open_calls += 1

        try:
            result = await fn()
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        self.stats.record_success()
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
                    self.stats.reset()

    def _on_failure(self) -> None:
        self.stats.record_failure()
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if (
                    self.stats.consecutive_failures >= self.config.failure_threshold
                    or (
                        self.stats.total_calls >= self.config.min_samples
                        and self.stats.rolling_failure_rate >= self.config.failure_rate_threshold
                    )
                ):
                    self._transition_to(CircuitState.OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        self._last_state_change = time.time()
        if self.config.on_state_change:
            self.config.on_state_change(self.name, old_state, new_state)
        logger.info("[熔断器] %s: %s → %s", self.name, old_state.value, new_state.value)

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self.stats.reset()
            self._half_open_calls = 0
            self._last_state_change = time.time()


class CircuitOpenError(Exception):
    """熔断器打开时抛出的异常。"""
    pass


class CircuitBreakerRegistry:
    """熔断器注册表。"""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ) -> CircuitBreaker:
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(name, config)
            return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        return self._breakers.get(name)

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        return {name: cb.stats.__dict__ for name, cb in self._breakers.items()}


_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry
