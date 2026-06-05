# -*- coding: utf-8 -*-
"""重试机制 —— 整合自 gbt-codeagent。

指数退避重试，支持抖动、可重试错误判定、降级回退。
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

DEFAULT_RETRYABLE_ERRORS: List[str] = [
    "ECONNRESET",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "socket hang up",
    "network error",
    "rate limit",
    "429",
    "503",
    "504",
]

DEFAULT_RETRYABLE_STATUS_CODES: List[int] = [429, 500, 502, 503, 504]


@dataclass
class RetryConfig:
    """重试配置。"""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_factor: float = 0.5
    retryable_errors: List[str] = field(default_factory=lambda: list(DEFAULT_RETRYABLE_ERRORS))
    retryable_status_codes: List[int] = field(default_factory=lambda: list(DEFAULT_RETRYABLE_STATUS_CODES))
    max_total_delay: Optional[float] = None
    on_retry: Optional[Callable[[Exception, int, int, float], None]] = None
    on_fail: Optional[Callable[[Exception, int, int], None]] = None


def is_retryable(error: Exception, config: Optional[RetryConfig] = None) -> bool:
    """判断错误是否可重试。"""
    cfg = config or RetryConfig()
    error_str = str(error).lower()

    for pattern in cfg.retryable_errors:
        if pattern.lower() in error_str:
            return True

    status_code = getattr(error, "status_code", None) or getattr(error, "statusCode", None)
    if status_code and status_code in cfg.retryable_status_codes:
        return True

    response = getattr(error, "response", None)
    if response:
        resp_status = getattr(response, "status_code", None) or getattr(response, "status", None)
        if resp_status and resp_status in cfg.retryable_status_codes:
            return True

    return False


def calculate_delay(attempt: int, config: Optional[RetryConfig] = None) -> float:
    """计算第 N 次重试的延迟时间（秒）。"""
    cfg = config or RetryConfig()
    delay = cfg.base_delay * (cfg.exponential_base ** attempt)
    delay = min(delay, cfg.max_delay)

    if cfg.jitter:
        jitter_range = delay * cfg.jitter_factor
        delay += random.uniform(-jitter_range, jitter_range)

    return max(0.0, delay)


def with_retry(
    fn: Callable[[], T],
    config: Optional[RetryConfig] = None,
) -> T:
    """同步重试包装。"""
    cfg = config or RetryConfig()
    last_error: Optional[Exception] = None
    total_delay = 0.0

    for attempt in range(cfg.max_attempts):
        try:
            return fn()
        except Exception as e:
            last_error = e

            if attempt == cfg.max_attempts - 1:
                if cfg.on_fail:
                    cfg.on_fail(e, attempt + 1, cfg.max_attempts)
                break

            if not is_retryable(e, cfg):
                raise

            delay = calculate_delay(attempt, cfg)

            if cfg.max_total_delay and total_delay + delay > cfg.max_total_delay:
                if cfg.on_fail:
                    cfg.on_fail(e, attempt + 1, cfg.max_attempts)
                raise last_error

            total_delay += delay

            if cfg.on_retry:
                cfg.on_retry(e, attempt + 1, cfg.max_attempts, delay)
            else:
                logger.info("[重试] 第 %d 次失败，%.0fms 后重试...", attempt + 1, delay * 1000)

            time.sleep(delay)

    if last_error is not None:
        raise last_error
    raise RuntimeError("with_retry: 不可达状态")


async def with_retry_async(
    fn: Callable[[], Awaitable[T]],
    config: Optional[RetryConfig] = None,
) -> T:
    """异步重试包装。"""
    cfg = config or RetryConfig()
    last_error: Optional[Exception] = None
    total_delay = 0.0

    for attempt in range(cfg.max_attempts):
        try:
            return await fn()
        except Exception as e:
            last_error = e

            if attempt == cfg.max_attempts - 1:
                if cfg.on_fail:
                    cfg.on_fail(e, attempt + 1, cfg.max_attempts)
                break

            if not is_retryable(e, cfg):
                raise

            delay = calculate_delay(attempt, cfg)

            if cfg.max_total_delay and total_delay + delay > cfg.max_total_delay:
                if cfg.on_fail:
                    cfg.on_fail(e, attempt + 1, cfg.max_attempts)
                raise last_error

            total_delay += delay

            if cfg.on_retry:
                cfg.on_retry(e, attempt + 1, cfg.max_attempts, delay)
            else:
                logger.info("[重试] 第 %d 次失败，%.0fms 后重试...", attempt + 1, delay * 1000)

            await asyncio.sleep(delay)

    if last_error is not None:
        raise last_error
    raise RuntimeError("with_retry_async: 不可达状态")


def with_retry_with_fallback(
    fn: Callable[[], T],
    fallback_fn: Callable[[Exception], T],
    config: Optional[RetryConfig] = None,
) -> T:
    """同步重试 + 降级回退。"""
    try:
        return with_retry(fn, config)
    except Exception as e:
        logger.info("[重试] 所有重试失败，执行降级方案...")
        return fallback_fn(e)
