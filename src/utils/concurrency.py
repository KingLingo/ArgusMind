# -*- coding: utf-8 -*-
"""并发控制 —— 整合自 gbt-codeagent。

提供异步信号量和同步信号量，限制并发执行数量。
"""

from __future__ import annotations

import asyncio
import threading
from typing import Optional


class AsyncSemaphore:
    """异步信号量：限制 asyncio 并发数。"""

    def __init__(self, max_concurrency: int) -> None:
        self._max = max_concurrency
        self._current = 0
        self._waiters: list[asyncio.Future] = []

    async def acquire(self) -> None:
        if self._current < self._max:
            self._current += 1
            return
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._waiters.append(future)
        await future

    def release(self) -> None:
        if self._waiters:
            future = self._waiters.pop(0)
            future.set_result(None)
        else:
            self._current = max(0, self._current - 1)


class ThreadSemaphore:
    """线程安全信号量：限制线程并发数。"""

    def __init__(self, max_concurrency: int) -> None:
        self._max = max_concurrency
        self._current = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

    def acquire(self, timeout: Optional[float] = None) -> bool:
        with self._condition:
            while self._current >= self._max:
                if not self._condition.wait(timeout=timeout or 0):
                    return False
            self._current += 1
            return True

    def release(self) -> None:
        with self._condition:
            self._current = max(0, self._current - 1)
            self._condition.notify()
