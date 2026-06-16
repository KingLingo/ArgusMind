"""中间件：请求日志 + CORS"""
from __future__ import annotations

import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        response.headers["x-request-id"] = request_id
        response.headers["x-response-time"] = f"{elapsed_ms}ms"
        return response


def _get_cors_origins() -> list[str]:
    """从环境变量 CORS_ORIGINS 读取允许的来源列表（逗号分隔）。

    未设置时回退到 ["*"]（仅适用于开发环境）。
    生产环境应设置 CORS_ORIGINS=http://localhost:8000,https://your-domain.com
    """
    raw = os.getenv("CORS_ORIGINS", "").strip()
    if not raw:
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def register_middleware(app: FastAPI) -> None:
    app.add_middleware(RequestContextMiddleware)
    origins = _get_cors_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
