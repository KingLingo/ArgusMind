"""应用日志配置（根 logger + 可选文件输出）。"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

_CONFIGURED = False


def setup_logging(level: str = "INFO", log_file: Optional[Path] = None) -> None:
    """配置根 logger，使 ``src.*`` 等应用模块的 INFO 日志能输出到控制台。"""
    global _CONFIGURED
    if _CONFIGURED:
        root = logging.getLogger()
        log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)
        root.setLevel(log_level)
        return

    log_level = getattr(logging, (level or "INFO").upper(), logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)

    # 与 Uvicorn 默认日志级别对齐，避免 access/error 被根 logger 级别挡住
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(log_level)

    _CONFIGURED = True
