"""数据平面：工具封装。所有工具继承 BaseTool，统一 name/description/usage、ToolResult 与 AI 可调用的 schema。"""

from src.tools.base import (
    BaseTool,
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_INVALID_ARGUMENT,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_PERMISSION_DENIED,
    ERROR_CODE_TIMEOUT,
    ERROR_CODE_UNAVAILABLE,
    ERROR_CODE_UNKNOWN,
    ToolResult,
)
from src.tools.filesystem import (
    ListFilesTool,
    ReadFileTool,
    ReadLinesTool,
)
from src.tools.ripgrep import RipgrepFilesTool, RipgrepSearchTool
from src.tools.registry import ToolRegistry, get_default_registry
from src.tools.tokei import TokeiTool

# OpenCodeTool 按需延迟加载（避免启动时 sandbox 阻断）
OpenCodeTool = None  # type: ignore[assignment]


def _get_opencode_tool():
    global OpenCodeTool
    if OpenCodeTool is None:
        try:
            from src.tools.opencode import OpenCodeTool as _OTC
            OpenCodeTool = _OTC
        except Exception:
            pass
    return OpenCodeTool


def __getattr__(name: str):
    if name == "register_neo4j_tools":
        from src.tools.neo4j_tools import register_neo4j_tools

        return register_neo4j_tools
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolRegistry",
    "get_default_registry",
    "register_neo4j_tools",
    "ERROR_CODE_INVALID_ARGUMENT",
    "ERROR_CODE_NOT_FOUND",
    "ERROR_CODE_PERMISSION_DENIED",
    "ERROR_CODE_TIMEOUT",
    "ERROR_CODE_EXTERNAL",
    "ERROR_CODE_UNKNOWN",
    "ERROR_CODE_UNAVAILABLE",
    "ReadFileTool",
    "ReadLinesTool",
    "ListFilesTool",
    "RipgrepFilesTool",
    "RipgrepSearchTool",
    "TokeiTool",
    "OpenCodeTool",
]
