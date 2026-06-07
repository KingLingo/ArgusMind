"""
Sink Finder 混合模式配置模块

定义混合架构的配置选项和默认值。
OpenCode 作为可选增强工具，在特定场景下与原生多轮 LLM 循环协同工作。
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class SinkFinderHybridConfig:
    """混合 Sink 发现模式的配置类"""

    # ── 启用开关 ──
    enable_hybrid_mode: bool = True
    enable_opencode: bool = True

    # ── 策略选择 ──
    # parallel: 并行执行两种方式，取先完成且通过验证的结果
    # serial-enhanced: 先用原生 LLM，对不确定结果用 OpenCode 深度验证
    # divide-conquer: 按漏洞类型/文件类型分配给不同方式
    strategy_mode: str = "serial-enhanced"

    # ── 场景判断阈值（从原始 500 文件 / 10万行 降低到 50 文件 / 1万行，让混合模式真正可用）──
    complex_project_file_threshold: int = 50
    complex_project_line_threshold: int = 10000
    multilingual_threshold: int = 2  # 从 3 降到 2
    framework_threshold: int = 3  # 从 5 降到 3

    # ── OpenCode 使用条件 - 漏洞类型列表 ──
    use_opencode_for_vuln_types: List[str] = field(default_factory=lambda: [
        "sql-injection",
        "command-injection",
        "deserialization",
        "rce",
        "path-traversal-advanced",
    ])

    # ── 降级配置 ──
    opencode_timeout_sec: int = 300
    max_opencode_retries: int = 2

    # ── 结果验证 ──
    enable_result_validation: bool = True
    enable_result_merging: bool = True

    # ── 性能配置 ──
    parallel_timeout_sec: int = 600
    max_verify_sinks: int = 10

    @classmethod
    def default_config(cls) -> "SinkFinderHybridConfig":
        return cls()

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
