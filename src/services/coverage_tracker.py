# -*- coding: utf-8 -*-
"""审计覆盖率追踪器 —— 整合自 gbt-codeagent/services/coverageService.js。

追踪哪些文件和攻击类型已被审查，发现盲区并生成定向审查任务。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# 代码文件扩展名
_CODE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".rs", ".kt",
    ".scala", ".swift", ".m", ".vue", ".svelte",
}


def _normalize_path(p: str) -> str:
    """统一路径分隔符为 /，去除首尾空白。"""
    return p.strip().replace("\\", "/")


def _is_code_file(path: str) -> bool:
    """判断是否为代码文件。"""
    ext = os.path.splitext(path)[1].lower()
    return ext in _CODE_EXTENSIONS


def _extract_subsystem(path: str) -> str:
    """从文件路径提取子系统（前两级目录）。"""
    parts = _normalize_path(path).split("/")
    # 跳过 src / app 等常见顶层目录
    skip = {"src", "app", "lib", "pkg", "internal", "cmd", "web", "server", "client"}
    meaningful = [p for p in parts[:-1] if p and p not in skip]
    return "/".join(meaningful[:2]) if meaningful else "root"


# 已知的攻击类型清单
ALL_ATTACK_CLASSES: List[str] = [
    "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "DESERIALIZATION",
    "XSS", "SSRF", "XXE", "PATH_TRAVERSAL", "AUTH_BYPASS", "IDOR",
    "HARD_CODED_SECRET", "WEAK_CRYPTO", "INFO_LEAK", "FILE_UPLOAD",
    "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "SESSION_FIXATION",
    "CORS_MISCONFIGURATION", "OPEN_REDIRECT", "LOG_INJECTION", "REDOS",
]

# 扩展名 → 适用的攻击类型
_EXTENSION_ATTACK_CLASSES: Dict[str, List[str]] = {
    ".java": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "SSRF", "XXE",
              "AUTH_BYPASS", "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "IDOR"],
    ".py": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "PATH_TRAVERSAL",
            "SSRF", "SSTI", "CODE_INJECTION"],
    ".js": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
            "SSRF", "CODE_INJECTION", "PROTOTYPE_POLLUTION"],
    ".ts": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
            "SSRF", "CODE_INJECTION"],
    ".go": ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION"],
    ".php": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL",
             "FILE_UPLOAD", "DESERIALIZATION"],
    ".cs": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "XSS", "AUTH_BYPASS"],
    ".cpp": ["COMMAND_INJECTION", "BUFFER_OVERFLOW", "PATH_TRAVERSAL", "CODE_INJECTION"],
    ".c": ["COMMAND_INJECTION", "BUFFER_OVERFLOW", "PATH_TRAVERSAL", "CODE_INJECTION"],
}

# Sink 关键词映射（用于盲区搜索）
_SINK_KEYWORDS: Dict[str, List[str]] = {
    "SQL_INJECTION": ["executeQuery", "executeUpdate", "createQuery", "Statement",
                      "PreparedStatement", "JdbcTemplate", "query("],
    "COMMAND_INJECTION": ["Runtime.getRuntime", "ProcessBuilder", "exec(",
                          "ProcessImpl", "os.system", "subprocess"],
    "DESERIALIZATION": ["readObject", "ObjectInputStream", "Yaml.load",
                        "parseObject", "readValue", "fromJson", "pickle.load"],
    "PATH_TRAVERSAL": ["FileInputStream", "FileOutputStream", "File(",
                       "Files.read", "Paths.get", "os.path.join"],
    "SSRF": ["HttpClient", "RestTemplate", "URL.openConnection",
             "fetch(", "WebClient", "requests.get"],
    "SSTI": ["Thymeleaf", "templateEngine", "process(",
             "FreeMarker", "Velocity", "Jinja2"],
    "JNDI_INJECTION": ["InitialContext", "lookup(", "JNDI"],
}

# Tier 分类正则
_T1_PATTERNS = [re.compile(p, re.I) for p in
                [r"controller", r"filter", r"interceptor", r"gateway",
                 r"securityconfig", r"webconfig", r"route", r"router"]]
_T2_PATTERNS = [re.compile(p, re.I) for p in
                [r"service", r"dao", r"mapper", r"repository", r"util",
                 r"helper", r"manager", r"handler", r"config", r"business",
                 r"core", r"common"]]
_T3_PATTERNS = [re.compile(p, re.I) for p in
                [r"entity", r"dto", r"vo", r"pojo", r"model", r"domain",
                 r"bean", r"object"]]

# 高信号文件模式
_HIGH_SIGNAL_PATTERN = re.compile(
    r"(controller|service|dao|repository|handler|route|auth|security|admin|api|endpoint|upload|file|config|util)",
    re.I,
)


def _classify_tier(file_path: str) -> str:
    """将文件按重要性分为 T1/T2/T3。"""
    lower = file_path.lower()
    for p in _T1_PATTERNS:
        if p.search(lower):
            return "T1"
    for p in _T2_PATTERNS:
        if p.search(lower):
            return "T2"
    for p in _T3_PATTERNS:
        if p.search(lower):
            return "T3"
    return "T2"  # 默认 T2


class CoverageTracker:
    """审计覆盖率追踪器。

    追踪哪些文件被审查、哪些攻击类型被检查，
    并可生成覆盖率报告和盲区定向审查任务。

    增强功能（整合自 gbt-codeagent coverageService.js）：
    - 子系统覆盖率统计
    - 盲区计算（子系统 × 攻击类型矩阵）
    - Tier 分类（T1/T2/T3）
    - Sink 关键词搜索定向任务
    """

    def __init__(self, project_path: str, all_files: Optional[List[str]] = None) -> None:
        self._project_path = project_path
        self._reviewed_files: Set[str] = set()
        self._file_attack_classes: Dict[str, Set[str]] = {}
        self._all_files: Set[str] = set()

        if all_files:
            for f in all_files:
                self._all_files.add(_normalize_path(f))

    def mark_reviewed(self, file_path: str, attack_class: str = "") -> None:
        """标记文件已被审查。"""
        key = _normalize_path(file_path)
        self._reviewed_files.add(key)
        if attack_class:
            self._file_attack_classes.setdefault(key, set()).add(attack_class)

    def mark_from_findings(self, findings: List[Dict[str, Any]]) -> None:
        """从发现列表批量标记。"""
        for f in findings:
            # 优先用 file（纯路径），其次从 location 中剥离行号
            file_path = f.get("file", "")
            if not file_path:
                location = f.get("location", "")
                if ":" in location:
                    file_path = location.rsplit(":", 1)[0]
                else:
                    file_path = location
            vuln_class = f.get("vulnType", f.get("vuln_class", f.get("category_name", "")))
            if file_path:
                self.mark_reviewed(file_path, vuln_class)

    def generate_report(self) -> Dict[str, Any]:
        """生成覆盖率报告。"""
        total_files = len(self._all_files) if self._all_files else 0
        # 按 _all_files 统计实际审查过的文件数（而非 _reviewed_files 总数）
        reviewed = [f for f in self._all_files if f in self._reviewed_files]
        reviewed_count = len(reviewed)

        unreviewed_files = [f for f in self._all_files if f not in self._reviewed_files]
        unreviewed_code_files = [f for f in unreviewed_files if _is_code_file(f)]

        # 按子系统分组统计
        subsystem_coverage: Dict[str, Dict[str, int]] = {}
        for f in self._all_files:
            subsys = _extract_subsystem(f)
            if subsys not in subsystem_coverage:
                subsystem_coverage[subsys] = {"total": 0, "reviewed": 0}
            subsystem_coverage[subsys]["total"] += 1
            if _normalize_path(f) in self._reviewed_files:
                subsystem_coverage[subsys]["reviewed"] += 1

        # 按子系统分组未审查文件
        subsystem_gaps: Dict[str, List[str]] = {}
        for f in unreviewed_code_files:
            subsys = _extract_subsystem(f)
            subsystem_gaps.setdefault(subsys, []).append(f)

        # 收集已审查的攻击类型
        reviewed_attack_classes: Set[str] = set()
        for classes in self._file_attack_classes.values():
            reviewed_attack_classes.update(classes)

        # 识别高优先级未审查文件
        high_priority_unreviewed = [
            f for f in unreviewed_code_files
            if _HIGH_SIGNAL_PATTERN.search(f)
        ][:20]

        # Tier 分类统计
        tier_stats: Dict[str, int] = {"T1": 0, "T2": 0, "T3": 0}
        for f in unreviewed_code_files:
            tier = _classify_tier(f)
            tier_stats[tier] = tier_stats.get(tier, 0) + 1

        coverage_rate = (reviewed_count / total_files * 100) if total_files > 0 else 0.0

        return {
            "total_files": total_files,
            "reviewed_files": reviewed_count,
            "unreviewed_code_files": len(unreviewed_code_files),
            "coverage_rate": round(coverage_rate, 1),
            "reviewed_attack_classes": sorted(reviewed_attack_classes),
            "subsystem_coverage": {
                k: v for k, v in sorted(
                    subsystem_coverage.items(), key=lambda x: -x[1]["total"]
                )
            },
            "subsystem_gaps": {
                k: len(v) for k, v in sorted(
                    subsystem_gaps.items(), key=lambda x: -len(x[1])
                )
            },
            "top_unreviewed": unreviewed_code_files[:20],
            "high_priority_unreviewed": high_priority_unreviewed,
            "tier_stats": tier_stats,
        }

    def compute_blind_spots(
        self,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, str]]:
        """计算盲区：哪些子系统 × 攻击类型从未被检查。"""
        findings = findings or []
        report = self.generate_report()
        spots: List[Dict[str, str]] = []
        seen_keys: Set[str] = set()

        # 收集已覆盖的子系统
        reviewed_subsystems = set(report.get("subsystem_coverage", {}).keys())
        if not reviewed_subsystems:
            for f in findings:
                file_path = f.get("location", f.get("file", ""))
                reviewed_subsystems.add(_extract_subsystem(file_path))

        # 对每个子系统，找从未检查的攻击类型
        for sub in reviewed_subsystems:
            checked_classes: Set[str] = set()
            for f in findings:
                f_sub = _extract_subsystem(f.get("location", f.get("file", "")))
                f_type = f.get("vulnType", f.get("vuln_class", f.get("category_name", "")))
                if f_sub == sub and f_type:
                    checked_classes.add(f_type)

            for ac in ALL_ATTACK_CLASSES:
                key = f"{sub}|{ac}"
                if ac not in checked_classes and key not in seen_keys:
                    seen_keys.add(key)
                    spots.append({
                        "subsystem": sub,
                        "attackClass": ac,
                        "reason": "never_checked",
                    })

        # 对完全未审查的高优先级文件找可能适用的攻击类型
        for file_path in report.get("high_priority_unreviewed", [])[:5]:
            sub = _extract_subsystem(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            relevant_classes = _EXTENSION_ATTACK_CLASSES.get(ext, [])
            for ac in relevant_classes:
                key = f"{sub}|{ac}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    spots.append({
                        "subsystem": sub,
                        "attackClass": ac,
                        "targetFile": file_path,
                        "reason": "unreviewed_file",
                    })

        return spots[:20]

    def generate_gapfill_tasks(
        self,
        max_tasks: int = 5,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """基于覆盖盲区生成定向审查任务（增强版）。

        整合自 gbt-codeagent 的 enhancedGapfill：
        1. 计算盲区
        2. 在未审查文件中搜索 sink 关键词
        3. 生成定向审查任务
        """
        findings = findings or []
        blind_spots = self.compute_blind_spots(findings)
        tasks: List[Dict[str, Any]] = []

        report = self.generate_report()
        unreviewed_files = report.get("high_priority_unreviewed", [])

        for spot in blind_spots[:max_tasks]:
            attack_class = spot.get("attackClass", "")
            keywords = _SINK_KEYWORDS.get(attack_class, [])
            if not keywords:
                # 无 sink 关键词的盲区，生成通用审查任务
                tasks.append({
                    "type": "blind_spot",
                    "subsystem": spot.get("subsystem", ""),
                    "attack_class": attack_class,
                    "reason": f"子系统 {spot.get('subsystem', '')} 的 {attack_class} 从未被审查",
                    "priority": 2,
                })
                continue

            # 在未审查文件中搜索 sink 关键词
            target_files = [spot.get("targetFile", "")] if spot.get("targetFile") else unreviewed_files[:10]
            for file_path in target_files:
                if not file_path or len(tasks) >= max_tasks:
                    break
                full_path = os.path.join(self._project_path, file_path)
                try:
                    content = Path(full_path).read_text(encoding="utf-8", errors="replace")
                    for kw in keywords:
                        if kw in content:
                            lines = content.split("\n")
                            line_idx = next(
                                (i for i, l in enumerate(lines) if kw in l), -1
                            )
                            tasks.append({
                                "type": "gapfill",
                                "attack_class": attack_class,
                                "subsystem": spot.get("subsystem", ""),
                                "target_files": [file_path],
                                "scope_hint": (
                                    f"盲区: {spot.get('subsystem', '')} 的 {attack_class} "
                                    f"从未被审查。发现潜在sink: {kw}"
                                ),
                                "rationale": (
                                    f"覆盖盲区发现: 文件 {file_path}:"
                                    f"{line_idx + 1 if line_idx >= 0 else '?'} "
                                    f"含有关键字 \"{kw}\"，但 {attack_class} "
                                    f"攻击类型尚未在此子系统中被审查"
                                ),
                                "priority": 2,
                            })
                            break  # 每个文件每个攻击类型只生成一个任务
                except Exception:
                    pass
                if len(tasks) >= max_tasks:
                    break

        # 如果没有找到 sink 关键词匹配，退回到子系统缺口任务
        if not tasks:
            for subsys, count in report.get("subsystem_gaps", {}).items():
                if len(tasks) >= max_tasks:
                    break
                if count > 0:
                    tasks.append({
                        "type": "subsystem_gap",
                        "subsystem": subsys,
                        "unreviewed_count": count,
                        "reason": f"子系统 {subsys} 有 {count} 个代码文件未被审查",
                        "priority": 3,
                    })

        return tasks

    def format_report_markdown(self) -> str:
        """生成覆盖率报告的 Markdown 文本。"""
        report = self.generate_report()
        lines = [
            "## 审计覆盖率报告",
            "",
            "| 指标 | 值 |",
            "|------|-----|",
            f"| 项目文件总数 | {report['total_files']} |",
            f"| 已审查文件 | {report['reviewed_files']} |",
            f"| 未审查代码文件 | {report['unreviewed_code_files']} |",
            f"| 覆盖率 | {report['coverage_rate']}% |",
            "",
        ]

        # Tier 统计
        tier_stats = report.get("tier_stats", {})
        if tier_stats:
            lines.append("### 未审查文件 Tier 分布")
            lines.append(f"- T1 (Controller/Filter/Interceptor): {tier_stats.get('T1', 0)}")
            lines.append(f"- T2 (Service/Util/Config): {tier_stats.get('T2', 0)}")
            lines.append(f"- T3 (Entity/DTO/Model): {tier_stats.get('T3', 0)}")
            lines.append("")

        if report["reviewed_attack_classes"]:
            lines.append("### 已检查的攻击类型")
            for cls in report["reviewed_attack_classes"]:
                lines.append(f"- {cls}")
            lines.append("")

        if report["subsystem_gaps"]:
            lines.append("### 未覆盖子系统")
            lines.append("| 子系统 | 未审查文件数 |")
            lines.append("|--------|-------------|")
            for subsys, count in report["subsystem_gaps"].items():
                lines.append(f"| {subsys} | {count} |")

        return "\n".join(lines)
