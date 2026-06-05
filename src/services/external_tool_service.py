# -*- coding: utf-8 -*-
"""外部工具集成服务 —— 整合自 gbt-codeagent/services/externalToolService.js。

支持集成：
- Gitleaks: 密钥和敏感信息检测
- Bandit: Python 代码安全分析
- Semgrep: 多语言静态分析

在 QuickScanService 中被调用，增强快速扫描能力。
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from src.knowledge.audit_config import detect_language
from src.knowledge.gbt_standards import VULN_GBT_MAP

logger = logging.getLogger(__name__)


def _kill_process_tree(pid: int) -> None:
    """在 Windows 上通过 taskkill /T 杀死整个进程树。"""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


# === Bandit test_id → 漏洞类型映射 ===

_BANDIT_VULN_TYPE_MAP: Dict[str, str] = {
    "B101": "ASSERT_STATEMENT",
    "B102": "EXEC_STATEMENT",
    "B103": "INSECURE_FILE_PERMISSIONS",
    "B104": "HARDCODED_BIND_ADDRESS",
    "B105": "HARD_CODED_PASSWORD",
    "B106": "HARD_CODED_PASSWORD",
    "B107": "HARD_CODED_PASSWORD",
    "B108": "INSECURE_TEMP_FILE",
    "B110": "EXCEPT_PASS",
    "B112": "EXCEPT_PASS",
    "B113": "REQUEST_WITHOUT_TIMEOUT",
    "B201": "FLASK_DEBUG_TRUE",
    "B301": "INSECURE_UNPICKLE",
    "B302": "INSECURE_MARSHAL",
    "B303": "WEAK_CRYPTO_MD5",
    "B304": "WEAK_CRYPTO_CIPHER",
    "B305": "WEAK_CRYPTO_CIPHER",
    "B306": "INSECURE_HASH_SHA1",
    "B307": "DANGEROUS_EVAL",
    "B308": "INSECURE_YAML_LOAD",
    "B310": "INSECURE_URL_OPEN",
    "B311": "WEAK_RANDOM",
    "B312": "TELNET_USAGE",
    "B313": "WEAK_CRYPTO_XML",
    "B321": "FTP_USAGE",
    "B322": "BUILTIN_OPEN",
    "B323": "UNSAFE_XSLT",
    "B324": "WEAK_HASH",
    "B401": "INSECURE_IMPORT",
    "B501": "REQUEST_WITHOUT_TIMEOUT",
    "B502": "SSL_INSECURE",
    "B503": "SSL_WEAK",
    "B506": "INSECURE_YAML_LOAD",
    "B507": "SSH_NO_HOST_VERIFY",
    "B601": "PARAMETERIZED_COMMAND",
    "B602": "SUBPROCESS_SHELL_TRUE",
    "B603": "SUBPROCESS_WITHOUT_SHELL",
    "B605": "OS_STARTFILE_WITH_SHELL",
    "B606": "START_PROCESS_WITH_SHELL",
    "B607": "START_PROCESS_WITH_PARTIAL_PATH",
    "B608": "HARDCODED_SQL",
    "B609": "LINUX_COMMAND_WILDCARD_INJECTION",
    "B610": "DJANGO_EXTRA",
    "B611": "DJANGO_RAW_SQL",
    "B701": "JINJA2_AUTOESCAPE_DISABLED",
    "B702": "TARFILE_UNSAFE_EXTRACTION",
    "B703": "MARKUPSAFE_UNSAFE",
}

# Bandit test_id → GB/T 映射
_BANDIT_GBT_MAP: Dict[str, str] = {
    "B608": "GB/T34944-6.1.2.1 SQL注入",
    "B601": "GB/T34944-6.1.1.6 命令注入",
    "B602": "GB/T34944-6.1.1.6 命令注入",
    "B606": "GB/T34944-6.1.1.6 命令注入",
    "B307": "GB/T34944-6.1.1.7 代码注入",
    "B105": "GB/T39412-6.1.1.10 硬编码敏感信息",
    "B106": "GB/T39412-6.1.1.10 硬编码敏感信息",
    "B107": "GB/T39412-6.1.1.10 硬编码敏感信息",
    "B301": "GB/T34944-6.1.3.2 不安全反序列化",
    "B303": "GB/T34944-6.3.3.1 弱加密",
    "B324": "GB/T34944-6.3.3.1 弱哈希",
    "B311": "GB/T34944-6.3.3.2 不安全随机数",
    "B506": "GB/T34944-6.1.3.2 不安全YAML加载",
}


def _run_command(
    command: str,
    timeout: int = 30,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """执行外部命令，返回 stdout/stderr/returncode。"""
    try:
        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)
        # 使用 Popen 代替 subprocess.run，以便在超时时完整杀死进程树
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=merged_env,
            shell=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            stdout, stderr = proc.communicate()
            return {"stdout": stdout or "", "stderr": f"命令执行超时: {command}", "returncode": -1}
        return {
            "stdout": stdout or "",
            "stderr": stderr or "",
            "returncode": proc.returncode,
        }
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"命令未找到: {command}", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _severity_label(severity: str) -> str:
    mapping = {"high": "高危", "medium": "中危", "low": "低危", "critical": "严重"}
    return mapping.get(severity, "中危")


def _map_bandit_severity(severity: str) -> str:
    mapping = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    return mapping.get(severity, "medium")


def _map_semgrep_severity(severity: str) -> str:
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return mapping.get(severity, "medium")


def _extract_cwe(message: str) -> str:
    """从消息中提取 CWE 编号。"""
    import re
    match = re.search(r"CWE-(\d+)", message)
    return f"CWE-{match.group(1)}" if match else "CWE-unknown"


def _detect_language_from_path(file_path: str) -> str:
    """从文件路径推断语言。"""
    ext = os.path.splitext(file_path)[1].lower()
    mapping = {
        ".py": "python", ".java": "java", ".js": "javascript",
        ".ts": "typescript", ".go": "go", ".c": "c",
        ".cpp": "cpp", ".h": "cpp", ".cs": "csharp",
        ".php": "php", ".rb": "ruby", ".rs": "rust",
    }
    return mapping.get(ext, "unknown")


class ExternalToolService:
    """外部工具集成服务。

    在 QuickScanService.scan_project() 中被调用：
    - scan_all() 返回外部工具扫描结果
    - 结果与规则扫描结果合并，统一进入 CandidateFilter 筛选
    """

    def __init__(self) -> None:
        self._tool_status: Dict[str, bool] = {}

    def check_tool_installed(self, tool_name: str) -> bool:
        """检查工具是否已安装。"""
        check_commands = {
            "gitleaks": "gitleaks version",
            "bandit": "bandit --version",
            "semgrep": "semgrep --version",
        }
        command = check_commands.get(tool_name)
        if not command:
            return False

        result = _run_command(command, timeout=5)
        installed = result["returncode"] == 0
        self._tool_status[tool_name] = installed
        return installed

    def check_all_tools(self) -> Dict[str, bool]:
        """检查所有工具安装状态。"""
        for tool in ("gitleaks", "bandit", "semgrep"):
            if tool not in self._tool_status:
                self.check_tool_installed(tool)
        return dict(self._tool_status)

    def scan_with_gitleaks(self, project_root: str) -> List[Dict[str, Any]]:
        """使用 Gitleaks 扫描密钥。"""
        findings: List[Dict[str, Any]] = []

        if not self.check_tool_installed("gitleaks"):
            logger.info("Gitleaks 未安装，跳过密钥扫描")
            return findings

        with tempfile.TemporaryDirectory(prefix="gitleaks-") as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            command = (
                f'gitleaks detect --source "{project_root}" '
                f'--report-path "{report_path}" --report-format json --no-git'
            )

            # Gitleaks 找到密钥时返回 exit code 1，这是正常行为
            result = _run_command(command, timeout=120)

            if os.path.isfile(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        report = json.load(f)
                    for item in report:
                        file_path = item.get("File", "")
                        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
                        findings.append({
                            "source": "external_tool",
                            "tool_name": "Gitleaks",
                            "vuln_id": "SECRET_DETECTION",
                            "title": f"发现敏感信息：{item.get('RuleID', 'unknown')}",
                            "severity": "high",
                            "confidence": 0.9,
                            "location": f"{rel_path}:{item.get('StartLine', 1)}",
                            "file": rel_path,
                            "line": item.get("StartLine", 1),
                            "vuln_type": "HARD_CODED_SECRET",
                            "cwe": "CWE-798",
                            "language": "unknown",
                            "gbt_mapping": "GB/T39412-6.1.1.10 硬编码敏感信息",
                            "cvss_score": 8.5,
                            "evidence": f"在 {rel_path}:{item.get('StartLine', 1)} "
                                        f"发现 {item.get('RuleID', '')} 类型的敏感信息",
                            "impact_description": "可能导致未授权访问、数据泄露或系统被入侵",
                            "remediation": "立即删除硬编码的敏感信息，使用环境变量或密钥管理服务",
                            "code_snippet": item.get("Secret", item.get("Match", "")),
                            "status": "待验证",
                        })
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Gitleaks 报告解析失败: {e}")

        return findings

    def scan_with_bandit(self, project_root: str) -> List[Dict[str, Any]]:
        """使用 Bandit 扫描 Python 代码。"""
        findings: List[Dict[str, Any]] = []

        if not self.check_tool_installed("bandit"):
            logger.info("Bandit 未安装，跳过 Python 安全扫描")
            return findings

        with tempfile.TemporaryDirectory(prefix="bandit-") as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            command = f'bandit -r "{project_root}" -f json -o "{report_path}"'
            result = _run_command(command, timeout=120)

            if os.path.isfile(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        report = json.load(f)
                    for item in report.get("results", []):
                        severity = _map_bandit_severity(item.get("issue_severity", "MEDIUM"))
                        test_id = item.get("test_id", "")
                        filename = item.get("filename", "")
                        rel_path = os.path.relpath(filename, project_root).replace("\\", "/")
                        findings.append({
                            "source": "external_tool",
                            "tool_name": "Bandit",
                            "vuln_id": test_id,
                            "title": item.get("issue_text", "Python 安全问题"),
                            "severity": severity,
                            "confidence": 0.85,
                            "location": f"{rel_path}:{item.get('line_number', 1)}",
                            "file": rel_path,
                            "line": item.get("line_number", 1),
                            "vuln_type": _BANDIT_VULN_TYPE_MAP.get(test_id, "UNKNOWN"),
                            "cwe": f"CWE-{item.get('issue_cwe', {}).get('id', 'unknown')}",
                            "language": "python",
                            "gbt_mapping": _BANDIT_GBT_MAP.get(
                                test_id,
                                VULN_GBT_MAP.get(
                                    _BANDIT_VULN_TYPE_MAP.get(test_id, ""),
                                    "GB/T39412-6.1.1.1 输入验证不足"
                                ),
                            ),
                            "cvss_score": 8.5 if severity == "high" else (5.5 if severity == "medium" else 3.0),
                            "evidence": f"在 {rel_path}:{item.get('line_number', 1)} "
                                        f"发现 {item.get('issue_text', '')}",
                            "impact_description": item.get("issue_text", ""),
                            "remediation": f"参考 Bandit 建议：{item.get('more_info', '请查阅相关安全编码规范')}",
                            "code_snippet": (item.get("code") or {}).get("raw", ""),
                            "status": "待验证",
                        })
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Bandit 报告解析失败: {e}")

        return findings

    def scan_with_semgrep(self, project_root: str) -> List[Dict[str, Any]]:
        """使用 Semgrep 扫描多语言代码。"""
        findings: List[Dict[str, Any]] = []

        if not self.check_tool_installed("semgrep"):
            logger.info("Semgrep 未安装，跳过多语言静态分析")
            return findings

        with tempfile.TemporaryDirectory(prefix="semgrep-") as temp_dir:
            report_path = os.path.join(temp_dir, "report.json")
            command = f'semgrep --json --output "{report_path}" "{project_root}"'
            env = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
            result = _run_command(command, timeout=300, env=env)

            if os.path.isfile(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        report = json.load(f)
                    for item in report.get("results", []):
                        severity = _map_semgrep_severity(item.get("severity", "WARNING"))
                        file_path = item.get("path", "")
                        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
                        check_id = item.get("check_id", "")
                        message = item.get("message", "")
                        findings.append({
                            "source": "external_tool",
                            "tool_name": "Semgrep",
                            "vuln_id": check_id,
                            "title": message,
                            "severity": severity,
                            "confidence": 0.85,
                            "location": f"{rel_path}:{item.get('start', {}).get('line', 1)}",
                            "file": rel_path,
                            "line": item.get("start", {}).get("line", 1),
                            "vuln_type": self._map_semgrep_to_vuln_type(check_id),
                            "cwe": _extract_cwe(message),
                            "language": _detect_language_from_path(file_path),
                            "gbt_mapping": VULN_GBT_MAP.get(
                                self._map_semgrep_to_vuln_type(check_id),
                                "GB/T39412-6.1.1.1 输入验证不足",
                            ),
                            "cvss_score": 8.5 if severity == "high" else (5.5 if severity == "medium" else 3.0),
                            "evidence": f"在 {rel_path}:{item.get('start', {}).get('line', 1)} "
                                        f"发现 {message}",
                            "impact_description": message,
                            "remediation": item.get("fix") or "请查阅相关安全编码规范",
                            "code_snippet": (item.get("extra") or {}).get("lines", ""),
                            "status": "待验证",
                        })
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Semgrep 报告解析失败: {e}")

        return findings

    def scan_all(self, project_root: str) -> List[Dict[str, Any]]:
        """执行所有已安装工具的扫描（并行执行，减少总耗时）。"""
        tool_status = self.check_all_tools()

        # 构建待执行任务列表
        tasks: List[tuple] = []
        if tool_status.get("gitleaks"):
            tasks.append(("Gitleaks", self.scan_with_gitleaks))
        if tool_status.get("bandit"):
            tasks.append(("Bandit", self.scan_with_bandit))
        if tool_status.get("semgrep"):
            tasks.append(("Semgrep", self.scan_with_semgrep))

        if not tasks:
            return []

        all_findings: List[Dict[str, Any]] = []

        # 并行执行所有工具扫描
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {
                executor.submit(func, project_root): name
                for name, func in tasks
            }
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    logger.info(f"{tool_name} 扫描完成: {len(findings)} 个发现")
                except Exception as e:
                    logger.warning(f"{tool_name} 扫描失败: {e}")

        return all_findings

    @staticmethod
    def _map_semgrep_to_vuln_type(check_id: str) -> str:
        """从 Semgrep check_id 推断漏洞类型。"""
        lower_id = check_id.lower()
        if "sql" in lower_id:
            return "SQL_INJECTION"
        if "xss" in lower_id:
            return "XSS"
        if "command" in lower_id or "exec" in lower_id:
            return "COMMAND_INJECTION"
        if "path" in lower_id:
            return "PATH_TRAVERSAL"
        if "secret" in lower_id or "credential" in lower_id:
            return "HARD_CODED_SECRET"
        if "crypto" in lower_id or "encryption" in lower_id:
            return "WEAK_CRYPTO"
        if "deserial" in lower_id:
            return "DESERIALIZATION"
        if "ssrf" in lower_id:
            return "SSRF"
        if "xxe" in lower_id:
            return "XXE"
        return "UNKNOWN"
