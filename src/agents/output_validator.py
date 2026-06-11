# -*- coding: utf-8 -*-
"""LLM 输出 Schema 校验管道 —— 参考 CodeScan 的 repair_validation.go。

对每个审计阶段的 LLM 输出做结构化校验：
1. JSON 提取和修复（已有 json_parse）
2. 必填字段校验（required_fields）
3. 类型校验（type 必须匹配阶段 expected_type）
4. 数组字段校验（array_fields 必须是列表）
5. 可选的自动修复（补全缺失字段默认值）

用法：
    from src.agents.output_validator import validate_findings_output
    ok, errors, fixed = validate_findings_output(raw_output, "SQL_INJECTION")
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.utils.json_parse import parse_json

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# 阶段 Schema 定义（参考 CodeScan repairStageRules）
# ══════════════════════════════════════════════════════════════════

@dataclass
class StageSchema:
    """单个审计阶段的输出 Schema。"""
    stage_key: str
    expected_type: str                     # findings 中 type 字段应匹配的值
    required_fields: List[str] = field(default_factory=list)
    array_fields: List[str] = field(default_factory=list)
    severity_values: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])


# ── 阶段 Schema 注册表 ──
STAGE_SCHEMAS: Dict[str, StageSchema] = {
    "COMMAND_INJECTION": StageSchema(
        stage_key="command_injection",
        expected_type="COMMAND_INJECTION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "SQL_INJECTION": StageSchema(
        stage_key="sql_injection",
        expected_type="SQL_INJECTION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "SSRF": StageSchema(
        stage_key="ssrf",
        expected_type="SSRF",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "DESERIALIZATION": StageSchema(
        stage_key="deserialization",
        expected_type="DESERIALIZATION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "CODE_INJECTION": StageSchema(
        stage_key="code_injection",
        expected_type="CODE_INJECTION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "XSS": StageSchema(
        stage_key="xss",
        expected_type="XSS",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "PATH_TRAVERSAL": StageSchema(
        stage_key="path_traversal",
        expected_type="PATH_TRAVERSAL",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "AUTH_BYPASS": StageSchema(
        stage_key="auth_bypass",
        expected_type="AUTH_BYPASS",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "XXE": StageSchema(
        stage_key="xxe",
        expected_type="XXE",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "FILE_UPLOAD": StageSchema(
        stage_key="file_upload",
        expected_type="FILE_UPLOAD",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "HARD_CODED_SECRET": StageSchema(
        stage_key="hard_coded_secret",
        expected_type="HARD_CODED_SECRET",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "JNDI_INJECTION": StageSchema(
        stage_key="jndi_injection",
        expected_type="JNDI_INJECTION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "SPEL_INJECTION": StageSchema(
        stage_key="spel_injection",
        expected_type="SPEL_INJECTION",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "SSTI": StageSchema(
        stage_key="ssti",
        expected_type="SSTI",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "INSECURE_RANDOM": StageSchema(
        stage_key="insecure_random",
        expected_type="INSECURE_RANDOM",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
    "CORS": StageSchema(
        stage_key="cors",
        expected_type="CORS",
        required_fields=["title", "file", "line", "reason", "severity"],
        array_fields=[],
    ),
}

# ── 通用 finding schema（不区分阶段）──
GENERIC_FINDING_SCHEMA = StageSchema(
    stage_key="generic",
    expected_type="",
    required_fields=["title", "file", "line", "reason", "severity"],
    array_fields=[],
)


# ══════════════════════════════════════════════════════════════════
# 校验结果
# ══════════════════════════════════════════════════════════════════

@dataclass
class ValidationError:
    """单条校验错误。"""
    item_index: int
    field: str
    message: str
    severity: str = "error"  # "error" / "warning"


@dataclass
class ValidationResult:
    """校验结果。"""
    valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    items_count: int = 0
    fixed_count: int = 0

    def add_error(self, item_index: int, field_name: str, message: str) -> None:
        self.errors.append(ValidationError(item_index, field_name, message, "error"))
        self.valid = False

    def add_warning(self, item_index: int, field_name: str, message: str) -> None:
        self.warnings.append(ValidationError(item_index, field_name, message, "warning"))

    def summary(self) -> str:
        if self.valid:
            return f"校验通过: {self.items_count} 条发现, {len(self.warnings)} 条警告"
        return f"校验失败: {len(self.errors)} 条错误, {len(self.warnings)} 条警告, {self.items_count} 条发现"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "items_count": self.items_count,
            "fixed_count": self.fixed_count,
            "errors": [{"item": e.item_index, "field": e.field, "message": e.message} for e in self.errors],
            "warnings": [{"item": w.item_index, "field": w.field, "message": w.message} for w in self.warnings],
        }


# ══════════════════════════════════════════════════════════════════
# 校验函数
# ══════════════════════════════════════════════════════════════════

def _get_schema(vul_name: str) -> StageSchema:
    """获取指定漏洞类型的 Schema。"""
    # 直接匹配
    if vul_name in STAGE_SCHEMAS:
        return STAGE_SCHEMAS[vul_name]
    # 模糊匹配
    vul_upper = vul_name.upper().replace(" ", "_").replace("-", "_")
    for key, schema in STAGE_SCHEMAS.items():
        if key in vul_upper or vul_upper in key:
            return schema
    return GENERIC_FINDING_SCHEMA


def _extract_string(value: Any) -> str:
    """安全提取字符串值。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return str(value).strip()


def _is_valid_severity(severity: str) -> bool:
    """检查严重等级是否有效。"""
    return severity.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


def validate_finding_item(
    item: Dict[str, Any],
    index: int,
    schema: StageSchema,
    auto_fix: bool = True,
) -> Tuple[bool, List[ValidationError], bool]:
    """校验单条 finding。

    Returns:
        (is_valid, errors, was_fixed)
    """
    errors: List[ValidationError] = []
    was_fixed = False

    if not isinstance(item, dict):
        errors.append(ValidationError(index, "_root", f"第 {index} 条发现不是 JSON 对象"))
        return False, errors, False

    # 1. 必填字段校验
    for field_name in schema.required_fields:
        value = item.get(field_name)
        str_val = _extract_string(value)
        if not str_val:
            # 尝试自动修复：补全缺失字段的默认值
            if auto_fix and field_name in ("title", "reason"):
                item[field_name] = f"[待补充] {field_name}"
                was_fixed = True
            elif auto_fix and field_name == "severity":
                item[field_name] = "MEDIUM"
                was_fixed = True
            elif auto_fix and field_name == "file":
                item[field_name] = "[unknown]"
                was_fixed = True
            elif auto_fix and field_name == "line":
                item[field_name] = 0
                was_fixed = True
            else:
                errors.append(ValidationError(index, field_name, f"缺失必填字段 '{field_name}'"))

    # 2. 严重等级校验
    severity = _extract_string(item.get("severity"))
    if severity and not _is_valid_severity(severity):
        if auto_fix:
            item["severity"] = "MEDIUM"
            was_fixed = True
        else:
            errors.append(ValidationError(index, "severity", f"无效的严重等级: {severity}"))

    # 3. 类型字段校验（如果 schema 指定了 expected_type）
    if schema.expected_type:
        item_type = _extract_string(item.get("type"))
        if item_type and item_type.upper() != schema.expected_type.upper():
            # 警告但不阻断（LLM 可能使用不同的 type 命名）
            errors.append(ValidationError(index, "type",
                f"type '{item_type}' 与阶段预期 '{schema.expected_type}' 不匹配", "warning"))

    # 4. 数组字段校验
    for array_field in schema.array_fields:
        value = item.get(array_field)
        if value is not None and not isinstance(value, list):
            if auto_fix:
                item[array_field] = [value] if value else []
                was_fixed = True
            else:
                errors.append(ValidationError(index, array_field, f"字段 '{array_field}' 应为数组"))

    is_valid = all(e.severity == "error" for e in errors) or not errors
    return is_valid, [e for e in errors if e.severity == "error"], was_fixed


def validate_findings_output(
    raw_output: str,
    vul_name: str,
    auto_fix: bool = True,
) -> Tuple[List[Dict[str, Any]], ValidationResult]:
    """校验 LLM 输出的 findings JSON。

    Args:
        raw_output: LLM 原始输出文本
        vul_name: 漏洞类型名称
        auto_fix: 是否自动修复可修复的问题

    Returns:
        (findings_list, validation_result)
    """
    result = ValidationResult()
    schema = _get_schema(vul_name)

    # 1. JSON 提取和修复
    findings = parse_json(raw_output, default=[])
    if not isinstance(findings, list):
        # 尝试包装为列表
        if isinstance(findings, dict):
            findings = [findings]
        else:
            result.add_error(-1, "_root", "输出不是 JSON 数组")
            return [], result

    result.items_count = len(findings)

    # 2. 逐条校验
    valid_findings = []
    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            result.add_error(i, "_root", f"第 {i} 条不是 JSON 对象，已跳过")
            continue

        is_valid, errors, was_fixed = validate_finding_item(item, i, schema, auto_fix=auto_fix)

        if was_fixed:
            result.fixed_count += 1

        if errors:
            for err in errors:
                if err.severity == "warning":
                    result.add_warning(err.item_index, err.field, err.message)
                else:
                    result.add_error(err.item_index, err.field, err.message)

        # 即使有 warning 也保留
        valid_findings.append(item)

    # 3. 去重（同文件+同行+同类型的发现只保留第一条）
    seen = set()
    deduped = []
    for item in valid_findings:
        key = (
            _extract_string(item.get("file")),
            str(item.get("line", "")),
            _extract_string(item.get("type", item.get("title", ""))),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    if len(deduped) < len(valid_findings):
        dup_count = len(valid_findings) - len(deduped)
        logger.info("去重: 移除 %d 条重复发现", dup_count)
        result.items_count = len(deduped)

    return deduped, result


def validate_and_log(raw_output: str, vul_name: str, task_id: str = "") -> List[Dict[str, Any]]:
    """校验并记录日志的便捷入口。

    Args:
        raw_output: LLM 原始输出
        vul_name: 漏洞类型
        task_id: 任务 ID（用于日志）

    Returns:
        校验通过的 findings 列表
    """
    findings, result = validate_findings_output(raw_output, vul_name, auto_fix=True)

    if result.fixed_count > 0:
        logger.info("[task=%s] %s: 自动修复 %d 条发现", task_id, vul_name, result.fixed_count)

    if result.warnings:
        for w in result.warnings[:5]:
            logger.warning("[task=%s] %s: 第 %d 条 %s - %s",
                          task_id, vul_name, w.item_index, w.field, w.message)

    if not result.valid:
        for e in result.errors[:5]:
            logger.error("[task=%s] %s: 第 %d 条 %s - %s",
                        task_id, vul_name, e.item_index, e.field, e.message)

    logger.info("[task=%s] %s: %s", task_id, vul_name, result.summary())
    return findings
