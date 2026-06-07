#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LLM 文件级安全审计 —— 不依赖 SinkFinder，直接按文件分批次送 LLM 审查。

对标 gbt-codeagent 的 DefensiveLlmReviewer，但适配 ArgusMind 的架构：
- 收集项目源文件
- 按 Token 预算分批
- 每批文件发给主 LLM 做安全审计
- 产出 findings 入库，source="file_review"
"""
from __future__ import annotations

import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 单批最大文件数
_MAX_FILES_PER_BATCH = 5
# 单批最大字符数（粗略估算，中文约 1.5 token/字符）
_MAX_CHARS_PER_BATCH = 12000
# 扩展名白名单（仅审计源文件）
_SOURCE_EXTS = frozenset({
    ".py", ".java", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".rb", ".php", ".kt", ".swift",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".scala",
})

# 文件级审计提示词模板（参考 gbt-codeagent 优化版）

_FILE_AUDIT_SYSTEM_PROMPT = """你是一个资深代码安全审计专家。审查以下代码文件，输出结构化的 JSON 发现。

== 行为规则（必须遵守）==
- **仅输出** JSON 数组，放在 ```json 代码块内。不要前言、不要总结、不要解释。
- 每个发现必须引用代码中的真实文件路径和行号，不得编造。
- 如果不确定，降低置信度或跳过；禁止凭空猜测。
- 确认可利用的漏洞 → CRITICAL/HIGH；纯理论关注 → MEDIUM/LOW。

== 严重等级校准（按项目规模）==
- **CRITICAL**: 无需认证的远程利用，直接导致 RCE/任意文件读写/认证完全绕过。**每项目最多 2 个。**
- **HIGH**: 需认证的利用，导致数据泄露/权限提升/SSRF 到内网。**每项目最多 5 个。**
- **MEDIUM**: 需要特定条件（管理员权限、竞态窗口、特定配置）。每项目 5-15 个。
- **LOW**: 纯理论风险、无实际攻击路径、或纯粹信息性。置信度 0.3-0.5。

== 禁止报告的内容（不报）==
- 代码风格、命名规范、重复代码（非安全问题）
- 测试代码、Demo 代码、Mock 数据、示例文件（路径含 test/demo/mock/example/sample/fixture）
- 框架默认已启用的保护（Spring Security CSRF、React XSS 自动转义等）
- 仅 import 未实际调用的 API
- 注释掉的代码、@Generated 注解、非功能性元数据
- 实体类的 getter/setter/字段定义（除非暴露敏感数据如密码字段）
- 日志语句本身（除非用户输入直接拼入日志参数且无过滤）
- 工具类的正常文件 I/O（若路径固定且不受用户输入控制）
- CSS 颜色值、UI 常量、前端样式

== Source→Sink 速查表（Java）==
| 漏洞 | Source（输入源） | Sink（危险API） | Safety（安全信号） |
|------|----------------|-----------------|-------------------|
| 命令注入 | request.getParameter, @RequestParam, @PathVariable | Runtime.exec(), ProcessBuilder 拼接 | 固定命令+数组参数 |
| SQL 注入 | 同上 | Statement拼接, MyBatis ${}, HQL拼接 | PreparedStatement, MyBatis #{}, JPA :param |
| 路径遍历 | 同上 + MultipartFile文件名 | File(用户可控路径) | Paths.get()+normalize(), 白名单目录 |
| SSRF | 同上 + @RequestBody | HttpURLConnection, RestTemplate(用户可控URL) | 域名白名单, 内网过滤 |
| 反序列化 | @RequestBody, 文件读取 | ObjectInputStream, Fastjson parseObject | 类型白名单, 禁用autoType |
| 代码注入 | @RequestBody, @RequestParam | ScriptEngine.eval(), GroovyShell | 表达式沙箱 |
| XXE | @RequestBody(XML) | DocumentBuilder(未禁用外部实体) | setFeature(DISALLOW_DOCTYPE) |
| XSS | @RequestParam | response.getWriter().write(用户输入) | HTML实体编码, JSON响应 |
| 文件上传 | MultipartFile | transferTo(用户可控文件名), FileOutputStream | UUID重命名, 白名单扩展名 |
| CORS | — | Access-Control-Allow-Origin反射Origin+allowCredentials | 固定白名单 |
| 认证缺失 | — | @GetMapping/@PostMapping 无 @PreAuthorize | SecurityContextHolder, @PreAuthorize |
| 硬编码凭据 | — | password/secret/apiKey/token = "字面量" | System.getenv(), @Value("${}") |
| 会话固定 | — | request.getSession(false) 不复用 | session.invalidate(), changeSessionId() |
| 竞态条件 | — | check-then-act, 余额检查后扣减 | @Version, @Lock, synchronized, AtomicInteger |
| 明文传输 | — | new URL("http://") 硬编码 | https://, SSLContext, HttpsURLConnection |

== 审查原则 ==
1. **深度优于广度**：深入分析每个文件，宁可少报几个高质量发现也不要一堆浅层猜测。
2. **Source→Sink 追踪**：对每个问题，追踪用户输入（Source）到危险API（Sink），识别中间的净化措施（Safety）。
3. **质量过滤**：报告前问自己："我能描述具体的攻击场景吗？" 如果模糊 → 降级或丢弃。
4. **逐文件审查**：不要跳过任何文件。如果某文件真的零漏洞，不要勉强编造。
5. **证据驱动**：每个发现必须有具体的代码行作为证据。

== 漏洞优先级 ==
1. 注入类（SQL/命令/代码/模板/JNDI）— 最高优先级
2. 认证/授权（认证绕过/权限缺失/会话固定）
3. 敏感数据（硬编码凭据/明文传输/信息泄露）
4. 文件操作（路径遍历/文件上传/资源泄漏）
5. 其他（竞态条件/弱加密/弱哈希等）

输出格式：
```json
[
  {
    "file": "相对文件路径",
    "line": 行号,
    "vuln_type": "漏洞类型(如 SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL, HARDCODED_CREDENTIALS, MISSING_AUTHENTICATION, SSRF, XXE, XSS, FILE_UPLOAD, RACE_CONDITION, WEAK_CRYPTO, SESSION_FIXATION, PLAINTEXT_TRANSMISSION, RESOURCE_LEAK, MISSING_ACCESS_CONTROL, PREDICTABLE_RANDOM, BUSINESS_LOGIC, LOG_INJECTION, OPEN_REDIRECT)",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW",
    "title": "简洁的漏洞标题（20字以内）",
    "evidence": "具体代码行或代码片段作为证据",
    "impact": "实际安全影响（可描述攻击场景）",
    "remediation": "具体可操作的修复方案（含代码示例或类名）",
    "cwe": "CWE编号",
    "confidence": 0.0-1.0
  }
]
```
如果零发现，返回 `[]`。
"""

_FILE_AUDIT_USER_PROMPT = """请审计以下 {language} 源代码文件，发现安全漏洞。

{file_list}

=== 文件内容 ===
{file_contents}

=== 额外安全上下文 ===
{security_context}
"""


def _estimate_tokens(text: str) -> int:
    """粗略估算 Token 数（中文 1.5x，英文 1x）。"""
    chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    ascii_chars = len(text) - chinese_chars
    return int(chinese_chars * 1.5 + ascii_chars * 0.4) + 50


def _collect_source_files(project_path: str) -> List[Dict[str, Any]]:
    """收集项目中的源文件信息。"""
    files = []
    project_path = str(project_path)
    for root, dirs, filenames in os.walk(project_path):
        # 跳过常见非源码目录
        dirs[:] = [d for d in dirs if not d.startswith(('.', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.git'))]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in _SOURCE_EXTS:
                abs_path = os.path.join(root, fn)
                rel_path = os.path.relpath(abs_path, project_path).replace("\\", "/")
                try:
                    size = os.path.getsize(abs_path)
                    if size > 0 and size < 500 * 1024:  # 跳过空文件和超大文件 >500KB
                        files.append({
                            "path": abs_path,
                            "relative_path": rel_path,
                            "size": size,
                        })
                except OSError:
                    continue
    # 按文件大小排序，小文件优先
    files.sort(key=lambda f: f["size"])
    return files


def _build_batches(files: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """将文件按 Token 预算分批。"""
    batches = []
    current_batch = []
    current_chars = 0

    for f in files:
        try:
            with open(f["path"], "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue
        f["content"] = content
        file_chars = len(content)

        # 单个文件超过最大限制时单独一批
        if file_chars > _MAX_CHARS_PER_BATCH:
            if current_batch:
                batches.append(current_batch)
                current_batch = []
                current_chars = 0
            f["content"] = content[:_MAX_CHARS_PER_BATCH]  # 截断
            batches.append([f])
            continue

        # 累加到当前批
        if len(current_batch) >= _MAX_FILES_PER_BATCH or current_chars + file_chars > _MAX_CHARS_PER_BATCH:
            batches.append(current_batch)
            current_batch = []
            current_chars = 0

        current_batch.append(f)
        current_chars += file_chars

    if current_batch:
        batches.append(current_batch)

    return batches


def _parse_llm_response(response_text: str) -> List[Dict[str, Any]]:
    """从 LLM 响应中解析 findings。"""
    if not response_text or not response_text.strip():
        return []

    # 尝试直接解析 JSON
    text = response_text.strip()

    # 从 Markdown 代码块提取
    code_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
    if code_match:
        text = code_match.group(1).strip()

    # 尝试解析 JSON 数组
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    # 尝试用正则提取 JSON 数组
    array_match = re.search(r'\[[\s\S]*\]', text)
    if array_match:
        try:
            parsed = json.loads(array_match.group())
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

    return []


def _validate_finding(f: Dict[str, Any]) -> bool:
    """验证单条 finding 是否有效。"""
    return bool(f.get("file")) and bool(f.get("vuln_type")) and bool(f.get("line"))


def _review_batch(
    batch_idx: int,
    batch: List[Dict[str, Any]],
    project_info: str,
    llm: Any,
) -> List[Dict[str, Any]]:
    """审查单批文件，返回发现的 findings 列表。"""
    messages = [
        {"role": "system", "content": _FILE_AUDIT_SYSTEM_PROMPT},
        {"role": "user", "content": _FILE_AUDIT_USER_PROMPT.format(
            language="Java" if any(f["relative_path"].endswith(".java") for f in batch) else "源代码",
            file_list="\n".join(f"- {f['relative_path']}" for f in batch),
            file_contents="\n\n".join(
                f"--- {f['relative_path']} ---\n{f.get('content', '')}"
                for f in batch
            ),
            security_context=project_info or "无额外上下文",
        )},
    ]

    # Token 预算预检（避免浪费 API 调用）
    total_chars = sum(len(str(m.get("content", ""))) for m in messages)
    estimated_tokens = _estimate_tokens(str(messages))
    # 粗略上限：大多数模型 128K，安全余量 85%
    max_safe_tokens = 100000  # 保守值
    if estimated_tokens > max_safe_tokens:
        logger.warning(
            "[FileReview] 第 %d 批 token 预算超限: ~%d > %d，跳过此批",
            batch_idx + 1, estimated_tokens, max_safe_tokens
        )
        return []

    batch_findings: List[Dict[str, Any]] = []
    try:
        resp = llm.call(messages, temperature=0.1)
        raw = resp.content if hasattr(resp, "content") else str(resp)
        findings = _parse_llm_response(raw)

        for f in findings:
            if _validate_finding(f):
                # 使用 LLM 返回的 confidence，默认 0.55
                conf = float(f.get("confidence", 0.55))
                batch_findings.append({
                    "source": "file_review",
                    "title": f.get("title", f"[文件审计] {f.get('vuln_type', '')}"),
                    "severity": f.get("severity", "MEDIUM"),
                    "confidence": conf,
                    "file": f.get("file", ""),
                    "line": int(f.get("line", 1)),
                    "vuln_type": f.get("vuln_type", ""),
                    "evidence": f.get("evidence", ""),
                    "impact_description": f.get("impact", ""),
                    "remediation": f.get("remediation", ""),
                    "cwe": f.get("cwe", ""),
                    "location": f"{f.get('file', '')}:{f.get('line', 1)}",
                    "status": "待验证",
                })

        logger.info("[FileReview] 第 %d/%d 批: LLM 返回 %d 条, 有效 %d 条",
                    batch_idx + 1, 0, len(findings), len(batch_findings))

    except Exception as e:
        logger.warning("[FileReview] 第 %d/%d 批 LLM 调用失败: %s",
                       batch_idx + 1, 0, e)

    return batch_findings


def run_file_review(
    task_id: str,
    project_id: str,
    project_path: str,
    project_info: str,
    llm: Any,
    max_workers: int = 5,
) -> int:
    """执行文件级 LLM 安全审计，返回入库的 finding 数量。

    不依赖 SinkFinder，直接收集源文件、分批送 LLM 审查。
    产出 findings 写入 vulnerability 表，source="file_review"。

    Args:
        task_id: 任务 ID
        project_id: 项目 ID
        project_path: 项目路径
        project_info: 项目信息描述
        llm: LLM 客户端
        max_workers: 并行审计的最大批数（控制 LLM 并发）
    """
    files = _collect_source_files(project_path)
    if not files:
        logger.info("[FileReview] 无可审查的源文件")
        return 0

    logger.info("[FileReview] 收集到 %d 个源文件，开始分批", len(files))
    batches = _build_batches(files)

    all_findings: List[Dict[str, Any]] = []
    if len(batches) <= 1:
        # 单批直接串行
        for batch_idx, batch in enumerate(batches):
            all_findings.extend(_review_batch(batch_idx, batch, project_info, llm))
    else:
        # 多批并行审计
        workers = min(max_workers, len(batches))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_review_batch, idx, batch, project_info, llm): batch
                for idx, batch in enumerate(batches)
            }
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    logger.warning("[FileReview] 并行审计异常: %s", e)

    if not all_findings:
        logger.info("[FileReview] 审计完成，未发现漏洞")
        return 0

    # 通过 persist_quick_scan_findings 入库（复用跨源去重逻辑）
    from src.services.vulnerability_service import persist_quick_scan_findings
    persisted = persist_quick_scan_findings(
        project_id=project_id,
        task_id=task_id,
        findings=all_findings,
        clear_existing=False,
    )

    logger.info("[FileReview] 审计完成，共发现 %d 条漏洞并入库（去重后 %d 条）", len(all_findings), persisted)
    return persisted


# ═══════════════════════════════════════════════════════════════
# Gapfill 补充审计提示词（对应 gbt-codeagent auditAnalystAgent 第549行逻辑）
# ═══════════════════════════════════════════════════════════════

_GAPFILL_SYSTEM_PROMPT = """你是代码安全审计专家。以下文件在上一轮审计中被遗漏，请重点审查。

== 必须检测的漏洞类型 ==
- 命令注入（Runtime.exec 拼接用户输入）、SQL注入（字符串拼接SQL）
- 路径遍历（File 操作路径来自用户输入）、SSRF（用户可控URL发起请求）
- 硬编码凭据（password/apiKey/token = "字面量"）、弱加密（DES/ECB/MD5/SHA1）
- 反序列化（ObjectInputStream/Fastjson）、XXE（未禁用外部实体）
- XSS、CSRF、CORS配置缺陷
- 访问控制缺失（@GetMapping 无 @PreAuthorize）、会话固定
- 明文传输（http://硬编码）、资源泄漏（未关闭的连接/流）

== 审查原则 ==
1. **深度优先**：宁可少报几个高质量发现，不要一堆浅层猜测
2. **Source→Sink 追踪**：看到用户输入进入危险API才报
3. **禁止报告**：实体类getter/setter、仅import未调用、测试/Demo代码、CSS/UI常量

== 本次补充审计的遗漏文件 ==
{file_blocks}

输出格式（仅输出JSON，不要其他文字）：
```json
[{{"title":"漏洞名(15字内)","severity":"critical|high|medium|low","location":"文件:行号","vulnType":"SQL_INJECTION|COMMAND_INJECTION|..."}}]
```
如果零发现，返回 `[]`。"""


def _construct_gapfill_prompt(gapfill_files: List[Dict[str, Any]]) -> str:
    """构建 gapfill 补充审计的 system prompt。

    对应 gbt-codeagent auditAnalystAgent 中 gapfill 阶段的精简提示词。
    """
    blocks = []
    for f in gapfill_files:
        ext = f.get("path", "").rsplit(".", 1)[-1] if "." in f.get("path", "") else "java"
        lang = {
            "py": "python", "js": "javascript", "ts": "typescript", "go": "go",
            "rb": "ruby", "cs": "csharp", "cpp": "cpp", "c": "c",
            "java": "java", "php": "php", "rs": "rust", "kt": "kotlin",
        }.get(ext, "java")
        blocks.append(f"### {f['path']}\n```{lang}\n{f['content']}\n```")

    return _GAPFILL_SYSTEM_PROMPT.format(file_blocks="\n".join(blocks))
