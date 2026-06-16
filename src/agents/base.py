# -*- coding: utf-8 -*-
"""
BaseAgent —— 所有 Agent 的公共基类。

提取 ChainAnalyzer / ChainConfirmer 中重复的 LLM 交互与工具执行逻辑：
  - _llm_step：单轮 LLM 调用，带重试、JSON 解析校验、对话自动回填
  - _execute_tool_call：统一的工具分发与错误处理
"""
import json
import logging
import traceback
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from src.core.event_span import EventSpan
from src.agents.brain import Brain
from src.agents.tool_output_limit import limit_tool_result
from src.core.event_bus import get_event_bus
from src.core.events import LogEvent
from src.core.task_control import ensure_task_running, TaskPausedError
from src.llm import LLMError
from src.tools.base import ERROR_CODE_CANCELLED

logger = logging.getLogger(__name__)


def _sanitize_messages(conversation: List[Dict[str, str]]) -> None:
    """清理对话中的无效消息（参考 CodeScan sanitizeMessageHistory）。

    原地修改 conversation，移除：
    - 空内容的 tool 消息
    - 孤立的 tool_call（没有对应 tool 结果）
    - 空内容的非 system 消息
    """
    # 1. 收集所有 tool_call_id
    tool_call_ids = set()
    for msg in conversation:
        for tc in msg.get("tool_calls", []):
            if isinstance(tc, dict) and tc.get("id"):
                tool_call_ids.add(tc["id"])

    # 2. 移除无效消息
    to_remove = set()
    for i, msg in enumerate(conversation):
        role = msg.get("role", "")
        content = msg.get("content", "")

        # 跳过 system 消息
        if role == "system":
            continue

        # 空内容的 tool 消息（没有对应 tool_call_id）
        if role == "tool" and not msg.get("tool_call_id"):
            to_remove.add(i)
            continue

        # 空内容的非 system/tool 消息
        if role in ("user", "assistant") and not content and not msg.get("tool_calls"):
            to_remove.add(i)

    # 3. 从后往前移除
    for i in sorted(to_remove, reverse=True):
        conversation.pop(i)


class _ToolResultCache:
    """增强型工具结果缓存 —— 参考 CodeScan 的缓存机制。

    特性：
    - LRU 淘汰：超过 max_entries 时淘汰最旧条目
    - 字节数限制：超过 max_bytes 时淘汰最旧条目
    - 统计信息：命中率、字节数等
    """

    def __init__(self, max_entries: int = 200, max_bytes: int = 8 * 1024 * 1024):
        self._entries: OrderedDict[str, Any] = OrderedDict()
        self._bytes: OrderedDict[str, int] = OrderedDict()
        self._total_bytes: int = 0
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> tuple[Any, bool]:
        if key in self._entries:
            self._entries.move_to_end(key)
            self._bytes.move_to_end(key)
            self._hits += 1
            return self._entries[key], True
        self._misses += 1
        return None, False

    def put(self, key: str, value: Any) -> None:
        entry_bytes = len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
        if entry_bytes > self._max_bytes:
            return

        if key in self._entries:
            old_bytes = self._bytes.get(key, 0)
            self._total_bytes -= old_bytes
        self._entries[key] = value
        self._bytes[key] = entry_bytes
        self._total_bytes += entry_bytes
        self._entries.move_to_end(key)
        self._bytes.move_to_end(key)

        self._evict()

    def _evict(self) -> None:
        while (
            len(self._entries) > self._max_entries
            or self._total_bytes > self._max_bytes
        ):
            if not self._entries:
                break
            oldest_key, _ = self._entries.popitem(last=False)
            oldest_bytes = self._bytes.pop(oldest_key, 0)
            self._total_bytes -= oldest_bytes

    @property
    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "total": total,
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0.0,
            "entries": len(self._entries),
            "total_bytes": self._total_bytes,
        }


class BaseAgent:
    """所有需要 LLM 多轮对话 + 工具调用的 Agent 的公共基类。"""

    _TOOL_CACHE_MAXSIZE = 200
    _TOOL_CACHE_MAX_BYTES = 8 * 1024 * 1024  # 8MB

    def __init__(self, brain: Optional[Brain] = None, max_retries: int = 3):
        self._brain = brain
        self.max_retries = max_retries
        self._tool_cache = _ToolResultCache(
            max_entries=self._TOOL_CACHE_MAXSIZE,
            max_bytes=self._TOOL_CACHE_MAX_BYTES,
        )
        self._tool_cache_hits = 0
        self._tool_cache_misses = 0
        self._llm_cached_tokens = 0
        # 并发去重：正在执行中的工具调用
        self._pending_tool_calls: dict[str, Any] = {}

    def _get_artifact_store(self):
        """获取当前任务的 ArtifactStore（懒初始化）。"""
        if self._brain is None:
            return None
        try:
            store = getattr(self._brain, "_artifact_store", None)
            if store is None:
                from src.core.artifact_store import ArtifactStore
                store = ArtifactStore(self._brain.tmp_dir / "artifacts")
                self._brain._artifact_store = store
            return store
        except Exception:
            return None

    @property
    def _agent_tag(self) -> str:
        """日志前缀，子类可覆写。"""
        return self.__class__.__name__

    def _publish_log(self, level: str, message: str) -> None:
        """经事件总线发布 LogEvent，由 handler 写入 logs 表；失败时仅回退到标准 logging。"""
        module = getattr(self, "MODULE_NAME", None) or self._agent_tag
        task_id = getattr(self._brain, "task_id", None) if self._brain else None
        try:
            get_event_bus().publish_async(
                LogEvent(level=level, module=module, message=message, task_id=task_id)
            )
        except Exception as ex:
            logger.debug("LogEvent publish failed: %s", ex)
            logger.log(
                getattr(logging, level.upper(), logging.INFO),
                "[%s] %s",
                module,
                message,
            )

    def _llm_step(self, conversation: List[Dict[str, str]]) -> tuple[None, int | Any, int | Any] | tuple[
        dict, Any, Any]:
        """
        执行一轮 LLM 调用。

        - 自动处理 JSON 解析失败的重试（回填纠正消息）
        - 成功返回解析后的 dict，失败返回 None
        - 每次成功/失败的响应都会追加到 conversation 中
        """
        task_id = getattr(self._brain, "task_id", None) if self._brain else None
        ensure_task_running(task_id or "")

        input_token, output_token = 0, 0
        for attempt in range(self.max_retries):
            ensure_task_running(task_id or "")
            try:
                result, input_token, output_token, cached_token = self._brain.ask(conversation)
                # 如果 LLM 未返回 token 用量，用字符数估计作为兜底
                if input_token == 0 and output_token == 0 and isinstance(result, dict):
                    input_token = sum(len(m.get("content", "")) for m in conversation) // 4
                    output_token = max(len(json.dumps(result, ensure_ascii=False)) // 4, 1)
                # 累计 LLM prompt cache 命中 token
                if cached_token:
                    self._llm_cached_tokens += cached_token
                # 直接上报 token（绕开 EventSpan/TicketEvent 链路，保证落库）
                if task_id and (input_token or output_token):
                    try:
                        from src.services.token_service import report_token_usage
                        report_token_usage(
                            task_id=task_id,
                            llm_input=input_token,
                            llm_output=output_token,
                            code_agent_input=0,
                            code_agent_output=0,
                            note=self._agent_tag,
                        )
                    except Exception:
                        pass
            except LLMError:
                # LLM 服务级致命错误（额度不足/鉴权失败/网络异常等）：
                # 绝不能吞成"空响应"后继续重试并标记完成，必须向上抛出，
                # 由编排层将任务标记为 failed。
                self._publish_log(
                    "ERROR",
                    f"[{self._agent_tag}] LLM 调用发生致命错误，终止当前流程（任务将标记为失败）",
                )
                raise
            except TaskPausedError:
                # 任务被暂停（含 token 预算超额自动暂停）：必须协作式向上抛出，
                # 不可被下方通用 except 吞成"空响应"后继续。
                raise
            except ValueError as e:
                conversation.append({"role": "assistant", "content": "(模型返回内容无法解析为JSON)"})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "INVALID_JSON",
                        "detail": str(e),
                        "requirement": "请严格按输出协议只返回一个JSON对象",
                    }, ensure_ascii=False),
                })
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] LLM 返回无法解析为 JSON (attempt {attempt + 1}/{self.max_retries}): {e!r}",
                )
                continue
            except Exception as e:
                logger.exception("[%s] LLM 调用异常: %s", self._agent_tag, e)
                tb = traceback.format_exc()
                tail = tb[-4000:] if len(tb) > 4000 else tb
                self._publish_log(
                    "ERROR",
                    f"[{self._agent_tag}] LLM 调用异常: {e!r}\n{tail}",
                )
                return None, input_token, output_token
            if result is None:
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] LLM 返回为空 (attempt {attempt + 1}/{self.max_retries})",
                )
                continue
            if isinstance(result, dict):
                content = json.dumps(result, ensure_ascii=False)
                conversation.append({"role": "assistant", "content": content})
                # 上下文压力检查：当 prompt_tokens 接近上限时自动压缩
                self._maybe_compact_conversation(conversation, input_token)
                return result, input_token, output_token
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] LLM 返回非 JSON 对象 (attempt {attempt + 1}/{self.max_retries}) {str(result)[:200]}",
            )
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "EXPECTED_JSON_OBJECT",
                    "requirement": "请返回一个JSON对象，包含 action 字段，禁止发送补全代码等非系统要求信息。",
                }, ensure_ascii=False),
            })
        self._publish_log(
            "WARNING",
            f"[{self._agent_tag}] LLM 已达最大重试 {self.max_retries} 次仍无有效响应",
        )
        return None, input_token, output_token

    def _bump_consecutive_invalid_action(
        self,
        conversation: List[Dict[str, str]],
        consecutive_invalid_action: int,
        *,
        threshold: int = 3,
    ) -> int:
        """
        连续 INVALID_ACTION 计数 +1；达到 threshold 时将 conversation[0] 的 system 消息再附加一次。
        返回更新后的连续计数（重新附加 system 后归零）。
        """
        count = consecutive_invalid_action + 1
        if count >= threshold and conversation and conversation[0].get("role") == "system":
            conversation.append(dict(conversation[0]))
            self._publish_log(
                "INFO",
                f"[{self._agent_tag}] 连续 {threshold} 次 INVALID_ACTION，已重新附加 system 提示",
            )
            return 0
        return count

    def _maybe_compact_conversation(
        self,
        conversation: List[Dict[str, str]],
        prompt_tokens: int,
    ) -> None:
        """根据 ContextCompressionPolicy 检查上下文压力，必要时压缩对话。

        压缩策略：
        - micro: 仅清理旧工具结果（通过 artifact 占位符替换）
        - full: 调用 ContextCompressor 做摘要压缩
        - hard: 强制截断旧消息
        """
        from src.core.context_compression import get_compression_policy
        policy = get_compression_policy()
        pressure = policy.pressure_level(prompt_tokens)
        if pressure == "safe":
            return

        self._publish_log(
            "INFO",
            f"[{self._agent_tag}] 上下文压力={pressure}, prompt_tokens={prompt_tokens}, "
            f"阈值 micro={policy.micro_limit_tokens} full={policy.full_limit_tokens} "
            f"hard={policy.hard_limit_tokens}",
        )

        if pressure == "hard":
            # 硬压缩：保留 system + 最近N条消息
            min_tail = policy.compact_min_tail_messages
            if len(conversation) > min_tail + 1:
                system_msg = conversation[0] if conversation[0].get("role") == "system" else None
                removed = len(conversation) - min_tail - (1 if system_msg else 0)
                tail = conversation[-min_tail:]
                conversation.clear()
                if system_msg:
                    conversation.append(system_msg)
                    conversation.append({
                        "role": "system",
                        "content": f"[上下文压缩] 已移除 {removed} 条旧消息以防止超出 token 上限。",
                    })
                conversation.extend(tail)
                self._publish_log("WARNING", f"[{self._agent_tag}] 硬压缩: 移除 {removed} 条旧消息")

        elif pressure == "full":
            # 全压缩：优先使用 session memory，否则调用 LLM 做摘要
            try:
                from src.services.session_memory import SessionMemory
                session_mem = SessionMemory(
                    task_id=getattr(self._brain, 'task_id', 'unknown'),
                    agent_tag=self._agent_tag,
                )

                # 1. 尝试 session memory 压缩（无需 LLM 调用）
                session_ctx = session_mem.get_session_context()
                if session_ctx and len(conversation) > 5:
                    # 保留 system + 最近 4 条消息 + session memory
                    system_msg = conversation[0] if conversation[0].get("role") == "system" else None
                    tail = conversation[-4:]
                    removed = len(conversation) - len(tail) - (1 if system_msg else 0)
                    conversation.clear()
                    if system_msg:
                        conversation.append(system_msg)
                    conversation.append({"role": "system", "content": session_ctx})
                    conversation.extend(tail)
                    self._inject_evidence_index(conversation)
                    self._publish_log("INFO",
                        f"[{self._agent_tag}] Session Memory 压缩: 移除 {removed} 条旧消息，使用会话记忆恢复")
                else:
                    # 2. 降级到 LLM 压缩
                    from src.services.context_compressor import ContextCompressor
                    brain = self._brain
                    if brain and hasattr(brain, "_llm_client"):
                        def _ask_fn(msgs):
                            resp, i_tok, o_tok, _ = brain.ask(msgs)
                            return json.dumps(resp, ensure_ascii=False) if isinstance(resp, dict) else str(resp), i_tok, o_tok
                        compressor = ContextCompressor(_ask_fn)
                        if compressor.should_compress(conversation):
                            # 压缩前清理无效消息
                            _sanitize_messages(conversation)
                            system_msg = conversation[0] if conversation[0].get("role") == "system" else None
                            compressed = compressor.apply_compression(conversation, system_message=system_msg)
                            conversation.clear()
                            conversation.extend(compressed)
                            # 注入 Evidence 索引
                            self._inject_evidence_index(conversation)
                            self._publish_log("INFO", f"[{self._agent_tag}] 全压缩: 对话已压缩为摘要")

                            # 更新 session memory
                            try:
                                summary_text = compressed[1].get("content", "") if len(compressed) > 1 else ""
                                if summary_text:
                                    session_mem.write_summary(summary_text)
                            except Exception:
                                pass
            except Exception as e:
                logger.debug("[%s] 全压缩失败，降级为 micro: %s", self._agent_tag, e)

        elif pressure == "micro":
            # 微压缩：用 artifact 占位符替换旧工具结果，保留最近 N 轮
            from src.core.context_compression import estimate_tokens_from_text
            keep_recent = 2  # 保留最近 2 轮工具结果
            max_msg_tokens = policy.effective_limit_tokens // max(len(conversation), 1)

            # 找出所有工具调用轮次
            tool_rounds = []
            current_round = -1
            for i, msg in enumerate(conversation):
                if msg.get("tool_calls"):
                    current_round += 1
                if msg.get("role") == "tool":
                    tool_rounds.append((i, current_round))

            # 保护最近 N 轮
            protected_rounds = set()
            seen_rounds = set()
            for _, r in reversed(tool_rounds):
                if r not in seen_rounds:
                    seen_rounds.add(r)
                    if len(protected_rounds) < keep_recent:
                        protected_rounds.add(r)

            store = self._get_artifact_store()
            compacted = 0
            for i, msg in enumerate(conversation):
                if msg.get("role") != "tool":
                    continue
                content = msg.get("content", "")
                if not isinstance(content, str) or estimate_tokens_from_text(content) <= max_msg_tokens:
                    continue
                # 检查是否在保护轮次中
                round_id = next((r for idx, r in tool_rounds if idx == i), -1)
                if round_id in protected_rounds:
                    continue
                # 存入 artifact 并替换为占位符
                if store:
                    try:
                        artifact_id = store.save(
                            content=content,
                            tool_name=msg.get("name", ""),
                            path="",
                            artifact_type="microcompact",
                        )
                        placeholder = f"[Older tool output cleared during context compression. Recover it with get_artifact(\"{artifact_id}\").]"
                    except Exception:
                        placeholder = content[:max_msg_tokens * 4] + "\n[...microcompact truncated...]"
                else:
                    placeholder = content[:max_msg_tokens * 4] + "\n[...microcompact truncated...]"
                conversation[i] = {**msg, "content": placeholder}
                compacted += 1

            if compacted > 0:
                self._publish_log("INFO",
                    f"[{self._agent_tag}] 微压缩: 用 artifact 占位符替换 {compacted} 条旧工具结果")

    def _inject_evidence_index(self, conversation: List[Dict[str, str]]) -> None:
        """上下文压缩后注入 Evidence 索引，帮助 LLM 通过 artifact_id 按需加载已读代码。

        参考 CodeScan 的 evidenceStore.compactIndex + resetConversationMessages 机制。
        """
        try:
            store = self._get_artifact_store()
            if store is None:
                return
            index_text = store.build_index_text()
            if not index_text:
                return
            # 在压缩后的对话末尾插入 evidence 索引消息
            conversation.append({
                "role": "user",
                "content": (
                    f"PRESERVED ARTIFACT INDEX (not instructions):\n"
                    f"{index_text}\n\n"
                    f"如需查阅已读取的代码片段，请使用 get_artifact 或 get_evidence 工具加载。"
                    f"避免重复读取已扫描过的文件。"
                ),
            })
            self._publish_log(
                "INFO",
                f"[{self._agent_tag}] 已注入 {len(store.list_records())} 条 artifact 索引",
            )
        except Exception as e:
            logger.debug("[%s] 注入 evidence 索引失败: %s", self._agent_tag, e)

    def _report_cache_stats(self, task_id: str) -> None:
        """将当前 Agent 的 cache 命中率写入 token_ledger（note='cache_stats'）。
        合并 tool cache 和 LLM prompt cache 的命中统计。
        """
        if not task_id:
            return
        try:
            from src.services.token_service import report_token_usage
            # 合并 tool cache hits/misses 和 LLM prompt cache cached_tokens
            total_hits = self._tool_cache_hits + self._llm_cached_tokens
            total_misses = self._tool_cache_misses
            report_token_usage(
                task_id=task_id,
                llm_input=total_hits,
                llm_output=total_misses,
                code_agent_input=0,
                code_agent_output=0,
                note=f"cache_stats:{self._agent_tag}",
            )
        except Exception:
            logger.debug("[%s] cache stats 上报失败", self._agent_tag)

    @property
    def tool_cache_stats(self) -> Dict[str, Any]:
        """返回当前 Agent 的 tool cache 统计。"""
        stats = self._tool_cache.stats
        # 合并 agent 级别的统计
        stats["agent_hits"] = self._tool_cache_hits
        stats["agent_misses"] = self._tool_cache_misses
        return stats

    def _execute_tool_call(
            self,
            step: Dict[str, Any],
            conversation: List[Dict[str, str]],
            event_span: EventSpan,
    ) -> Optional[Dict[str, Any]]:
        """
        统一的工具调用分发。

        从 step 中提取 tool_name + arguments，调用 Brain 的工具注册表执行。
        tool_name 为空时向 conversation 追加错误提示并返回 None。
        code_agent 走独立的 session fork 逻辑。
        """
        tool_name = step.get("tool_name", "")
        arguments = step.get("arguments", {}) or {}
        
        # 工具别名映射：处理 LLM 可能使用的不同工具名称
        _tool_aliases = {
            "search": "ripgrep_search",
            "grep": "ripgrep_search",
            "find": "ripgrep_search",
            "read": "read_file",
            "cat": "read_file",
            "list": "list_files",
            "ls": "list_files",
            "list_directory": "list_files",
            "dir": "list_files",
        }
        if tool_name in _tool_aliases:
            original_name = tool_name
            tool_name = _tool_aliases[tool_name]
            self._publish_log(
                "INFO",
                f"[{self._agent_tag}] 工具别名映射: {original_name!r} -> {tool_name!r}"
            )
        
        if not tool_name:
            self._publish_log("WARNING", f"[{self._agent_tag}] tool_call 缺少 tool_name")
            conversation.append({
                "role": "user",
                "content": json.dumps({
                    "error": "MISSING_TOOL_NAME",
                    "requirement": "tool_call 时 tool_name 不能为空",
                }, ensure_ascii=False),
            })
            return None
        if tool_name == "code_agent":
            return self._run_code_agent(tool_name, arguments, event_span)

        # 定义工具必需参数的校验规则
        _required_params = {
            "read_file": ["file_path", "path", "filepath", "file"],
            "read_lines": ["file_path", "path", "filepath", "file"],
            "ripgrep_search": ["pattern"],
            "ripgrep": ["pattern"],
        }
        
        # 检查必需参数
        required_keys = _required_params.get(tool_name, [])
        if required_keys:
            has_required = any(key in arguments for key in required_keys)
            if not has_required:
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] 工具 {tool_name!r} 缺少必需参数 {required_keys!r}"
                )
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "error": "MISSING_REQUIRED_PARAM",
                        "tool_name": tool_name,
                        "required": required_keys,
                        "requirement": f"调用 {tool_name} 时必须提供 {'或'.join(required_keys)} 参数",
                    }, ensure_ascii=False),
                })
                return None

        # 只缓存只读工具（read_file / read_lines / ripgrep / search / list）
        _cacheable_prefixes = ("read_", "readlines", "ripgrep", "search", "list_")
        _cache_key = None
        if tool_name.startswith(_cacheable_prefixes) and isinstance(arguments, dict):
            # 增强缓存 key 策略：
            # - read_file: 按文件路径去重（同一文件只读一次）
            # - read_lines: 按文件路径去重（如果已有 read_file 缓存则复用）
            # - ripgrep: 按 pattern + path 去重
            # - 其他: 按完整参数去重
            if tool_name == "read_file":
                file_path = arguments.get("path", arguments.get("file_path", ""))
                if file_path:
                    _cache_key = f"read_file:{file_path}"
            elif tool_name == "read_lines":
                file_path = arguments.get("path", arguments.get("file_path", ""))
                if file_path:
                    # 先查 read_file 的缓存（整个文件）
                    _full_file_key = f"read_file:{file_path}"
                    cached, hit = self._tool_cache.get(_full_file_key)
                    if hit:
                        self._tool_cache_hits += 1
                        logger.debug("[%s] 工具缓存命中(read_file→read_lines) %s", self._agent_tag, file_path)
                        return cached
                    # 再查 read_lines 自身的缓存
                    _cache_key = f"read_lines:{file_path}"
            elif tool_name == "ripgrep":
                pattern = arguments.get("pattern", "")
                path = arguments.get("path", arguments.get("directory", ""))
                if pattern:
                    _cache_key = f"ripgrep:{path}:{pattern}"
            else:
                _cache_key = f"{tool_name}:{hash(frozenset((k, str(v)) for k, v in sorted(arguments.items())))}"

            if _cache_key:
                cached, hit = self._tool_cache.get(_cache_key)
                if hit:
                    self._tool_cache_hits += 1
                    logger.debug("[%s] 工具缓存命中 %s", self._agent_tag, tool_name)
                    return cached
                self._tool_cache_misses += 1

        try:
            result = self._brain.run_tool(tool_name, **arguments)
            if isinstance(result, dict):
                if not result.get("success", True):
                    self._publish_log(
                        "WARNING",
                        f"[{self._agent_tag}] 工具 {tool_name!r} 返回 success=False | "
                        f"error={result.get('error')!r}",
                    )
                if self._brain is not None:
                    final_result = limit_tool_result(
                        result,
                        self._brain.tmp_dir,
                        tool_name=tool_name,
                        artifact_store=self._get_artifact_store(),
                    )
                else:
                    final_result = result
            else:
                final_result = result

            # 写入缓存（仅成功的结果）
            if _cache_key is not None and isinstance(final_result, dict) and final_result.get("success", True):
                self._tool_cache.put(_cache_key, final_result)

            return final_result
        except Exception as e:
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] 工具 {tool_name!r} 执行异常: {e!r}",
            )
            return {"success": False, "error": str(e), "error_code": "TOOL_EXECUTION_FAILED"}

    def _run_code_agent(
            self,
            tool_name: str,
            arguments: Dict[str, Any],
            event_span: EventSpan,
    ) -> Optional[Dict[str, Any]]:
        """运行 code_agent（OpenCodeTool）。

        - 传入 event_id：让 opencode 在 SSE 流中把每条事件实时落库到 opencode_events，
          并把 step-finish 累计 token 实时回写到 events.code_agent_*_delta。
        - 结束后把累计 token 写到 EventSpan；add_* 与 finish 会按当前总量发 TokenEvent，
          经 ``report_token_usage`` 对绑定 event 的账本行覆盖写；任务 token 由对 ledger 聚合得到。
        """
        try:
            arguments["event_id"] = event_span.event_id
            arguments['task_id'] = self._brain.task_id
            result = self._brain.run_tool(tool_name, **arguments)
            if (result or {}).get("error_code") == ERROR_CODE_CANCELLED:
                ensure_task_running(self._brain.task_id)
            # Brain.run_tool 走 ToolRegistry.invoke，统一返回 dict（ToolResult.to_dict()）
            data = dict((result or {}).get("data") or {})
            token_input = data.pop("token_input", 0) or 0
            token_output = data.pop("token_output", 0) or 0
            event_span.add_code_agent_tokens(token_input, token_output)
            event_span.set_output(json.dumps(result))
            if isinstance(result, dict) and not result.get("success", True):
                self._publish_log(
                    "WARNING",
                    f"[{self._agent_tag}] code_agent 返回 success=False | error={result.get('error')!r}",
                )
            return result
        except Exception as e:
            self._publish_log(
                "WARNING",
                f"[{self._agent_tag}] code_agent 执行异常: {e!r}",
            )
            return {"success": False, "error": str(e), "error_code": "TOOL_EXECUTION_FAILED"}
