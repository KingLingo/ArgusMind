"""LLM 客户端（基于 LiteLLM 统一接口）"""
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.config import LLMConfig

try:
    import litellm
    from litellm import completion as litellm_completion
except ImportError:
    litellm = None
    litellm_completion = None

logger = logging.getLogger(__name__)


class LLMError(RuntimeError):
    """LLM 调用失败（鉴权失败、额度不足、网络错误、服务异常等）。

    这是一类**致命错误**：调用方不应将其当作"空响应"吞掉后继续重试并标记完成，
    而应让其向上传播，由编排层把任务标记为 ``failed``。

    Attributes:
        original: 底层抛出的原始异常（litellm/openai 等）
        retryable: 是否属于可重试的瞬时错误（已在客户端内重试耗尽）
        status_code: HTTP 状态码（若可获取），便于排查（401 鉴权 / 402,429 额度等）
    """

    def __init__(
        self,
        message: str,
        *,
        original: Optional[BaseException] = None,
        retryable: bool = False,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.original = original
        self.retryable = retryable
        self.status_code = status_code


# 可重试的瞬时错误（网络/超时/服务暂时不可用/限流）。
# 限流可能是真正的额度耗尽，也可能是临时节流；统一先按瞬时重试，
# 重试耗尽后仍会抛出 LLMError，保证不会被当作空响应吞掉。
_RETRYABLE_EXC_NAMES = frozenset({
    "Timeout",
    "APITimeoutError",
    "APIConnectionError",
    "ServiceUnavailableError",
    "InternalServerError",
    "RateLimitError",
})

# litellm 原生支持、需保留各自专有路由（专有 SDK / 鉴权 / 端点）的厂商。
# 不在此列且配置了 base_url 的 provider（典型为 one-api / new-api / 各类自建聚合代理，
# 或下拉里选了 litellm 不识别的国产厂商名）一律按 OpenAI 兼容端点处理，
# 避免 litellm 报 "LLM Provider NOT provided" 或忽略 base_url 直连真实厂商。
_NATIVE_PROVIDERS = frozenset({
    "openai", "azure", "azure_ai", "anthropic", "bedrock", "vertex_ai", "vertex",
    "gemini", "google", "palm", "cohere", "mistral", "ollama", "together_ai",
    "groq", "deepseek", "xai", "openrouter", "fireworks_ai", "perplexity",
    "anyscale", "replicate", "huggingface", "watsonx", "cloudflare", "voyage",
    "databricks", "nvidia_nim", "deepinfra", "ai21", "nlp_cloud", "aleph_alpha",
    "sagemaker", "moonshot", "volcengine",
})

# 视为 "OpenAI 兼容端点" 的 type 取值（配置管理里可显式指定 / 用开关强制）。
# 注意：
#   - 不含裸 "openai"（有歧义，可能只是厂商名）；
#   - 不含 "custom"：自定义端点默认走下方 "base_url + 非原生 provider" 的启发式判定，
#     仅当用户在 UI 显式打开 "OpenAI 兼容端点" 开关（写入 openai_compatible）时才强制兼容路由。
_COMPATIBLE_TYPES = frozenset({
    "openai_compatible", "compatible", "oneapi",
    "one-api", "new-api", "newapi", "proxy",
})


def _litellm_native_providers() -> frozenset:
    """合并静态白名单与 litellm 运行时 provider_list（若可用），尽量准确。"""
    providers = set(_NATIVE_PROVIDERS)
    try:  # litellm 不同版本里 provider_list 元素可能是字符串或枚举
        for p in (getattr(litellm, "provider_list", None) or []):
            name = getattr(p, "value", None) or str(p)
            if name:
                providers.add(name.lower())
    except Exception:  # pragma: no cover - 仅作增强，失败回退到静态表
        pass
    return frozenset(providers)

@dataclass
class LLMResponse:
    """单次调用的返回：回复内容 + 本次对话消耗的 token"""

    content: str
    """AI 回复文本"""

    prompt_tokens: int = 0
    """输入（提示）消耗的 token 数"""

    completion_tokens: int = 0
    """输出（补全）消耗的 token 数"""

    total_tokens: int = 0
    """总 token 数（prompt_tokens + completion_tokens）"""

    cached_tokens: int = 0
    """命中 prompt cache 的 token 数"""

    raw: object | None = None
    """底层 LLM 原始响应对象（用于调试/透传）"""

    @property
    def usage(self) -> Dict[str, int]:
        """以字典形式返回用量，便于日志或上报"""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


class LLMClient:
    """
    LLM 客户端，基于 [LiteLLM](https://docs.litellm.ai/docs/) 统一调用多种模型。

    所有参数通过 config 传入，不读写环境变量。
    模型格式为：`provider/model`，例如：
    - openai/gpt-4o
    - anthropic/claude-3-sonnet-20240229
    - azure/your-deployment-name
    - ollama/llama2（本地）
    - 自建服务：config 中设置 base_url，model 用 openai/your-model 或 custom/your-model
    """

    def __init__(self, config: LLMConfig):
        """
        初始化 LLM 客户端。

        Args:
            config: LLM 配置（api_key、base_url、api_version 等均通过 config 传入）
        """
        self.MAX_RETRIES = 3
        if litellm_completion is None:
            raise ImportError("请安装 litellm: pip install litellm")
        self.config = config

    def _is_openai_compatible(self, provider: str, api_base: Optional[str]) -> bool:
        """是否应按 OpenAI 兼容端点调用。

        判定优先级：
        1) type 显式声明为兼容端点（openai_compatible/custom/oneapi 等）；
        2) 配置了 base_url，但 provider 不在 litellm 原生白名单里（自建/聚合代理，
           或下拉里选了 litellm 不识别的厂商名）。
        """
        tp = (self.config.type or "").strip().lower()
        if tp in _COMPATIBLE_TYPES:
            return True
        if api_base and provider and provider.lower() not in _litellm_native_providers():
            return True
        return False

    def _litellm_kwargs(self, temperature: float = 0.7, max_tokens: Optional[int] = None, **kwargs) -> Dict:
        """从 config 构建 litellm completion 参数，不依赖环境变量"""
        provider = (self.config.provider or "").strip()
        model = (self.config.model or "").strip()
        # base_url：自建或自定义端点；Azure 时也可用 azure_endpoint
        api_base = self.config.base_url or getattr(self.config, "azure_endpoint", None)
        openai_compatible = self._is_openai_compatible(provider, api_base)

        if openai_compatible:
            # 兼容端点：原样使用配置的 model id（可能含 "/", 如聚合代理的 "org/model"），
            # 仅去掉用户误加的 "openai/" 前缀，避免 "openai/openai/..."。
            full_model = model[len("openai/"):] if model.startswith("openai/") else model
        elif "/" in model:
            full_model = model
        elif provider:
            full_model = f"{provider}/{model}"
        else:
            full_model = model

        kw: Dict = {
            "model": full_model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            # 自动丢弃目标端点不支持的参数（部分代理对 temperature/max_tokens 等会 400）
            "drop_params": True,
        }
        if openai_compatible:
            # 让 litellm 走 OpenAI 兼容客户端，直连 api_base，而非按品牌名解析路由
            kw["custom_llm_provider"] = "openai"
        if self.config.api_key:
            kw["api_key"] = self.config.api_key
        if api_base and self.config.type != "builtin":
            kw["api_base"] = api_base
        if getattr(self.config, "api_version", None):
            kw["api_version"] = self.config.api_version
        kw.update(kwargs)
        return {k: v for k, v in kw.items() if v is not None}

    def _is_retryable_error(self, exc: BaseException) -> bool:
        """判断 LLM 调用异常是否为可重试的瞬时错误。

        鉴权失败 / 额度不足 / 请求非法 / 上下文超长等视为致命，立即失败，
        不做无意义的重试。
        """
        # 通过异常类型名匹配，避免不同 litellm 版本类路径差异导致 import 失败
        for klass in type(exc).__mro__:
            if klass.__name__ in _RETRYABLE_EXC_NAMES:
                return True
        return False

    def _parse_usage(self, response) -> tuple[int, int, int, int]:
        """从 LiteLLM 响应中解析 usage，返回 (prompt_tokens, completion_tokens, total_tokens, cached_tokens)"""
        prompt_tokens = completion_tokens = total_tokens = cached_tokens = 0
        if getattr(response, "usage", None):
            u = response.usage
            prompt_tokens = getattr(u, "prompt_tokens", 0) or 0
            completion_tokens = getattr(u, "completion_tokens", 0) or 0
            total_tokens = getattr(u, "total_tokens", 0) or (prompt_tokens + completion_tokens)
            # 提取 prompt caching 命中的 token 数
            prompt_details = getattr(u, "prompt_tokens_details", None)
            if prompt_details:
                cached_tokens = getattr(prompt_details, "cached_tokens", 0) or 0
        return (prompt_tokens, completion_tokens, total_tokens, cached_tokens)

    def call(
            self,
            messages: List[Dict[str, str]],
            temperature: float = 0.7,
            max_tokens: Optional[int] = None,
            **kwargs,
    ) -> LLMResponse:
        """
        调用 LLM 接口。

        Args:
            messages: 消息列表，格式为 [{"role": "user", "content": "..."}]
            temperature: 温度参数
            max_tokens: 最大 token 数
            **kwargs: 其他 LiteLLM 支持的参数（如 stream=True）

        Returns:
            LLMResponse：包含 content（回复文本）与 prompt_tokens/completion_tokens/total_tokens

        Raises:
            LLMError: 调用失败（鉴权/额度/网络/服务异常等），属于致命错误，
                调用方不应吞掉，应让其向上传播以将任务标记为 failed。
        """
        litellm_kw = self._litellm_kwargs(
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        # 强制超时：litellm 默认无超时，API 挂起时永久阻塞
        litellm_kw.setdefault("timeout", 120)
        last_exc: Optional[BaseException] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                response = litellm_completion(
                    messages=messages,
                    **litellm_kw,
                )
            except Exception as e:
                last_exc = e
                retryable = self._is_retryable_error(e)
                status_code = getattr(e, "status_code", None)
                if retryable and attempt < self.MAX_RETRIES:
                    sleep_s = min(2 ** (attempt - 1), 8)
                    logger.warning(
                        "LLM 调用瞬时错误，第 %d/%d 次尝试失败，%ss 后重试: %r",
                        attempt, self.MAX_RETRIES, sleep_s, e,
                    )
                    time.sleep(sleep_s)
                    continue
                # 错误信息附带诊断上下文（model / api_base / provider，绝不含 api_key），
                # 便于排查 "provider/代理调不通"：是路由没走对，还是端点不通。
                diag = (
                    f"model={litellm_kw.get('model')!r} "
                    f"api_base={litellm_kw.get('api_base')!r} "
                    f"custom_llm_provider={litellm_kw.get('custom_llm_provider')!r}"
                )
                raise LLMError(
                    f"LLM 调用失败: {e} [{diag}]",
                    original=e,
                    retryable=retryable,
                    status_code=status_code,
                ) from e

            # 边界保护：部分代理/网关异常时可能返回无 choices 或结构异常的响应，
            # 直接索引 choices[0] 会抛 IndexError/AttributeError（裸异常、不可重试），
            # 这里统一收敛为"空 content"分支，交由下方退避重试逻辑处理。
            choices = getattr(response, "choices", None) or []
            if choices:
                message = getattr(choices[0], "message", None)
                content = (getattr(message, "content", None) or "") if message else ""
            else:
                content = ""

            # ------------------------------------------------------------
            # 空/异常的 LLM 响应检测
            #
            # 部分 API 网关/代理在上游限流或服务异常时，可能将实际错误
            # （429 Too Many Requests / 503 Service Unavailable）包装为
            # HTTP 200 OK 但返回空 content 或极短无效内容。
            #
            # 此类响应对调用方表现为"成功但非 JSON 对象"消息，排查困难。
            # 统一按可重试瞬时错误处理，让外层 retry 循环自动退避重试。
            # ------------------------------------------------------------
            content_stripped = content.strip()
            if not content_stripped:
                last_exc = LLMError(
                    "LLM 返回空 content（可能 API 网关吞掉了错误状态码）",
                    retryable=True,
                )
                if attempt < self.MAX_RETRIES:
                    sleep_s = min(2 ** (attempt - 1), 8)
                    logger.warning(
                        "LLM 返回空 content，第 %d/%d 次尝试，%ss 后重试",
                        attempt, self.MAX_RETRIES, sleep_s,
                    )
                    time.sleep(sleep_s)
                    continue
                raise last_exc

            prompt_tokens, completion_tokens, total_tokens, cached_tokens = self._parse_usage(response)
            return LLMResponse(
                content=content,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cached_tokens=cached_tokens,
                raw=response,
            )

        # 理论上不可达：重试循环只会以 return 或 raise 结束
        raise LLMError(f"LLM 调用失败: {last_exc}", original=last_exc, retryable=True)



    def supports_streaming(self) -> bool:
        """LiteLLM 支持流式，传 stream=True 即可"""
        return True

    def supports_json_mode(self) -> bool:
        """部分模型支持 response_format json_object"""
        return True
