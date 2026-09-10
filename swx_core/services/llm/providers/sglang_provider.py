# pyright: reportMissingImports=false

import logging
from time import monotonic
from typing import Any, AsyncGenerator

import httpx

from swx_core.contracts.llm import LLMRequest, LLMResponse, ProviderHealthStatus, SSEEvent, ValidateProviderResult
from swx_core.services.llm.providers import BaseLLMProvider
from swx_core.services.llm.providers.openai_provider import _messages


logger = logging.getLogger(__name__)


class SGLangProvider(BaseLLMProvider):
    """SGLang provider using the OpenAI-compatible /v1 API.

    SGLang exposes an OpenAI-compatible endpoint at /v1/chat/completions.
    Health is checked via /v1/models and enriched via /health which
    returns GPU memory stats when available.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        provider_config: dict[str, Any] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=float(provider_config.get("timeout_seconds", 90) if provider_config else 90),
        )
        self.config = provider_config or {}

    async def generate(self, request: LLMRequest) -> LLMResponse:
        started_at = monotonic()
        model_name = self.config.get("model_name", "meta-llama/Meta-Llama-3.1-8B-Instruct")
        try:
            payload: dict[str, Any] = {
                "model": model_name,
                "messages": _messages(request),
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
                "top_p": request.top_p,
                "stream": False,
            }
            if request.json_mode:
                payload["response_format"] = {"type": "json_object"}
            if request.stop_sequences:
                payload["stop"] = request.stop_sequences

            response = await self.client.post("/v1/chat/completions", json=payload)
            response.raise_for_status()
            data = response.json()

            usage = data.get("usage", {})
            return LLMResponse(
                True,
                data["choices"][0]["message"]["content"] or "",
                model=data.get("model", model_name),
                provider="sglang",
                tokens_used=int(usage.get("total_tokens", 0)),
                prompt_tokens=int(usage.get("prompt_tokens", 0)),
                completion_tokens=int(usage.get("completion_tokens", 0)),
                latency_ms=int((monotonic() - started_at) * 1000),
            )
        except Exception as exc:
            logger.error("LLM provider %s failed: %s", self.__class__.__name__, exc)
            return LLMResponse(
                False,
                "",
                error=str(exc),
                model=model_name,
                provider="sglang",
                latency_ms=int((monotonic() - started_at) * 1000),
            )

    async def stream(self, request: LLMRequest) -> AsyncGenerator[SSEEvent, None]:
        model_name = self.config.get("model_name", "meta-llama/Meta-Llama-3.1-8B-Instruct")
        payload: dict[str, Any] = {
            "model": model_name,
            "messages": _messages(request),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": True,
        }
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        if request.stop_sequences:
            payload["stop"] = request.stop_sequences

        prompt_tokens = 0
        completion_tokens = 0
        try:
            async with self.client.stream("POST", "/v1/chat/completions", json=payload) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        import json
                        chunk = json.loads(data_str)
                    except Exception:
                        continue
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield SSEEvent(event_type="text_delta", data=content)
                    usage = chunk.get("usage")
                    if usage:
                        prompt_tokens = int(usage.get("prompt_tokens", 0))
                        completion_tokens = int(usage.get("completion_tokens", 0))

            if prompt_tokens or completion_tokens:
                yield SSEEvent(
                    event_type="usage",
                    data={
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": prompt_tokens + completion_tokens,
                    },
                )
            yield SSEEvent(event_type="done")
        except Exception as exc:
            yield SSEEvent(event_type="error", data={"code": "STREAM_ERROR", "message": str(exc)})
            raise

    async def health_check(self) -> bool:
        try:
            response = await self.client.get("/v1/models")
            return response.is_success
        except Exception:
            return False

    async def health(self) -> ProviderHealthStatus:
        from time import monotonic as _monotonic
        started = _monotonic()
        try:
            models_response = await self.client.get("/v1/models")
            latency_ms = (_monotonic() - started) * 1000
            if not models_response.is_success:
                return ProviderHealthStatus(
                    healthy=False,
                    latency_ms=round(latency_ms, 2),
                    model_loaded=False,
                    error=f"SGLang /v1/models returned {models_response.status_code}",
                )

            model_loaded = True
            vram_used_gb: float | None = None
            vram_total_gb: float | None = None
            gpu_utilization: float | None = None

            try:
                health_response = await self.client.get("/health")
                if health_response.is_success:
                    health_data = health_response.json()
                    mem_info = health_data.get("mem_pool_usage") or {}
                    if isinstance(mem_info, dict):
                        vram_used_gb = mem_info.get("vram_used_gb")
                        vram_total_gb = mem_info.get("vram_total_gb")
                    gpu_util_pct = health_data.get("gpu_utilization")
                    if gpu_util_pct is not None:
                        gpu_utilization = float(gpu_util_pct)
            except Exception:
                pass

            return ProviderHealthStatus(
                healthy=True,
                latency_ms=round(latency_ms, 2),
                model_loaded=model_loaded,
                gpu_utilization=gpu_utilization,
                vram_used_gb=vram_used_gb,
                vram_total_gb=vram_total_gb,
            )
        except Exception as exc:
            latency_ms = (_monotonic() - started) * 1000
            return ProviderHealthStatus(
                healthy=False,
                latency_ms=round(latency_ms, 2),
                model_loaded=False,
                error=str(exc),
            )

    async def validate_api_key(self) -> ValidateProviderResult:
        try:
            response = await self.client.get("/v1/models")
            if response.is_success:
                data = response.json()
                model_ids = sorted(m.get("id", "") for m in data.get("data", []))
                return ValidateProviderResult(valid=True, models=model_ids)
            return ValidateProviderResult(valid=False, error=f"SGLang returned status {response.status_code}")
        except Exception as exc:
            return ValidateProviderResult(valid=False, error=str(exc))

    async def list_models(self) -> list[str]:
        try:
            response = await self.client.get("/v1/models")
            if response.is_success:
                data = response.json()
                return sorted(m.get("id", "") for m in data.get("data", []))
            return []
        except Exception:
            return []