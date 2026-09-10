# pyright: reportMissingImports=false

import logging
from time import monotonic
from typing import Any, AsyncGenerator

import httpx

from swx_core.contracts.llm import LLMRequest, LLMResponse, ProviderHealthStatus, SSEEvent, ValidateProviderResult
from swx_core.services.llm.providers import BaseLLMProvider


logger = logging.getLogger(__name__)


class LlamaCppProvider(BaseLLMProvider):
    """llama.cpp server provider using its native /completion and /v1/chat/completions APIs.

    llama.cpp server supports both its native completion endpoint and an
    OpenAI-compatible /v1/chat/completions endpoint. Health is checked via
    /health and enriched with GPU/VRAM stats when available.
    """

    def __init__(
        self,
        base_url: str,
        provider_config: dict[str, Any] | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=float(provider_config.get("timeout_seconds", 120) if provider_config else 120),
        )
        self.config = provider_config or {}

    async def generate(self, request: LLMRequest) -> LLMResponse:
        started_at = monotonic()
        model_name = self.config.get("model_name", "default")
        try:
            messages: list[dict[str, str]] = []
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            messages.append({"role": "user", "content": request.prompt})

            payload: dict[str, Any] = {
                "messages": messages,
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
                "top_p": request.top_p,
                "stream": False,
            }
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
                provider="llamacpp",
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
                provider="llamacpp",
                latency_ms=int((monotonic() - started_at) * 1000),
            )

    async def stream(self, request: LLMRequest) -> AsyncGenerator[SSEEvent, None]:
        model_name = self.config.get("model_name", "default")
        messages: list[dict[str, str]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload: dict[str, Any] = {
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": True,
        }
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
            response = await self.client.get("/health")
            return response.is_success
        except Exception:
            return False

    async def health(self) -> ProviderHealthStatus:
        from time import monotonic as _monotonic
        started = _monotonic()
        try:
            health_response = await self.client.get("/health")
            latency_ms = (_monotonic() - started) * 1000

            if not health_response.is_success:
                return ProviderHealthStatus(
                    healthy=False,
                    latency_ms=round(latency_ms, 2),
                    model_loaded=False,
                    error=f"llama.cpp /health returned {health_response.status_code}",
                )

            vram_used_gb: float | None = None
            vram_total_gb: float | None = None
            gpu_utilization: float | None = None
            model_loaded = True

            try:
                health_data = health_response.json()
                if isinstance(health_data, dict):
                    status_val = health_data.get("status", "")
                    if status_val == "no slot available":
                        model_loaded = True
                    elif status_val == "loading":
                        model_loaded = False

                    vram_info = health_data.get("vram")
                    if isinstance(vram_info, dict):
                        vram_total_gb = vram_info.get("total_gb")
                        vram_used_gb = vram_info.get("used_gb")
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
            response = await self.client.get("/health")
            if response.is_success:
                return ValidateProviderResult(valid=True)
            return ValidateProviderResult(valid=False, error=f"llama.cpp returned status {response.status_code}")
        except Exception as exc:
            return ValidateProviderResult(valid=False, error=str(exc))

    async def list_models(self) -> list[str]:
        model_name = self.config.get("model_name", "default")
        return [model_name]