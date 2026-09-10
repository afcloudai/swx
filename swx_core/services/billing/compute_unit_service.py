"""Compute Unit Abstraction Layer — converts raw token counts to compute units.

Different models consume different GPU time per token.  This service applies
configurable model multipliers so that billing reflects actual compute cost
rather than misleading raw token counts.

Level definitions are loaded from ``settings.COMPUTE_UNIT_LEVELS`` and can be
overridden per-model via the ``register_multiplier`` method or by setting
``model_key`` in the configuration.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel

from swx_core.config.settings import settings


class ModelMultiplier(BaseModel):
    model_key: str
    level: str
    input_multiplier: float
    output_multiplier: float
    is_default: bool = False


class ComputeUnitResult(BaseModel):
    compute_units: float
    input_tokens: int
    output_tokens: int
    model_key: str
    level: str
    input_multiplier: float
    output_multiplier: float


def _default_multipliers_from_settings() -> dict[str, ModelMultiplier]:
    result: dict[str, ModelMultiplier] = {}
    levels = settings.COMPUTE_UNIT_LEVELS
    default_level = settings.COMPUTE_UNIT_DEFAULT_LEVEL
    pricing = settings.USAGE_METERING_MODEL_PRICING

    for model_key, pricing_info in pricing.items():
        level = default_level
        is_default = model_key == "default"
        result[model_key] = ModelMultiplier(
            model_key=model_key,
            level=level,
            input_multiplier=float(pricing_info.get("input", 1000)),
            output_multiplier=float(pricing_info.get("output", 3000)),
            is_default=is_default,
        )
    return result


class ComputeUnitService:
    """Converts raw token counts to compute units using model multipliers."""

    def __init__(self):
        self._multipliers: dict[str, ModelMultiplier] = _default_multipliers_from_settings()

    def calculate_cus(self, model_key: str, input_tokens: int, output_tokens: int) -> ComputeUnitResult:
        multiplier = self.get_multiplier(model_key)
        raw_cus = (input_tokens * multiplier.input_multiplier + output_tokens * multiplier.output_multiplier) / 1000
        decimals = settings.COMPUTE_UNIT_DECIMALS
        compute_units = round(raw_cus, decimals) if decimals > 0 else float(int(round(raw_cus)))
        return ComputeUnitResult(
            compute_units=compute_units,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model_key=multiplier.model_key,
            level=multiplier.level,
            input_multiplier=multiplier.input_multiplier,
            output_multiplier=multiplier.output_multiplier,
        )

    def get_multiplier(self, model_key: str) -> ModelMultiplier:
        if model_key in self._multipliers:
            return self._multipliers[model_key]
        default_key = settings.USAGE_METERING_DEFAULT_MODEL_KEY
        if default_key in self._multipliers:
            return self._multipliers[default_key]
        return ModelMultiplier(
            model_key=model_key,
            level=settings.COMPUTE_UNIT_DEFAULT_LEVEL,
            input_multiplier=1.0,
            output_multiplier=1.0,
            is_default=True,
        )

    def register_multiplier(self, multiplier: ModelMultiplier) -> None:
        self._multipliers[multiplier.model_key] = multiplier

    def list_multipliers(self) -> list[ModelMultiplier]:
        return list(self._multipliers.values())


_compute_unit_service: ComputeUnitService | None = None


def get_compute_unit_service() -> ComputeUnitService:
    global _compute_unit_service
    if _compute_unit_service is None:
        _compute_unit_service = ComputeUnitService()
    return _compute_unit_service