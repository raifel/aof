"""Platform configuration (owned by the platform team)."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml
from pydantic import Field, PositiveFloat, PositiveInt

from .enums import RiskTier
from .models.base import Strict


class RegistryCfg(Strict):
    namespace_prefix: str
    allowed_remote_types: list[str] = ["streamable-http"]


class BudgetsCfg(Strict):
    max_steps_per_run: PositiveInt
    max_delegation_depth: PositiveInt
    max_cost_usd_per_run: PositiveFloat


class IdentityCfg(Strict):
    scope_ttl_seconds: PositiveInt
    token_exchange: str
    token_endpoint: str | None = None


class TelemetryCfg(Strict):
    genai_semconv_version: str


class ToolsCfg(Strict):
    max_tools_per_server: PositiveInt
    min_description_chars: PositiveInt
    max_description_chars: PositiveInt


class GoldenSetCfg(Strict):
    min_cases: PositiveInt
    recommended_max: PositiveInt


class Thresholds(Strict):
    task_success: float = Field(ge=0, le=1)
    tool_call_accuracy: float = Field(ge=0, le=1)
    safety_pass_rate: float = Field(ge=0, le=1)


class PilotCfg(Strict):
    min_window_days: PositiveInt
    min_proposals: PositiveInt
    min_agreement_rate: dict[RiskTier, float]
    max_incidents: dict[RiskTier, int]


class SlosCfg(Strict):
    demotion_window_hours: PositiveInt
    p95_latency_ms: PositiveInt
    max_human_override_rate: float = Field(ge=0, le=1)
    max_policy_violations: int = Field(ge=0)


class Price(Strict):
    input: float = Field(ge=0)
    output: float = Field(ge=0)
    cache_read: float | None = Field(default=None, ge=0)


class LlmCfg(Strict):
    provider: str = "anthropic"
    default_model: str
    allowed_models: list[str]
    max_tokens_ceiling: PositiveInt
    max_model_calls_per_run: PositiveInt
    allowed_betas: list[str] = []
    allowed_server_tools: list[str] = []
    pricing_usd_per_mtok: dict[str, Price]
    cache_write_multiplier: float = 1.25
    fast_mode_multiplier: float = 2.0


class PlatformConfig(Strict):
    version: str
    registry: RegistryCfg
    budgets: BudgetsCfg
    identity: IdentityCfg
    telemetry: TelemetryCfg
    tools: ToolsCfg
    golden_set: GoldenSetCfg
    eval_thresholds: dict[RiskTier, Thresholds]
    pilot: PilotCfg
    slos: SlosCfg
    llm: LlmCfg | None = None


def load_platform(path: str | Path | None = None) -> PlatformConfig:
    if path is None:
        text = resources.files("aof").joinpath("platform.yaml").read_text()
    else:
        text = Path(path).read_text()
    return PlatformConfig.model_validate(yaml.safe_load(text))
