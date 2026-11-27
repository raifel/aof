"""Platform configuration (owned by the platform team)."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml
from pydantic import Field, PositiveFloat, PositiveInt

from pydantic import model_validator

from .enums import Classification, DataSafetyMode, Exposure, RiskTier
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
    issuer: str | None = None
    jwks_uri: str | None = None
    algorithms: list[str] = ["RS256", "PS256", "ES256", "EdDSA"]
    roles_claim: str = "roles"
    tenant_claim: str | None = "tenant"
    leeway_seconds: int = Field(default=60, ge=0, le=300)
    operator_role: str = "aof-operator"


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
    no_leak_rate: float = Field(default=1.0, ge=0, le=1)  # required from apps with governed reads


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


class QueryLimitsCfg(Strict):
    max_queries_per_run: PositiveInt = 20
    max_rows_ceiling: PositiveInt
    timeout_seconds_ceiling: PositiveInt
    max_bytes_scanned_ceiling: PositiveInt
    allowed_functions: list[str]  # SQL function names the guard accepts (upper case)


class ProviderCfg(Strict):
    zero_data_retention: str = Field(default="required", pattern=r"^(required|recommended|not_required)$")


class VaultCfg(Strict):
    ttl_seconds: PositiveInt = 3600
    max_bytes_per_result: PositiveInt = 5_000_000
    model_preview_rows: int = Field(default=20, ge=0)  # visible rows the agent gets back
    reader_clients: list[str] = []  # OAuth client ids that may read GET /results (the app's UI)


class CustomPatternCfg(Strict):
    regex: str
    action: str = Field(default="block", pattern=r"^(block|redact|off)$")


class EgressCfg(Strict):
    """Checks on model requests (POST /v1/messages) before they leave for the provider."""

    detectors: dict[str, str] = {"iban": "redact", "card_number": "block", "email": "redact", "phone": "redact"}
    custom_patterns: dict[str, CustomPatternCfg] = {}  # e.g. national ids, internal account formats
    non_text: str = Field(default="block", pattern=r"^(block|allow)$")  # images, documents
    fingerprints: bool = True  # block requests carrying values from vaulted results
    max_fingerprints_per_user: PositiveInt = 20000

    @model_validator(mode="after")
    def _known(self) -> "EgressCfg":
        bad = {k for k in self.detectors if k not in ("iban", "card_number", "email", "phone")}
        if bad:
            raise ValueError(f"unknown egress detectors {sorted(bad)}; add them as custom_patterns")
        bad_actions = {v for v in self.detectors.values() if v not in ("block", "redact", "off")}
        if bad_actions:
            raise ValueError(f"egress detector actions are block, redact or off, not {sorted(bad_actions)}")
        import re
        for name, spec in self.custom_patterns.items():
            try:
                re.compile(spec.regex)
            except re.error as exc:
                raise ValueError(f"egress.custom_patterns.{name}: {exc}") from None
        return self


class DataSafetyCfg(Strict):
    # What the gateway does with results of tools that read governed data:
    # enforce = vault them and return a handle; shadow = vault and audit, return them
    # unchanged; off = return them unchanged.
    results: str = Field(default="shadow", pattern=r"^(enforce|shadow|off)$")
    default_mode: DataSafetyMode = DataSafetyMode.METADATA_ONLY
    metadata_only_from_tier: RiskTier = RiskTier.T3  # apps at this tier or above must use it
    default_exposure: dict[Classification, Exposure]
    exposure_ceiling: dict[Classification, Exposure]
    min_group_size: PositiveInt = 10
    row_count_buckets: list[int] = [0, 1, 10, 100, 1000, 10000]
    row_filter_claims: dict[str, str] = {}  # name used in contracts -> dotted token claim path
    provider: ProviderCfg = ProviderCfg()
    vault: VaultCfg = VaultCfg()
    egress: EgressCfg = EgressCfg()
    query: QueryLimitsCfg

    @model_validator(mode="after")
    def _complete(self) -> "DataSafetyCfg":
        for name in ("default_exposure", "exposure_ceiling"):
            missing = set(Classification) - set(getattr(self, name))
            if missing:
                raise ValueError(f"data_safety.{name} lacks {sorted(c.value for c in missing)}")
        for c, e in self.default_exposure.items():
            if e > self.exposure_ceiling[c]:
                raise ValueError(f"data_safety.default_exposure.{c.value} exceeds its ceiling")
        return self


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
    data_safety: DataSafetyCfg


def load_platform(path: str | Path | None = None) -> PlatformConfig:
    if path is None:
        text = resources.files("aof").joinpath("platform.yaml").read_text()
    else:
        text = Path(path).read_text()
    return PlatformConfig.model_validate(yaml.safe_load(text))
