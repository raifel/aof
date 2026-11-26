"""The compiled gateway policy (output of `aof compile-policy`) as the gateway reads it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from ..enums import AutonomyLevel, RiskTier

Decision = Literal["allow", "allow_within_limits", "require_approval", "deny"]


class _M(BaseModel):
    model_config = ConfigDict(extra="allow")


class RateLimitRule(_M):
    calls: int
    per: Literal["second", "minute", "hour", "day"]

    @property
    def window_seconds(self) -> int:
        return {"second": 1, "minute": 60, "hour": 3600, "day": 86400}[self.per]


class ToolRule(_M):
    name: str
    access: Literal["read", "write"]
    risk_tier: RiskTier
    decision: Decision
    reason: str = ""
    scopes: list[str] = []
    reads: list[str] = []
    rate_limit: RateLimitRule | None = None
    limits: dict[str, Any] | None = None
    sample_rate: float | None = None
    approver_role: str | None = None
    dry_run_preview: bool = False
    reversibility: str | None = None


class AgentInfo(_M):
    id: str
    owner: str
    on_call: str
    risk_tier: RiskTier
    autonomy_level: AutonomyLevel
    autonomy_target: AutonomyLevel


class BudgetRule(_M):
    max_steps_per_run: int
    max_delegation_depth: int
    max_cost_usd_per_run: float


class SloRule(_M):
    demotion_window_hours: int = 24
    max_policy_violations: int = 0


class PriceRule(_M):
    input: float
    output: float
    cache_read: float | None = None


class LlmRule(_M):
    provider: str = "anthropic"
    models: list[str]
    default_model: str
    max_tokens: int
    max_model_calls_per_run: int
    rate_limit: RateLimitRule | None = None
    allowed_betas: list[str] = []
    allowed_server_tools: list[str] = []
    pricing_usd_per_mtok: dict[str, PriceRule] = {}
    cache_write_multiplier: float = 1.25
    fast_mode_multiplier: float = 2.0


class A2aPeerRule(_M):
    name: str
    card_url: str
    skills: list[str]
    credential_env: str | None = None
    audience: str | None = None
    scopes: list[str] = []


class A2aRule(_M):
    enabled: bool = False
    inbound: bool = False
    max_delegation_depth: int = 3
    max_delegations_per_run: int = 5
    allowed_callers: list[str] = []
    peers: list[A2aPeerRule] = []

    def peer(self, name: str) -> A2aPeerRule | None:
        return next((p for p in self.peers if p.name == name), None)


class IdentityRule(_M):
    mode: Literal["on_behalf_of", "workload"] = "workload"
    token_exchange: str | None = None
    token_endpoint: str | None = None
    audience: str | None = None
    scope_ttl_seconds: int = 900


class CompiledPolicy(_M):
    aof_policy_version: str
    default: Literal["deny"]
    agent: AgentInfo
    budgets: BudgetRule
    tools: list[ToolRule]
    slos: SloRule = SloRule()
    llm: LlmRule | None = None
    a2a: A2aRule = A2aRule()
    identity: IdentityRule = IdentityRule()

    def rule(self, tool: str) -> ToolRule | None:
        return next((t for t in self.tools if t.name == tool), None)


def load_policy(path: str | Path) -> CompiledPolicy:
    return CompiledPolicy.model_validate(json.loads(Path(path).read_text()))
