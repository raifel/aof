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


class CompiledPolicy(_M):
    aof_policy_version: str
    default: Literal["deny"]
    agent: AgentInfo
    budgets: BudgetRule
    tools: list[ToolRule]
    slos: SloRule = SloRule()

    def rule(self, tool: str) -> ToolRule | None:
        return next((t for t in self.tools if t.name == tool), None)


def load_policy(path: str | Path) -> CompiledPolicy:
    return CompiledPolicy.model_validate(json.loads(Path(path).read_text()))
