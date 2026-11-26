"""Tool manifest: the policy-relevant facts about every tool an app exposes."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, NonNegativeFloat, PositiveInt, field_validator

from ..enums import Access, ApprovalMode, Reversibility, RiskTier
from .base import Strict


class Param(Strict):
    type: Literal["string", "integer", "number", "boolean", "array", "object"]
    description: str = ""
    enum: list[Any] | None = None
    required: bool = True
    format: str | None = None  # e.g. date, uuid, email


class RateLimit(Strict):
    calls: PositiveInt
    per: Literal["second", "minute", "hour", "day"]


class Limits(Strict):
    max_amount: NonNegativeFloat | None = None
    currency: str | None = None
    max_per_hour: PositiveInt | None = None
    scope: str | None = None  # e.g. "own_tickets", "region:EU"

    def is_empty(self) -> bool:
        return all(v is None for v in self.model_dump().values())


class Approval(Strict):
    mode: ApprovalMode
    sample_rate: float | None = Field(default=None, ge=0, le=1)
    limits: Limits | None = None
    approver_role: str | None = None


class Tool(Strict):
    name: str
    description: str = ""
    example: str = ""
    not_for: str | None = None  # boundary with similar tools
    access: Access
    risk_tier: RiskTier
    side_effects: list[str] = []
    idempotent: bool = False
    idempotency_key: str | None = None
    scopes: list[str] = []
    rate_limit: RateLimit | None = None
    approval: Approval | None = None
    reversibility: Reversibility | None = None
    supports_dry_run: bool = False
    executes_code: bool = False
    sandboxed: bool = False
    reads: list[str] = []  # semantic views / data products (must have data contracts)
    params: dict[str, Param] = {}


class ToolManifest(Strict):
    server: str  # registry name of the MCP server
    version: str
    tools: list[Tool] = Field(min_length=1)

    @field_validator("tools")
    @classmethod
    def _unique_names(cls, tools: list[Tool]) -> list[Tool]:
        seen: set[str] = set()
        for t in tools:
            if t.name in seen:
                raise ValueError(f"duplicate tool name: {t.name}")
            seen.add(t.name)
        return tools

    def tool(self, name: str) -> Tool | None:
        return next((t for t in self.tools if t.name == name), None)

    @property
    def write_tools(self) -> list[Tool]:
        return [t for t in self.tools if t.access is Access.WRITE]
