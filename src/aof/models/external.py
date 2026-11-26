"""Artefacts that follow external specs: MCP Registry server.json and A2A agent card.

Only the fields AOF depends on are modelled; everything else passes through so the
files stay valid against the upstream schemas. Pin the upstream schema versions in
platform.yaml and validate against them in the registry service itself.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ..enums import AutonomyLevel, RiskTier
from .base import Open, Strict

AOF_META_KEY = "io.modelcontextprotocol.registry/publisher-provided"


class AofRegistryMeta(Strict):
    """AOF extension stored under _meta[publisher-provided]["aof"]."""

    owner: str
    risk_tier: RiskTier
    autonomy_level: AutonomyLevel
    on_call: str


class Remote(Open):
    type: str  # e.g. streamable-http
    url: str


class ServerJson(Open):
    name: str  # reverse-DNS, e.g. com.example/refunds
    description: str
    version: str
    remotes: list[Remote] = []
    packages: list[dict[str, Any]] = []
    meta: dict[str, Any] = Field(default_factory=dict, alias="_meta")

    def aof_meta(self) -> dict[str, Any] | None:
        provided = self.meta.get(AOF_META_KEY) or {}
        return provided.get("aof")


class AgentSkill(Open):
    id: str
    name: str
    description: str


class AgentCard(Open):
    name: str
    description: str
    url: str
    version: str
    skills: list[AgentSkill] = Field(min_length=1)
    securitySchemes: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
