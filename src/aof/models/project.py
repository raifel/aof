"""aof.yaml: the root of an app's onboarding contract."""

from __future__ import annotations

from pydantic import Field, PositiveFloat, PositiveInt, model_validator

from ..enums import AutonomyLevel, Pattern, RiskTier
from .base import Signoff, Strict


class AppInfo(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,62}$")
    description: str = ""
    owner: str  # owning team
    on_call: str  # rota / escalation alias
    user_facing: bool = True  # user-facing agents act on behalf of the signed-in user


class Autonomy(Strict):
    current: AutonomyLevel = AutonomyLevel.L0  # approved level the gateway enforces
    target: AutonomyLevel  # level this onboarding asks for

    @model_validator(mode="after")
    def _target_not_below_current(self) -> "Autonomy":
        if self.target < self.current:
            raise ValueError("autonomy.target cannot be below autonomy.current")
        return self


class McpServerRef(Strict):
    """Either a server in this repo or a managed one (for data-only apps)."""

    path: str | None = None
    command: list[str] | None = None  # how to launch it over stdio for conformance checks
    managed: str | None = None  # e.g. "snowflake" for a Snowflake-managed MCP server

    @model_validator(mode="after")
    def _one_of(self) -> "McpServerRef":
        if bool(self.path) == bool(self.managed):
            raise ValueError("set exactly one of mcp_server.path or mcp_server.managed")
        return self


class Budgets(Strict):
    """App budgets may only tighten the platform's, never loosen them."""

    max_steps_per_run: PositiveInt | None = None
    max_delegation_depth: PositiveInt | None = None
    max_cost_usd_per_run: PositiveFloat | None = None


class Artefacts(Strict):
    """Paths, relative to the repo root. Defaults are the template layout."""

    use_case: str = "aof/use-case.yaml"
    readiness: str = "aof/readiness.yaml"
    manifest: str = "aof/tools.manifest.yaml"
    data_contracts: str = "aof/data-contracts"
    registry: str = "server.json"
    agent_card: str = "agent-card.json"
    eval_suite: str = "evals/suite.yaml"
    eval_results: str = "evals/results.json"
    pilot_results: str = "evals/pilot.json"
    agents_md: str = "AGENTS.md"
    runbook: str = "RUNBOOK.md"


class Approvals(Strict):
    architecture_review: Signoff | None = None  # pattern + autonomy level sign-off
    review_board: Signoff | None = None  # required for T3 apps and L3+ promotion


class Project(Strict):
    aof_version: str
    app: AppInfo
    risk_tier: RiskTier  # highest tier of any delegated action
    pattern: Pattern
    pattern_justification: str | None = None  # required for agentic patterns
    autonomy: Autonomy
    hosts_agent: bool = False  # app exposes its own agent over A2A
    mcp_server: McpServerRef
    budgets: Budgets = Budgets()
    approvals: Approvals = Approvals()
    artefacts: Artefacts = Artefacts()
