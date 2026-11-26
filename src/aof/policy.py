"""Policy compiler.

Two jobs:
  1. `check_policy` enforces the risk-tier and autonomy rules on the tool manifest and
     fails the build when, for example, a write tool lacks an approval rule.
  2. `compile_policy` turns a clean manifest into the gateway policy document the
     shared agent gateway enforces on every call (default deny).

Runtime enforcement uses the *approved* autonomy level (`autonomy.current`); build-time
checks use the *requested* level (`autonomy.target`). Autonomy is earned.
"""

from __future__ import annotations

from typing import Any

from . import CONTRACT_VERSION
from .enums import (
    Access,
    ApprovalMode,
    AutonomyLevel,
    READ_ONLY_LEVELS,
    Reversibility,
    RiskTier,
)
from .findings import Finding, error, info, warning
from .models import Project, Tool, ToolManifest
from .platform import PlatformConfig

A = "tools.manifest"


class PolicyError(Exception):
    def __init__(self, findings: list[Finding]):
        self.findings = findings
        super().__init__(f"{len(findings)} policy error(s)")


def _check_tool(t: Tool, project: Project) -> list[Finding]:
    out: list[Finding] = []
    where = f"{A}:{t.name}"
    mode = t.approval.mode if t.approval else None

    if t.risk_tier is RiskTier.T4:
        out.append(info("AOF-P013", where, "T4 tool will be compiled as deny at the gateway"))
        return out

    if t.risk_tier > project.risk_tier:
        out.append(error("AOF-P002", where,
                         f"tool tier {t.risk_tier.value} exceeds app tier {project.risk_tier.value}",
                         "raise the app risk_tier (re-triage) or lower the tool's tier"))

    if t.executes_code:
        if not t.sandboxed:
            out.append(error("AOF-P011", where, "code-running tool must be sandboxed (ASI05)"))
        if t.risk_tier < RiskTier.T3:
            out.append(error("AOF-P011", where, "no code or shell tools at T1-T2 (ASI05)"))

    if t.access is Access.READ:
        if not t.scopes:
            out.append(warning("AOF-P009", where, "read tool declares no scopes",
                               "least privilege: name the narrowest scope it needs"))
        if mode is ApprovalMode.SAMPLED and t.approval and t.approval.sample_rate is None:
            out.append(warning("AOF-P014", where, "sampled review without sample_rate; gateway uses 0.05"))
        return out

    # ---- write tools ----
    if t.approval is None:
        out.append(error("AOF-P001", where, "write tool lacks an approval rule",
                         "add approval.mode: per_action | within_limits"))
    if t.risk_tier is RiskTier.T1:
        out.append(error("AOF-P006", where, "write tools are T2 or higher; T1 is read/draft/search only"))
    if t.reversibility is None:
        out.append(error("AOF-P008", where, "write tool must declare reversibility"))
    elif t.reversibility is Reversibility.IRREVERSIBLE and t.risk_tier < RiskTier.T3:
        out.append(error("AOF-P007", where, "irreversible writes are T3: they need explicit human approval"))
    if not t.scopes:
        out.append(error("AOF-P009", where, "write tool must declare its required scopes"))
    if t.rate_limit is None:
        out.append(error("AOF-P010", where, "write tool must declare a rate limit"))
    if not t.idempotent and not t.idempotency_key:
        out.append(warning("AOF-P012", where, "non-idempotent write has no idempotency_key",
                           "retries may duplicate the side effect"))

    if t.risk_tier is RiskTier.T3:
        if mode is not None and mode is not ApprovalMode.PER_ACTION:
            out.append(error("AOF-P003", where, "T3 actions need explicit human approval per action"))
        if not t.supports_dry_run:
            out.append(error("AOF-P004", where, "T3 actions need a dry-run preview for the approver",
                             "set supports_dry_run: true and implement dry_run in the tool"))
    elif t.risk_tier is RiskTier.T2 and mode is not None:
        if mode in (ApprovalMode.NONE, ApprovalMode.SAMPLED):
            out.append(error("AOF-P005", where,
                             "T2 writes auto-execute only within limits: use within_limits or per_action"))
        elif mode is ApprovalMode.WITHIN_LIMITS and (t.approval.limits is None or t.approval.limits.is_empty()):
            out.append(error("AOF-P005", where, "within_limits approval must define amount, rate or scope limits"))

    return out


def check_policy(project: Project, manifest: ToolManifest, platform: PlatformConfig) -> list[Finding]:
    out: list[Finding] = []
    target = project.autonomy.target

    if project.risk_tier is RiskTier.T4:
        out.append(error("AOF-P020", "aof.yaml", "an app cannot be onboarded at T4: T4 actions are never delegated"))

    for t in manifest.tools:
        out.extend(_check_tool(t, project))

    delegable_writes = [t for t in manifest.write_tools if t.risk_tier is not RiskTier.T4]
    if target in READ_ONLY_LEVELS and delegable_writes:
        names = ", ".join(t.name for t in delegable_writes)
        out.append(error("AOF-P021", "aof.yaml",
                         f"target autonomy {target.value} is read-only but the manifest has write tools: {names}",
                         "request L2+ or mark the tools T4 until the app is ready"))
    if target is AutonomyLevel.L2:
        for t in delegable_writes:
            if t.approval and t.approval.mode is not ApprovalMode.PER_ACTION:
                out.append(error("AOF-P022", f"{A}:{t.name}",
                                 "at L2 a human approves every write: approval.mode must be per_action",
                                 "keep the limits; they take effect at L3"))
    if target is AutonomyLevel.L4 and not project.hosts_agent:
        out.append(error("AOF-P023", "aof.yaml", "L4 (delegated multi-agent) requires hosts_agent and an A2A agent card"))

    delegable = [t.risk_tier for t in manifest.tools if t.risk_tier is not RiskTier.T4]
    if delegable and max(delegable) < project.risk_tier:
        out.append(info("AOF-P024", "aof.yaml",
                        f"app tier {project.risk_tier.value} is above its highest tool tier {max(delegable).value}"))

    pb, ab = platform.budgets, project.budgets
    for name in ("max_steps_per_run", "max_delegation_depth", "max_cost_usd_per_run"):
        app_v, plat_v = getattr(ab, name), getattr(pb, name)
        if app_v is not None and app_v > plat_v:
            out.append(error("AOF-P025", "aof.yaml",
                             f"budgets.{name}={app_v} exceeds the platform ceiling {plat_v}"))

    if platform.telemetry.genai_semconv_version == "PIN_ME":
        out.append(warning("AOF-P030", "platform.yaml",
                           "OTel GenAI semconv version is not pinned",
                           "platform team: pin telemetry.genai_semconv_version"))
    return out


# --------------------------------------------------------------------------- compile


def decide(t: Tool, level: AutonomyLevel) -> tuple[str, str]:
    """Gateway decision for one tool at an approved autonomy level."""
    if t.risk_tier is RiskTier.T4:
        return "deny", "T4: never delegated"
    mode = t.approval.mode if t.approval else None
    if t.access is Access.READ:
        if mode is ApprovalMode.PER_ACTION:
            return "require_approval", "read tool marked per_action"
        return "allow", "read"
    if level in READ_ONLY_LEVELS:
        return "deny", f"approved level {level.value} is read-only"
    if mode is None:
        return "deny", "write tool has no approval rule"
    if level is AutonomyLevel.L2 or t.risk_tier >= RiskTier.T3 or mode is ApprovalMode.PER_ACTION:
        return "require_approval", "human approves this write"
    if mode is ApprovalMode.WITHIN_LIMITS:
        return "allow_within_limits", "bounded autonomy"
    return "deny", f"approval mode {mode.value} not valid for writes"


def _effective_budgets(project: Project, platform: PlatformConfig) -> dict[str, Any]:
    out = {}
    for name, plat_v in platform.budgets.model_dump().items():
        app_v = getattr(project.budgets, name)
        out[name] = plat_v if app_v is None else min(app_v, plat_v)
    return out


def compile_policy(project: Project, manifest: ToolManifest, platform: PlatformConfig) -> dict[str, Any]:
    errors = [f for f in check_policy(project, manifest, platform) if f.severity.value == "error"]
    if errors:
        raise PolicyError(errors)

    level = project.autonomy.current
    budgets = _effective_budgets(project, platform)
    tools = []
    for t in manifest.tools:
        decision, reason = decide(t, level)
        entry: dict[str, Any] = {
            "name": t.name,
            "access": t.access.value,
            "risk_tier": t.risk_tier.value,
            "decision": decision,
            "reason": reason,
            "scopes": t.scopes,
            "reads": t.reads,
        }
        if t.rate_limit:
            entry["rate_limit"] = t.rate_limit.model_dump()
        if t.approval:
            if t.approval.limits and not t.approval.limits.is_empty():
                entry["limits"] = t.approval.limits.model_dump(exclude_none=True)
            if t.approval.mode is ApprovalMode.SAMPLED:
                entry["sample_rate"] = t.approval.sample_rate if t.approval.sample_rate is not None else 0.05
            if t.approval.approver_role:
                entry["approver_role"] = t.approval.approver_role
        if decision == "require_approval" and t.access is Access.WRITE:
            entry["dry_run_preview"] = t.supports_dry_run
            entry["bulk_approval"] = False  # ASI09: no rubber-stamp bulk approvals
        if t.reversibility:
            entry["reversibility"] = t.reversibility.value
        if t.executes_code:
            entry["sandbox"] = True
        tools.append(entry)

    return {
        "aof_policy_version": CONTRACT_VERSION,
        "default": "deny",
        "agent": {
            "id": f"agent:{project.app.name}",
            "owner": project.app.owner,
            "on_call": project.app.on_call,
            "risk_tier": project.risk_tier.value,
            "autonomy_level": level.value,
            "autonomy_target": project.autonomy.target.value,
        },
        "source": {"mcp_server": manifest.server, "manifest_version": manifest.version},
        "identity": {
            "mode": "on_behalf_of" if project.app.user_facing else "workload",
            "token_exchange": platform.identity.token_exchange if project.app.user_facing else None,
            "scope_ttl_seconds": platform.identity.scope_ttl_seconds,
            "shared_service_account": False,
            "credentials_in_context": False,
        },
        "budgets": budgets,
        "tools": tools,
        "a2a": {
            "enabled": project.hosts_agent and level >= AutonomyLevel.L4,
            "mtls": True,
            "verify_agent_cards": True,
            "max_delegation_depth": budgets["max_delegation_depth"],
        },
        "memory": {"scope": "per_user_per_tenant", "provenance": True, "ttl_required": True},
        "kill_switch": {"enabled": True, "runbook": project.artefacts.runbook},
        "telemetry": {
            "otel_genai_semconv": platform.telemetry.genai_semconv_version,
            "audit": "all_calls",
        },
        "slos": {
            **platform.slos.model_dump(),
            "on_breach": "demote_one_autonomy_level",
        },
    }
