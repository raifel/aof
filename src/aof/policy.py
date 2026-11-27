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

from typing import Any, Iterable

from . import CONTRACT_VERSION
from .enums import (
    Access,
    ApprovalMode,
    AutonomyLevel,
    DataSafetyMode,
    Exposure,
    READ_ONLY_LEVELS,
    Reversibility,
    RiskTier,
)
from .findings import Finding, error, info, warning
from .models import Project, Tool, ToolManifest
from .datasafety import effective_classification, views_from_contracts
from .models.data_contract import DataContract
from .models.project import A2aConfig
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

    out.extend(_check_llm(project, platform))
    out.extend(_check_a2a(project))
    out.extend(_check_data_safety(project, manifest, platform))
    ident = platform.identity
    for name in ("issuer", "jwks_uri"):
        url = getattr(ident, name)
        if url and not url.startswith("https://"):
            out.append(error("AOF-P061", "platform.yaml", f"identity.{name} must be https",
                             "token signing keys must come from an authenticated source"))
    weak = [a for a in ident.algorithms if a.lower() == "none" or a.upper().startswith("HS")]
    if weak:
        out.append(error("AOF-P062", "platform.yaml", f"identity.algorithms must be asymmetric; remove {weak}",
                         "HS* with a public key (JWKS) enables key-confusion forgery"))
    endpoint = platform.identity.token_endpoint
    if project.app.user_facing and endpoint and not endpoint.startswith("https://"):
        out.append(error("AOF-P060", "platform.yaml", "identity.token_endpoint must be https",
                         "user tokens are sent to it"))

    if platform.telemetry.genai_semconv_version == "PIN_ME":
        out.append(warning("AOF-P030", "platform.yaml",
                           "OTel GenAI semconv version is not pinned",
                           "platform team: pin telemetry.genai_semconv_version"))
    return out


def _check_llm(project: Project, platform: PlatformConfig) -> list[Finding]:
    if project.llm is None:
        return []
    if platform.llm is None:
        return [error("AOF-P040", "aof.yaml", "the platform does not offer model calls through the gateway")]
    cfg, plat, out = project.llm, platform.llm, []
    for m in cfg.models or [plat.default_model]:
        if m not in plat.allowed_models:
            out.append(error("AOF-P040", "aof.yaml", f"model {m} is not in the platform's allowed_models",
                             f"choose from {', '.join(plat.allowed_models)}"))
        elif m not in plat.pricing_usd_per_mtok:
            out.append(warning("AOF-P043", "platform.yaml",
                               f"no price for {m}: the gateway charges it at the highest listed price"))
    if cfg.max_tokens > plat.max_tokens_ceiling:
        out.append(error("AOF-P041", "aof.yaml",
                         f"llm.max_tokens {cfg.max_tokens} exceeds the platform ceiling {plat.max_tokens_ceiling}"))
    for t in cfg.allowed_server_tools:
        if t not in plat.allowed_server_tools:
            out.append(error("AOF-P042", "aof.yaml", f"server tool {t} is not allowed by the platform"))
    return out


def data_safety_mode(project: Project, platform: PlatformConfig) -> DataSafetyMode:
    return project.data_safety.mode or platform.data_safety.default_mode


_RESULTS_RANK = {"off": 0, "shadow": 1, "enforce": 2}


def data_safety_results(project: Project, platform: PlatformConfig) -> str:
    app, plat = project.data_safety.results, platform.data_safety.results
    return app if app and _RESULTS_RANK[app] > _RESULTS_RANK[plat] else plat


def _check_data_safety(project: Project, manifest: ToolManifest, platform: PlatformConfig) -> list[Finding]:
    ds, out = platform.data_safety, []
    if project.risk_tier >= ds.metadata_only_from_tier and data_safety_mode(project, platform) is not DataSafetyMode.METADATA_ONLY:
        out.append(error("AOF-P074", "aof.yaml",
                         f"{project.risk_tier.value} apps must use data_safety.mode: metadata_only",
                         f"the platform requires it from {ds.metadata_only_from_tier.value}"))
    if project.llm is not None and ds.provider.zero_data_retention == "required" and not project.llm.zero_data_retention:
        out.append(error("AOF-P073", "aof.yaml", "the platform requires zero data retention with the model provider",
                         "confirm the provider account's terms, then set llm.zero_data_retention: true"))
    app_results = project.data_safety.results
    if app_results and _RESULTS_RANK[app_results] < _RESULTS_RANK[ds.results]:
        out.append(error("AOF-P076", "aof.yaml",
                         f"data_safety.results {app_results} is weaker than the platform's {ds.results}",
                         "apps may only tighten: off < shadow < enforce"))
    lim = ds.query
    for t in manifest.tools:
        q = t.query
        if q is None:
            continue
        where = f"{A}:{t.name}"
        if t.access is not Access.READ:
            out.append(error("AOF-P072", where, "query tools are read tools; writes never go through a query"))
        missing = [n for n in ("max_rows", "timeout_seconds", "max_bytes_scanned") if getattr(q, n) is None]
        if missing:
            out.append(error("AOF-P070", where, f"query tool must declare query.{', query.'.join(missing)}"))
        for name, ceiling in (("max_rows", lim.max_rows_ceiling), ("timeout_seconds", lim.timeout_seconds_ceiling),
                              ("max_bytes_scanned", lim.max_bytes_scanned_ceiling)):
            value = getattr(q, name)
            if value is not None and value > ceiling:
                out.append(error("AOF-P075", where, f"query.{name}={value} exceeds the platform ceiling {ceiling}"))
        mode = t.approval.mode if t.approval else None
        if q.form == "sql" and project.risk_tier >= RiskTier.T3 and mode is not ApprovalMode.PER_ACTION:
            out.append(error("AOF-P071", where, "raw SQL in a T3 app needs per_action approval",
                             "use form: ir (semantic queries), or approve each query"))
    return out


def exposure_exceptions(project: Project, platform: PlatformConfig) -> dict[str, Exposure]:
    """Signed exceptions in force: only under metadata_only (contract mode doesn't need them)."""
    if data_safety_mode(project, platform) is not DataSafetyMode.METADATA_ONLY:
        return {}
    return {e.field: e.exposure for e in project.data_safety.exceptions}


def check_ds8(project: Project, manifest: ToolManifest, platform: PlatformConfig,
              contracts: Iterable[DataContract]) -> list[Finding]:
    """Exceptions (P077, P078) and verdicts (P079): how a value-blind agent still decides."""
    ds, out = platform.data_safety, []
    tools = {t.name: t for t in manifest.tools}
    for e in project.data_safety.exceptions:
        owner, key = e.field.split(".", 1)
        tool = tools.get(owner)
        if tool is not None:
            if key not in tool.result_keys:
                out.append(error("AOF-P077", "aof.yaml", f"exception {e.field}: {owner} declares no result key {key}"))
            elif e.exposure > tool.result_keys[key]:
                out.append(error("AOF-P078", "aof.yaml",
                                 f"exception {e.field} asks for {e.exposure.value}; the manifest declares "
                                 f"{tool.result_keys[key].value}", "an exception lifts metadata_only, not the manifest"))
        else:
            dc = next((c for c in contracts if c.name == owner), None)
            f = dc.field(key) if dc else None
            if f is None:
                out.append(error("AOF-P077", "aof.yaml", f"exception {e.field} names no data-contract field or tool "
                                                         "result key"))
            else:
                limit = f.llm_exposure or ds.default_exposure[effective_classification(f)]
                if e.exposure > limit:
                    out.append(error("AOF-P078", "aof.yaml",
                                     f"exception {e.field} asks for {e.exposure.value}; the contract allows "
                                     f"{limit.value}", "an exception lifts metadata_only, not the contract or "
                                                       "the platform ceiling"))
    for t in manifest.tools:
        for name, v in t.verdicts.items():
            where = f"tools.manifest:{t.name}"
            if v.type == "enum" and len(set(v.values)) > ds.max_verdict_values:
                out.append(error("AOF-P079", where, f"verdict {name} has {len(set(v.values))} values; the platform "
                                                    f"allows {ds.max_verdict_values}",
                                 "a verdict is a decision, not a way to return the value"))
            if name in t.result_keys:
                out.append(error("AOF-P079", where, f"{name} is both a verdict and a result key"))
    return out


def _compile_data_safety(project: Project, manifest: ToolManifest, platform: PlatformConfig,
                         contracts: Iterable[DataContract]) -> dict[str, Any]:
    ds = platform.data_safety
    mode = data_safety_mode(project, platform)
    views = views_from_contracts(contracts, ds.default_exposure, mode, exposure_exceptions(project, platform))
    return {
        "mode": mode.value,
        "results": data_safety_results(project, platform),
        "vault": ds.vault.model_dump(),
        "egress": ds.egress.model_dump(),
        "max_queries_per_run": ds.query.max_queries_per_run,
        "views": {name: v.model_dump(mode="json", exclude_defaults=True) for name, v in views.items()},
        "min_group_size": ds.min_group_size,
        "row_count_buckets": ds.row_count_buckets,
        "row_filter_claims": ds.row_filter_claims,
        "allowed_functions": ds.query.allowed_functions,
    }


def _check_a2a(project: Project) -> list[Finding]:
    cfg = project.a2a
    if cfg is None or not (cfg.peers or cfg.allowed_callers):
        return []
    out: list[Finding] = []
    if project.autonomy.target < AutonomyLevel.L4:
        out.append(error("AOF-P050", "aof.yaml", "agent-to-agent traffic (a2a) requires autonomy target L4",
                         "remove the a2a block or raise the target"))
    if cfg.allowed_callers and not project.hosts_agent:
        out.append(error("AOF-P051", "aof.yaml", "a2a.allowed_callers requires hosts_agent and an agent card"))
    names = [peer.name for peer in cfg.peers]
    for name in sorted({n for n in names if names.count(n) > 1}):
        out.append(error("AOF-P053", "aof.yaml", f"a2a peer {name} is listed more than once"))
    for peer in cfg.peers:
        if not peer.card_url.startswith("https://"):
            out.append(error("AOF-P052", "aof.yaml", f"a2a peer {peer.name}: card_url must be https"))
    return out


def _compile_llm(project: Project, platform: PlatformConfig) -> dict[str, Any] | None:
    if project.llm is None or platform.llm is None:
        return None
    cfg, plat = project.llm, platform.llm
    models = cfg.models or [plat.default_model]
    return {
        "provider": plat.provider,
        "models": models,
        "default_model": models[0],
        "max_tokens": cfg.max_tokens,
        "max_model_calls_per_run": plat.max_model_calls_per_run,
        "rate_limit": cfg.rate_limit.model_dump(),
        "allowed_betas": plat.allowed_betas,
        "allowed_server_tools": cfg.allowed_server_tools,
        "pricing_usd_per_mtok": {m: p.model_dump(exclude_none=True)
                                 for m, p in plat.pricing_usd_per_mtok.items()},
        "cache_write_multiplier": plat.cache_write_multiplier,
        "fast_mode_multiplier": plat.fast_mode_multiplier,
    }


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


def compile_policy(project: Project, manifest: ToolManifest, platform: PlatformConfig,
                   contracts: Iterable[DataContract] = ()) -> dict[str, Any]:
    errors = [f for f in check_policy(project, manifest, platform) if f.severity.value == "error"]
    if errors:
        raise PolicyError(errors)

    level = project.autonomy.current
    budgets = _effective_budgets(project, platform)
    a2a = project.a2a or A2aConfig()
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
        if t.query:
            entry["query"] = t.query.model_dump()
        if t.result_keys:
            strict = data_safety_mode(project, platform) is DataSafetyMode.METADATA_ONLY
            signed = exposure_exceptions(project, platform)

            def clamp(k: str, v: Exposure) -> Exposure:  # metadata_only clamps these like contract fields
                if not strict or v is Exposure.TOKEN:
                    return v
                e = signed.get(f"{t.name}.{k}")
                return min(e, v) if e is not None else Exposure.NONE

            entry["result_keys"] = {k: clamp(k, v).value for k, v in t.result_keys.items()}
        if t.verdicts:  # shown in every mode; the gateway drops values outside the type
            entry["verdicts"] = {k: v.model_dump(exclude_defaults=True) | {"type": v.type}
                                 for k, v in t.verdicts.items()}
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
            "token_endpoint": platform.identity.token_endpoint if project.app.user_facing else None,
            "audience": project.mcp_server.audience,
            "issuer": platform.identity.issuer,
            "jwks_uri": platform.identity.jwks_uri,
            "algorithms": platform.identity.algorithms,
            "roles_claim": platform.identity.roles_claim,
            "tenant_claim": platform.identity.tenant_claim,
            "leeway_seconds": platform.identity.leeway_seconds,
            "operator_role": platform.identity.operator_role,
            "scope_ttl_seconds": platform.identity.scope_ttl_seconds,
            "shared_service_account": False,
            "credentials_in_context": False,
        },
        "budgets": budgets,
        "tools": tools,
        "a2a": {
            "enabled": level >= AutonomyLevel.L4,  # the current level: a demotion turns it off
            "inbound": project.hosts_agent,
            "mtls": True,
            "verify_agent_cards": True,
            "max_delegation_depth": budgets["max_delegation_depth"],
            "max_delegations_per_run": a2a.max_delegations_per_run,
            "allowed_callers": a2a.allowed_callers,
            "peers": [peer.model_dump() for peer in a2a.peers],
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
        "llm": _compile_llm(project, platform),
        "data_safety": _compile_data_safety(project, manifest, platform, contracts),
    }
