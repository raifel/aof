"""Cross-artefact contract checks (the build gate's "contract checks pass in CI")."""

from __future__ import annotations

import re

from pydantic import ValidationError

from .enums import ASI_RISKS, AutonomyLevel, Classification, RiskTier
from .findings import Finding, Report, error, info, warning
from .lint import lint_manifest
from .loader import LoadedProject
from .models import AofRegistryMeta
from .models.evals import REQUIRED_METRICS
from .platform import PlatformConfig
from .policy import check_policy

SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


def check_mcp_server(lp: LoadedProject) -> list[Finding]:
    ref = lp.project.mcp_server
    if ref.managed:
        return [info("AOF-C001", "aof.yaml", f"uses a managed MCP server ({ref.managed})")]
    if not lp.path(ref.path).exists():
        return [error("AOF-C001", "aof.yaml", f"mcp_server.path {ref.path} does not exist")]
    if not ref.command:
        return [warning("AOF-C001", "aof.yaml", "no mcp_server.command: `aof check-server` cannot launch it")]
    return []


def check_registry(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    sj, p, out = lp.server_json, lp.project, []
    where = p.artefacts.registry
    if sj is None:
        return out
    if not sj.name.startswith(platform.registry.namespace_prefix + "/") and not sj.name.startswith(
        platform.registry.namespace_prefix + "."
    ):
        out.append(error("AOF-C010", where,
                         f"name {sj.name!r} is outside namespace {platform.registry.namespace_prefix!r}"))
    if "/" not in sj.name:
        out.append(error("AOF-C010", where, "name must be reverse-DNS with a slash, e.g. com.example/refunds"))
    if not SEMVER.match(sj.version):
        out.append(error("AOF-C011", where, f"version {sj.version!r} is not semver"))
    if not sj.remotes and not sj.packages and not p.mcp_server.managed:
        out.append(error("AOF-C012", where, "declare at least one remote endpoint or package"))
    for r in sj.remotes:
        if r.type not in platform.registry.allowed_remote_types:
            out.append(error("AOF-C012", where, f"remote type {r.type!r} not allowed"))
        if not r.url.startswith("https://"):
            out.append(error("AOF-C012", where, f"remote {r.url} must be https"))

    meta = sj.aof_meta()
    if meta is None:
        out.append(error("AOF-C013", where, "missing AOF metadata under _meta publisher-provided.aof",
                         "owner, risk_tier, autonomy_level, on_call"))
    else:
        try:
            m = AofRegistryMeta.model_validate(meta)
        except ValidationError as exc:
            out.append(error("AOF-C013", where, f"invalid AOF metadata: {exc.errors()[0]['msg']}"))
        else:
            if m.owner != p.app.owner:
                out.append(error("AOF-C014", where, f"owner {m.owner!r} != aof.yaml owner {p.app.owner!r}"))
            if m.risk_tier is not p.risk_tier:
                out.append(error("AOF-C014", where, "risk_tier differs from aof.yaml"))
            if m.autonomy_level is not p.autonomy.current:
                out.append(error("AOF-C014", where, "autonomy_level must equal aof.yaml autonomy.current"))
            if m.on_call != p.app.on_call:
                out.append(error("AOF-C014", where, "on_call differs from aof.yaml"))

    if lp.manifest and lp.manifest.server != sj.name:
        out.append(error("AOF-C015", "tools.manifest",
                         f"server {lp.manifest.server!r} != registry name {sj.name!r}"))
    if lp.manifest and lp.manifest.version != sj.version:
        out.append(warning("AOF-C015", "tools.manifest", "manifest version differs from server.json version"))
    return out


def check_data_contracts(lp: LoadedProject) -> list[Finding]:
    out: list[Finding] = []
    views: dict[str, object] = {}
    for dc in lp.data_contracts:
        where = f"data-contract:{dc.name}"
        if dc.semantic_view in views:
            out.append(error("AOF-C020", where, f"semantic_view {dc.semantic_view} declared twice"))
        views[dc.semantic_view] = dc
        top = max(f.classification for f in dc.fields)
        if top > dc.classification:
            out.append(error("AOF-C021", where,
                             f"a field is {top.value} but the contract is {dc.classification.value}"))
        if any(f.pii for f in dc.fields) and dc.classification < Classification.CONFIDENTIAL:
            out.append(error("AOF-C022", where, "contracts with PII fields are confidential or higher"))
        if not dc.quality:
            out.append(warning("AOF-C023", where, "no quality SLAs declared"))

    if lp.manifest:
        for t in lp.manifest.tools:
            for r in t.reads:
                if r not in views:
                    out.append(error("AOF-C024", f"tools.manifest:{t.name}",
                                     f"reads {r!r} but no data contract declares that semantic view",
                                     "agents read only through governed data products"))
    return out


def check_agent_card(lp: LoadedProject) -> list[Finding]:
    out: list[Finding] = []
    card, p = lp.agent_card, lp.project
    where = p.artefacts.agent_card
    if card is None:
        return out
    if not card.securitySchemes:
        out.append(error("AOF-C030", where, "agent card must declare securitySchemes (no anonymous agents)"))
    if not card.url.startswith("https://"):
        out.append(error("AOF-C031", where, "agent endpoint must be https (mTLS through the gateway)"))
    if not p.hosts_agent:
        out.append(warning("AOF-C032", where, "agent card present but hosts_agent is false"))
    return out


def check_evals_static(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    out: list[Finding] = []
    suite = lp.eval_suite
    if suite is None:
        return out
    where = lp.project.artefacts.eval_suite
    for m in REQUIRED_METRICS:
        if m not in suite.metrics:
            out.append(error("AOF-E001", where, f"metrics must include {m}"))

    n = len(lp.golden_cases)
    if n < platform.golden_set.min_cases:
        out.append(warning("AOF-E002", suite.golden_set,
                           f"golden set has {n} cases; the evaluate gate needs {platform.golden_set.min_cases}"))
    if lp.golden_cases and not any("edge_case" in c.tags for c in lp.golden_cases):
        out.append(warning("AOF-E003", suite.golden_set, "no case tagged edge_case"))
    ids = [c.id for c in lp.golden_cases] + [c.id for c in lp.safety_cases]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        out.append(error("AOF-E004", where, f"duplicate case ids: {', '.join(sorted(dupes))}"))

    if lp.manifest:
        names = {t.name for t in lp.manifest.tools}
        for c in lp.golden_cases:
            unknown = [x for x in c.expected_tools if x not in names]
            if unknown:
                out.append(error("AOF-E005", f"{suite.golden_set}:{c.id}",
                                 f"expects unknown tools: {', '.join(unknown)}"))

    covered = {a for c in lp.safety_cases for a in c.asi}
    bad = covered - ASI_RISKS.keys()
    if bad:
        out.append(error("AOF-E006", suite.safety_cases, f"unknown ASI codes: {', '.join(sorted(bad))}"))
    missing = sorted(ASI_RISKS.keys() - covered)
    if missing:
        out.append(warning("AOF-E007", suite.safety_cases,
                           f"red-team cases do not cover {', '.join(missing)}",
                           "the evaluate gate requires all of ASI01-ASI10"))
    return out


def check_docs(lp: LoadedProject) -> list[Finding]:
    out: list[Finding] = []
    a = lp.project.artefacts
    if not lp.path(a.agents_md).exists():
        out.append(error("AOF-C040", a.agents_md, "AGENTS.md is missing"))
    rb = lp.path(a.runbook)
    if not rb.exists():
        out.append(error("AOF-C041", a.runbook, "runbook is missing"))
    else:
        text = rb.read_text().lower()
        if "kill switch" not in text and "kill-switch" not in text:
            out.append(error("AOF-C042", a.runbook, "runbook must document the kill-switch steps"))
        if lp.project.app.on_call.lower() not in text:
            out.append(warning("AOF-C043", a.runbook, f"runbook does not name the on-call rota {lp.project.app.on_call!r}"))
    return out


def check_use_case_alignment(lp: LoadedProject) -> list[Finding]:
    out: list[Finding] = []
    uc, p = lp.use_case, lp.project
    if uc is None:
        return out
    if uc.triage and uc.triage.assigned_risk_tier is not p.risk_tier:
        out.append(error("AOF-C050", "aof.yaml",
                         f"risk_tier {p.risk_tier.value} differs from the tier assigned at triage "
                         f"({uc.triage.assigned_risk_tier.value})", "re-triage to change the tier"))
    if uc.actions.write and p.autonomy.target <= AutonomyLevel.L1:
        out.append(info("AOF-C051", "use-case", "the use case lists writes but the target level is read-only"))
    if not uc.errors_reversible and p.risk_tier < RiskTier.T3:
        out.append(warning("AOF-C052", "use-case",
                           "errors are irreversible but the app is below T3",
                           "irreversible impact needs a human approval step"))
    return out


def validate(lp: LoadedProject, platform: PlatformConfig) -> Report:
    """Everything CI runs on every commit: schemas, contract, policy, lint, static evals."""
    report = Report()
    report.extend(lp.load_findings)
    if lp.project is None:
        return report
    report.extend(check_mcp_server(lp))
    report.extend(check_registry(lp, platform))
    report.extend(check_data_contracts(lp))
    report.extend(check_agent_card(lp))
    report.extend(check_evals_static(lp, platform))
    report.extend(check_docs(lp))
    report.extend(check_use_case_alignment(lp))
    if lp.manifest is not None:
        report.extend(check_policy(lp.project, lp.manifest, platform))
        report.extend(lint_manifest(lp.manifest, platform))
    return report
