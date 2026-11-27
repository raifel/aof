"""The seven onboarding stages, each ending in a named gate.

Gates are stateless: each one re-reads the repo's artefacts, so CI and humans see the
same answer. Sign-offs live in the artefacts (triage in the use-case card, reviews in
aof.yaml), which keeps the audit trail in version control.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import validate
from .enums import AGENTIC_PATTERNS, ASI_RISKS, DATA_SAFETY_RISKS, AutonomyLevel, Dimension, Pattern, ReadinessStatus, RiskTier, Stage
from .findings import Finding, Report, error, info, warning
from .loader import LoadedProject
from .platform import PlatformConfig
from .evalbasis import stale_reasons
from .outcomes import RATES, measured
from .policy import data_safety_results

GATE_NAMES = {
    Stage.INTAKE: "platform team accepts and assigns a risk tier",
    Stage.READINESS: "no blocking readiness gaps",
    Stage.PATTERN: "architecture review signs off pattern and autonomy level",
    Stage.BUILD: "contract checks pass in CI",
    Stage.EVALUATE: "eval scores meet the tier's thresholds",
    Stage.PILOT: "shadow-mode agreement and incidents meet thresholds",
    Stage.PROMOTE: "review and one-level-at-a-time promotion",
}


@dataclass
class GateResult:
    stage: Stage
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not Report(self.findings).errors


def _intake(lp: LoadedProject, _: PlatformConfig) -> list[Finding]:
    uc = lp.use_case
    if uc is None:
        return [error("AOF-G001", "use-case", "use-case card is missing or invalid")]
    if uc.triage is None:
        return [error("AOF-G001", "use-case", "not yet triaged",
                      "platform team adds triage: accepted_by, date, assigned_risk_tier")]
    if uc.triage.assigned_risk_tier is RiskTier.T4:
        return [error("AOF-G002", "use-case", "assigned T4: this use case cannot be delegated")]
    return []


def _readiness(lp: LoadedProject, _: PlatformConfig) -> list[Finding]:
    r = lp.readiness
    if r is None:
        return [error("AOF-G010", "readiness", "readiness scorecard is missing or invalid")]
    out: list[Finding] = []
    for d in Dimension:
        s = r.dimensions.get(d)
        where = f"readiness:{d.value}"
        if s is None:
            out.append(error("AOF-G010", where, "dimension not scored"))
        elif s.status is ReadinessStatus.NOT_READY:
            out.append(error("AOF-G011", where, "not ready: remediate before build",
                             s.remediation or "add a remediation item"))
        elif s.status is ReadinessStatus.PARTIAL:
            out.append(warning("AOF-G012", where, "partially ready", s.remediation))
        elif not s.evidence:
            out.append(warning("AOF-G013", where, "marked ready without evidence"))
    return out


def _pattern(lp: LoadedProject, _: PlatformConfig) -> list[Finding]:
    p = lp.project
    out: list[Finding] = []
    if p.approvals.architecture_review is None:
        out.append(error("AOF-G020", "aof.yaml", "no architecture review sign-off for pattern and autonomy level"))
    if p.pattern in AGENTIC_PATTERNS and not (p.pattern_justification or "").strip():
        out.append(error("AOF-G021", "aof.yaml",
                         f"pattern {p.pattern.value} needs pattern_justification",
                         "workflow before agent: show why a simpler pattern falls short"))
    if p.pattern is Pattern.MULTI_AGENT and p.autonomy.target < AutonomyLevel.L4:
        out.append(warning("AOF-G022", "aof.yaml", "multi_agent pattern usually targets L4 (A2A delegation)"))
    return out


def _build(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    return validate(lp, platform).findings


def _evaluate(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    p, res = lp.project, lp.eval_results
    out: list[Finding] = []
    n = len(lp.golden_cases)
    if n < platform.golden_set.min_cases:
        out.append(error("AOF-G042", "evals", f"golden set has {n} cases; need {platform.golden_set.min_cases}"))
    missing = sorted(ASI_RISKS.keys() - {a for c in lp.safety_cases for a in c.asi})
    if missing:
        out.append(error("AOF-G043", "evals", f"red-team suite misses {', '.join(missing)}"))
    tools = lp.manifest.tools if lp.manifest else []
    if any(t.query for t in tools):
        missing_ds = sorted(DATA_SAFETY_RISKS.keys() - {d for c in lp.safety_cases for d in c.ds})
        if missing_ds:
            out.append(error("AOF-G070", "evals", f"the app has query tools; red-team suite misses "
                                                  f"data-safety categories {', '.join(missing_ds)}"))
    # In shadow mode results reach the agent on purpose, so leaks are expected: only an app
    # that enforces data safety must show it holds.
    governed = any(t.reads or t.query for t in tools) and data_safety_results(p, platform) == "enforce"
    if res is None:
        out.append(error("AOF-G040", p.artefacts.eval_results, "no eval results",
                         "run the eval suite and write the results file"))
        return out
    th = platform.eval_thresholds.get(p.risk_tier)
    if th is None:
        out.append(error("AOF-G041", "platform.yaml", f"no thresholds for tier {p.risk_tier.value}"))
        return out
    for metric, need in th.model_dump().items():
        if metric == "no_leak_rate" and not governed:
            continue  # reported in shadow mode, where leaks are expected; not gated
        got = getattr(res, metric)
        if got is None:
            if governed:  # only no_leak_rate can be missing, and it is required here
                out.append(error("AOF-G071", p.artefacts.eval_results,
                                 f"results lack {metric}; the app reads governed data",
                                 "run `aof eval`, which scores leaks from the gateway's record"))
            continue
        if got < need:
            out.append(error("AOF-G041", p.artefacts.eval_results,
                             f"{metric} {got:.3f} below {p.risk_tier.value} threshold {need:.3f}"))
    if res.cases_run < n + len(lp.safety_cases):
        out.append(warning("AOF-G044", p.artefacts.eval_results,
                           f"results cover {res.cases_run} cases; suite has {n + len(lp.safety_cases)}"))
    out += _stale(lp, platform, res)
    return out


def _stale(lp: LoadedProject, platform: PlatformConfig, res) -> list[Finding]:
    """Results describe the app only while what they measured is unchanged (evalbasis.py)."""
    where = lp.project.artefacts.eval_results
    recorded = (res.model_extra or {}).get("basis")
    if not isinstance(recorded, dict):
        return [warning("AOF-G046", where, "results carry no basis, so the gate can't tell whether they are stale",
                        "re-run `aof eval`, which records what it evaluated")]
    level = (res.model_extra or {}).get("autonomy_level")
    try:
        lvl = AutonomyLevel(level) if level else None
    except ValueError:
        lvl = None
    reasons = stale_reasons(lp, platform, recorded, lvl)
    if not reasons:
        return []
    return [error("AOF-G045", where, "eval results are stale: " + "; ".join(reasons),
                  "re-run `aof eval` so the scores describe the app as it is now")]


def _pilot(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    p, pr, cfg = lp.project, lp.pilot_results, platform.pilot
    where = p.artefacts.pilot_results
    if pr is None:
        return [error("AOF-G050", where, "no shadow-mode pilot results")]
    out: list[Finding] = []
    days = (pr.window_end - pr.window_start).days
    if days < cfg.min_window_days:
        out.append(error("AOF-G051", where, f"pilot window {days} days; need {cfg.min_window_days}"))
    if pr.proposals < cfg.min_proposals:
        out.append(error("AOF-G052", where, f"{pr.proposals} proposals; need {cfg.min_proposals}"))
    need = cfg.min_agreement_rate.get(p.risk_tier)
    if need is not None and pr.agreement_rate < need:
        out.append(error("AOF-G053", where, f"agreement {pr.agreement_rate:.3f} below {need:.3f}"))
    cap = cfg.max_incidents.get(p.risk_tier)
    if cap is not None and pr.incidents > cap:
        out.append(error("AOF-G054", where, f"{pr.incidents} incidents; max {cap}"))
    out += _outcomes(lp, pr)
    return out


def _outcomes(lp: LoadedProject, pr) -> list[Finding]:
    """The business outcome promised at intake, checked against what the pilot measured."""
    where = lp.project.artefacts.pilot_results
    metrics = lp.use_case.outcome_metrics if lp.use_case else []
    if not metrics:
        return [warning("AOF-G057", "use-case", "the business outcome isn't measured",
                        "declare outcome_metrics in the use-case card; the pilot report measures them")]
    out: list[Finding] = []
    for m in metrics:
        stat = "" if m.measure in RATES else f"{m.stat} "
        got = measured(pr.measures, m.measure, m.stat)
        if got is None:
            out.append(error("AOF-G055", where, f"outcome {m.name}: the pilot results have no {m.measure}",
                             "write them with `aof gateway pilot-report`"))
            continue
        base = f" (baseline {m.baseline:g})" if m.baseline is not None else ""
        if m.target.max is not None and got > m.target.max:
            out.append(error("AOF-G056", where, f"outcome {m.name}: {stat}{m.measure} {got:g}, target at most "
                                                f"{m.target.max:g}{base}"))
        if m.target.min is not None and got < m.target.min:
            out.append(error("AOF-G056", where, f"outcome {m.name}: {stat}{m.measure} {got:g}, target at least "
                                                f"{m.target.min:g}{base}"))
    return out


def _promote(lp: LoadedProject, platform: PlatformConfig) -> list[Finding]:
    p = lp.project
    cur, tgt = p.autonomy.current, p.autonomy.target
    out: list[Finding] = []
    if tgt.rank - cur.rank > 1:
        out.append(error("AOF-G060", "aof.yaml",
                         f"cannot jump {cur.value} -> {tgt.value}: autonomy rises one level at a time"))
    if (tgt >= AutonomyLevel.L3 or p.risk_tier >= RiskTier.T3) and p.approvals.review_board is None:
        out.append(error("AOF-G061", "aof.yaml", "AI review board approval required (T3 app or L3+)"))
    failing = [s.value for s in (Stage.BUILD, Stage.EVALUATE, Stage.PILOT)
               if not run_gate(s, lp, platform).passed]
    if failing:
        out.append(error("AOF-G062", "lifecycle", f"earlier gates failing: {', '.join(failing)}"))
    if tgt == cur and not out:
        out.append(info("AOF-G063", "aof.yaml", f"already at target level {cur.value}"))
    return out


_GATES = {
    Stage.INTAKE: _intake,
    Stage.READINESS: _readiness,
    Stage.PATTERN: _pattern,
    Stage.BUILD: _build,
    Stage.EVALUATE: _evaluate,
    Stage.PILOT: _pilot,
    Stage.PROMOTE: _promote,
}


def run_gate(stage: Stage, lp: LoadedProject, platform: PlatformConfig) -> GateResult:
    if lp.project is None:
        return GateResult(stage, list(lp.load_findings))
    return GateResult(stage, _GATES[stage](lp, platform))


def status(lp: LoadedProject, platform: PlatformConfig) -> list[GateResult]:
    return [run_gate(s, lp, platform) for s in Stage]
