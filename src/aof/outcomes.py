"""Outcome metrics: the business outcome promised at intake, measured during the pilot.

`use-case.yaml` declares what the app must achieve, in terms of measures the gateway's
audit log can answer:

    outcome_metrics:
      - name: handling_time
        measure: case_minutes      # from the catalogue below
        stat: median               # median | p90 | mean (rates have one value)
        target: {max: 6}
        baseline: 18               # before the app, for the report

`aof gateway pilot-report` computes every measure into `pilot.json` (`measures`), and the
pilot gate compares the declared targets with them (AOF-G055, G056). Pure: no I/O.

Measures, per run (one agent session, by run id) unless noted:
  case_minutes           first call of the run to its last human decision; to its last
                         call when no human was needed
  agent_minutes          first to last call of the run, without the human wait
  approval_wait_minutes  per approval: requested to decided
  steps_per_run          tool calls, denied and held ones included
  cost_usd_per_run       model spend
  denials_per_run        tool and model denials
  approval_rate          rate: approved / decided approvals
  rework_rate            rate: runs with at least one rejected approval
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any, Iterable

RATES = ("approval_rate", "rework_rate")
MEASURES = ("case_minutes", "agent_minutes", "approval_wait_minutes", "steps_per_run", "cost_usd_per_run",
            "denials_per_run", *RATES)
STATS = ("median", "p90", "mean")
_STEP_EVENTS = {"tool_executed", "tool_denied", "tool_failed", "approval_requested", "query_rejected",
                "reference_refused"}
_DENIALS = {"tool_denied", "llm_denied", "query_rejected", "reference_refused"}


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    p90 = ordered[min(len(ordered) - 1, max(0, round(0.9 * len(ordered) + 0.5) - 1))]
    return {"n": len(values), "median": round(statistics.median(ordered), 4), "p90": round(p90, 4),
            "mean": round(statistics.fmean(ordered), 4)}


def compute_measures(records: Iterable[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Every catalogue measure from one agent's audit records (any order, several replicas)."""
    records = sorted(records, key=lambda r: r.get("ts", 0))
    runs: dict[str, list[dict]] = defaultdict(list)
    run_of_approval: dict[str, str] = {}
    requested_at: dict[str, float] = {}
    decisions: list[dict] = []
    for r in records:
        if r.get("event") == "approval_decided":
            decisions.append(r)
            continue
        run_id = r.get("run_id")
        if not run_id:
            continue
        runs[run_id].append(r)
        if r.get("event") == "approval_requested" and r.get("approval_id"):
            run_of_approval[r["approval_id"]] = run_id
            requested_at[r["approval_id"]] = r.get("ts", 0)

    decided_in: dict[str, list[dict]] = defaultdict(list)
    waits: list[float] = []
    for d in decisions:
        aid = d.get("approval_id")
        if aid in run_of_approval:
            decided_in[run_of_approval[aid]].append(d)
            waits.append((d.get("ts", 0) - requested_at[aid]) / 60)

    case, agent, steps, cost, denials = [], [], [], [], []
    reworked = 0
    for run_id, events in runs.items():
        first, last = events[0].get("ts", 0), events[-1].get("ts", 0)
        human = [d.get("ts", 0) for d in decided_in.get(run_id, [])]
        agent.append((last - first) / 60)
        case.append((max([last, *human]) - first) / 60)
        steps.append(sum(1 for e in events if e.get("event") in _STEP_EVENTS))
        cost.append(sum(float(e.get("cost_usd") or 0) for e in events if e.get("event") == "llm_call"))
        denials.append(sum(1 for e in events if e.get("event") in _DENIALS))
        reworked += any(d.get("decision") == "rejected" for d in decided_in.get(run_id, []))

    approved = sum(1 for d in decisions if d.get("decision") == "approved")
    return {
        "case_minutes": _summary(case),
        "agent_minutes": _summary(agent),
        "approval_wait_minutes": _summary(waits),
        "steps_per_run": _summary(steps),
        "cost_usd_per_run": _summary(cost),
        "denials_per_run": _summary(denials),
        "approval_rate": {"n": len(decisions), "value": round(approved / len(decisions), 4)} if decisions
        else {"n": 0},
        "rework_rate": {"n": len(runs), "value": round(reworked / len(runs), 4)} if runs else {"n": 0},
    }


def measured(measures: dict[str, dict[str, float]] | None, measure: str, stat: str) -> float | None:
    m = (measures or {}).get(measure) or {}
    if not m.get("n"):
        return None
    value = m.get("value") if measure in RATES else m.get(stat)
    return float(value) if value is not None else None
