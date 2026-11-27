"""Candidate eval cases from production incidents (ROADMAP 4c.3). Pure: no I/O.

What the gateway refused or a human rejected in production is what the evals should
test next. `aof gateway harvest-cases` groups an agent's audited incidents by event, code
and tool, and writes one candidate per group to `evals/candidates.jsonl` with a suggested
category and expectation:

  tool, model and query denials, refused references, probe signals  ->  safety candidates
  rejected proposals, and queries or references the agent got wrong  ->  golden candidates

The audit log never holds prompts or argument values, so a candidate can't say what the
user asked: its `input` is a TODO, and `source.runs` names runs whose conversation the
reviewer looks up in the app's own logs. A reviewer fills in the input (and, for golden
cases, the expectation), then moves the case into the suite, keeping `harvested_from`, so
the next harvest skips that group. `aof validate` refuses suite cases that still hold a
TODO (AOF-E008).
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any, Iterable

TODO = "TODO"

# (event, code) -> (kind, asi, ds, expected). Code None matches any code of the event.
_RULES: dict[tuple[str, str | None], tuple[str, list[str], list[str], str]] = {
    ("tool_denied", "MISSING_SCOPE"): ("safety", ["ASI03"], [], "block"),
    ("tool_denied", "DENIED_BY_POLICY"): ("safety", ["ASI02"], [], "block"),
    ("tool_denied", "UNKNOWN_TOOL"): ("safety", ["ASI02"], [], "block"),
    ("tool_denied", "RATE_LIMITED"): ("safety", ["ASI02", "ASI08"], [], "block"),
    ("tool_denied", "STEP_BUDGET"): ("safety", ["ASI08"], [], "block"),
    ("tool_denied", "COST_BUDGET"): ("safety", ["ASI08"], [], "block"),
    ("tool_denied", "DELEGATION_DEPTH"): ("safety", ["ASI07"], [], "block"),
    ("tool_denied", "KILL_SWITCH"): ("safety", ["ASI10"], [], "block"),
    ("tool_denied", None): ("safety", ["ASI02"], [], "block"),
    ("query_rejected", "SQL_NOT_READ_ONLY"): ("safety", ["ASI02"], ["DS02"], "block"),
    ("query_rejected", "SQL_FILTER_NOT_ALLOWED"): ("safety", ["ASI01"], ["DS04"], "block"),
    ("query_rejected", "SQL_COLUMN_NOT_ALLOWED"): ("safety", ["ASI02"], ["DS01"], "block"),
    ("query_rejected", "SQL_VIEW_NOT_ALLOWED"): ("safety", ["ASI02"], ["DS03"], "block"),
    ("query_rejected", "SQL_CONSTRUCT_NOT_ALLOWED"): ("safety", ["ASI02"], ["DS05"], "block"),
    ("query_rejected", "SQL_FUNCTION_NOT_ALLOWED"): ("safety", ["ASI05"], ["DS05"], "block"),
    ("query_rejected", "ROW_FILTER_UNBOUND"): ("safety", ["ASI03"], ["DS03"], "block"),
    ("query_rejected", "QUERY_BUDGET"): ("safety", ["ASI08"], ["DS04"], "block"),
    ("query_rejected", "QUERY_NEEDS_CLARIFICATION"): ("golden", [], [], ""),
    ("query_rejected", "QUERY_FAILED"): None,  # the warehouse failed, not the agent
    ("query_rejected", None): ("golden", [], [], ""),  # invalid or unparseable, unknown field: the agent's mistake
    ("llm_denied", "DATA_EGRESS_BLOCKED"): ("safety", ["ASI01"], ["DS07"], "no_leak"),
    ("llm_denied", "SENSITIVE_DATA_BLOCKED"): ("safety", ["ASI02"], ["DS06"], "block"),
    ("llm_denied", "NON_TEXT_BLOCKED"): ("safety", ["ASI01"], ["DS06"], "block"),
    ("llm_denied", None): ("safety", ["ASI08"], [], "block"),
    ("reference_refused", "RESULT_NOT_FOUND"): ("safety", ["ASI03"], [], "block"),
    ("reference_refused", "REFERENCE_INVALID"): ("golden", [], [], ""),  # a path the result doesn't have
    ("reference_refused", None): None,  # vault configuration and size limits: operations, not evals
    ("query_probe_suspected", None): ("safety", ["ASI01"], ["DS04"], "block"),
    ("approval_decided", "rejected"): ("golden", [], [], ""),
}
_EVENTS = {event for event, _ in _RULES}


def _rule(event: str, code: str | None):
    return _RULES[(event, code)] if (event, code) in _RULES else _RULES.get((event, None))


def signature(event: str, code: str | None, tool: str | None) -> str:
    """The incident group a candidate came from; suite cases keep it as `harvested_from`."""
    return f"{event}:{code or '-'}:{tool or '-'}"


def case_id(sig: str) -> str:
    return f"h-{hashlib.sha256(sig.encode()).hexdigest()[:6]}"


def unreviewed(case: dict[str, Any]) -> list[str]:
    """Fields a reviewer still has to fill in."""
    return [k for k in ("input", "expected") if isinstance(case.get(k), str) and case[k].startswith(TODO)]


def to_suite_case(candidate: dict[str, Any]) -> dict[str, Any]:
    """A reviewed candidate as a golden or safety case (without the review-only keys)."""
    return {k: v for k, v in candidate.items() if k not in ("kind", "source")}


def _day(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).date().isoformat()


def harvest(records: Iterable[dict[str, Any]], *, known: set[str] = frozenset(),
            previous: Iterable[dict[str, Any]] = (), max_runs: int = 5) -> list[dict[str, Any]]:
    """Candidates from one agent's audit records. `known`: signatures already in the suite
    (skipped). `previous`: the candidates file so far; their ids and reviewer edits stay,
    counts and dates are refreshed. Most frequent first."""
    records = list(records)
    tool_of_approval = {r["approval_id"]: r.get("tool") for r in records
                        if r.get("event") == "approval_requested" and r.get("approval_id")}
    run_of_approval = {r["approval_id"]: r.get("run_id") for r in records
                       if r.get("event") == "approval_requested" and r.get("approval_id")}
    groups: dict[str, dict[str, Any]] = {}
    for r in records:
        event = r.get("event")
        if event not in _EVENTS:
            continue
        code = r.get("decision") if event == "approval_decided" else r.get("code")
        rule = _rule(event, code)
        if rule is None:  # e.g. an approved decision, a warehouse outage
            continue
        tool = r.get("tool") or tool_of_approval.get(r.get("approval_id"))
        if event == "llm_denied":
            tool = None  # model calls: the model, not a tool
        run = r.get("run_id") or run_of_approval.get(r.get("approval_id"))
        sig = signature(event, code, tool)
        g = groups.setdefault(sig, {"event": event, "code": code, "tool": tool, "count": 0, "runs": [],
                                    "first": r.get("ts", 0), "last": r.get("ts", 0), "rule": rule})
        g["count"] += 1
        g["first"], g["last"] = min(g["first"], r.get("ts", 0)), max(g["last"], r.get("ts", 0))
        if run and run not in g["runs"] and len(g["runs"]) < max_runs:
            g["runs"].append(run)

    kept = {c["harvested_from"]: c for c in previous if c.get("harvested_from") and c["harvested_from"] not in known}
    out: list[dict[str, Any]] = []
    for sig, g in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        if sig in known:
            continue
        kind, asi, ds, expected = g["rule"]
        source = {"event": g["event"], "code": g["code"], "tool": g["tool"], "count": g["count"],
                  "first_seen": _day(g["first"]), "last_seen": _day(g["last"]), "runs": g["runs"]}
        old = kept.pop(sig, None)
        if old is not None:  # keep the reviewer's work; refresh what production says
            out.append({**old, "source": source})
            continue
        what = f"{g['event']} {g['code'] or ''}".strip() + (f" on {g['tool']}" if g["tool"] else "")
        case: dict[str, Any] = {"id": case_id(sig), "kind": kind,
                                "harvested_from": sig, "input": f"{TODO}: the user's request in one of source.runs",
                                "source": source}
        if kind == "safety":
            case.update(asi=asi, ds=ds, expected=expected)
        else:
            case.update(expected=f"{TODO}: what the agent should have done ({what})",
                        expected_tools=[g["tool"]] if g["tool"] else [], tags=["harvested"])
        out.append(case)
    out += kept.values()  # candidates whose incidents fell out of the window stay for review
    return out
