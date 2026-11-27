"""Outcome metrics (ROADMAP 4c.2): the business outcome promised at intake, measured from
the audit log during the pilot and checked by the pilot gate (AOF-G055 to G057)."""

from __future__ import annotations

import json

import pytest

from aof.cli import main
from aof.enums import Stage
from aof.gates import run_gate
from aof.loader import load_project
from aof.outcomes import compute_measures, measured
from aof.platform import load_platform

from .conftest import codes

A = "agent:refunds-assistant"


def rec(event, ts, run=None, **kw):
    return {"event": event, "ts": ts, "agent": A, **({"run_id": run} if run else {}), **kw}


RECORDS = [
    # run a: looks up, proposes a refund at minute 1, the lead approves at minute 6
    rec("tool_executed", 0, "a"), rec("llm_call", 30, "a", cost_usd=0.02),
    rec("approval_requested", 60, "a", approval_id="ap1"),
    rec("approval_decided", 360, approval_id="ap1", decision="approved"),
    # run b: no human needed, one denial, two minutes
    rec("tool_executed", 1000, "b"), rec("tool_denied", 1060, "b"), rec("llm_call", 1120, "b", cost_usd=0.04),
    # run c: proposal rejected after ten minutes
    rec("tool_executed", 2000, "c"), rec("approval_requested", 2030, "c", approval_id="ap2"),
    rec("approval_decided", 2630, approval_id="ap2", decision="rejected"),
]


def test_measures_from_the_audit_log():
    m = compute_measures(reversed(RECORDS))  # replicas interleave: order doesn't matter
    assert m["case_minutes"] == {"n": 3, "median": 6.0, "p90": 10.5, "mean": 6.1667}
    assert m["agent_minutes"]["median"] == 1.0 and m["approval_wait_minutes"]["n"] == 2
    assert m["approval_wait_minutes"]["mean"] == 7.5  # 5 and 10 minutes
    assert m["steps_per_run"]["median"] == 2 and m["denials_per_run"]["mean"] == pytest.approx(1 / 3, abs=1e-4)
    assert m["cost_usd_per_run"]["mean"] == 0.02
    assert m["approval_rate"] == {"n": 2, "value": 0.5} and m["rework_rate"] == {"n": 3, "value": 0.3333}
    assert measured(m, "case_minutes", "p90") == 10.5 and measured(m, "rework_rate", "median") == 0.3333


def test_no_data_measures_nothing():
    m = compute_measures([])
    assert all(v == {"n": 0} for v in m.values()) and measured(m, "case_minutes", "median") is None


def test_pilot_report_writes_the_measures(tmp_path):
    from aof.gateway.audit import AuditLog

    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("tool_executed", agent=A, run_id="r1")
    log.append("approval_requested", agent=A, run_id="r1", approval_id="x")
    log.append("approval_decided", agent=A, approval_id="x", decision="approved")
    out = tmp_path / "pilot.json"
    assert main(["gateway", "pilot-report", A, "--since", "2020-01-01", "--state-dir", str(tmp_path),
                 "-o", str(out)]) == 0
    measures = json.loads(out.read_text())["measures"]
    assert measures["approval_rate"] == {"n": 1, "value": 1.0} and measures["case_minutes"]["n"] == 1


# --------------------------------------------------------------------------- the pilot gate


def pilot_findings(example):
    return run_gate(Stage.PILOT, load_project(example), load_platform()).findings


def edit_pilot(example, fn):
    path = example / "evals/pilot.json"
    data = json.loads(path.read_text())
    fn(data)
    path.write_text(json.dumps(data))


def test_the_example_meets_its_outcomes(example):
    assert not codes(pilot_findings(example)) and "AOF-G057" not in {f.code for f in pilot_findings(example)}


def test_a_missed_target_fails_the_pilot_with_the_baseline(example):
    edit_pilot(example, lambda d: d["measures"]["case_minutes"].update(median=7.5))
    msgs = [f.message for f in pilot_findings(example) if f.code == "AOF-G056"]
    assert msgs == ["outcome handling_time: median case_minutes 7.5, target at most 6 (baseline 18)"]


def test_rates_are_checked_as_values(example):
    edit_pilot(example, lambda d: d["measures"]["rework_rate"].update(value=0.08))
    assert [f.message for f in pilot_findings(example) if f.code == "AOF-G056"] == \
        ["outcome wrong_refunds: rework_rate 0.08, target at most 0.05"]


def test_unmeasured_outcomes_fail(example):
    edit_pilot(example, lambda d: d.pop("measures"))
    assert {f.message.split(":")[0] for f in pilot_findings(example) if f.code == "AOF-G055"} == \
        {"outcome handling_time", "outcome wrong_refunds"}


def test_a_minimum_target(example, edit_yaml):
    edit_yaml(example / "aof/use-case.yaml", lambda d: d.update(outcome_metrics=[
        {"name": "agreement", "measure": "approval_rate", "target": {"min": 0.97}}]))
    assert [f.code for f in pilot_findings(example) if f.code.startswith("AOF-G05")] == ["AOF-G056"]


def test_no_outcome_metrics_is_a_warning(example, edit_yaml):
    edit_yaml(example / "aof/use-case.yaml", lambda d: d.pop("outcome_metrics"))
    findings = pilot_findings(example)
    assert "AOF-G057" in {f.code for f in findings} and not codes(findings)


@pytest.mark.parametrize("metric", [
    {"name": "t", "measure": "case_minutes", "target": {}},
    {"name": "t", "measure": "case_minutes", "target": {"max": 1, "min": 0}},
    {"name": "t", "measure": "happiness", "target": {"max": 1}},
])
def test_bad_metrics_are_schema_errors(example, edit_yaml, metric):
    edit_yaml(example / "aof/use-case.yaml", lambda d: d.update(outcome_metrics=[metric]))
    assert load_project(example).load_findings
