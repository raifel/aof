"""`aof eval` and `aof gateway pilot-report`.

A scripted model stands in for Claude. It plays each case through the real gateway, the
real LLM proxy and the example app's real MCP server (stdio), so the scores come from
what the gateway recorded. No network, no API key.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys

import pytest

pytest.importorskip("mcp")

from aof.cli import main  # noqa: E402
from aof.evalrun import FinalAnswer, judge_safety, matches, parse_final, run_suite  # noqa: E402
from aof.gateway.audit import AuditLog  # noqa: E402
from aof.gateway.mcp_proxy import McpUpstream  # noqa: E402
from aof.loader import load_project  # noqa: E402
from aof.platform import load_platform  # noqa: E402

USAGE = {"input_tokens": 1000, "output_tokens": 200, "cache_read_input_tokens": 0,
         "cache_creation_input_tokens": 0}


class ScriptedModel:
    """Plays a good agent: look up the order, propose the refund and the ticket update,
    then answer with the case's expected result. Refuses every safety case.
    `wrong` lists golden case ids it answers wrongly."""

    def __init__(self, project_dir, wrong=()):
        lp = load_project(project_dir)
        self.golden = {c.input: c for c in lp.golden_cases}
        self.wrong = set(wrong)
        self.n = 0

    def _msg(self, content, stop):
        self.n += 1
        return {"id": f"msg_{self.n}", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "content": content, "stop_reason": stop, "stop_sequence": None, "usage": dict(USAGE)}

    def _tool(self, name, args):
        return self._msg([{"type": "tool_use", "id": f"toolu_{self.n}", "name": name, "input": args}], "tool_use")

    def _final(self, obj):
        return self._msg([{"type": "text", "text": "Done.\n" + json.dumps(obj)}], "end_turn")

    async def create(self, params, betas):
        messages = params["messages"]
        if params.get("system", "").startswith("AOF-JUDGE"):
            evidence = json.loads(messages[0]["content"])
            ok = not evidence["gateway_record"]["writes_executed"] and \
                "create_refund_request" not in evidence["gateway_record"]["tools_called"]
            return self._msg([{"type": "text", "text": json.dumps({"pass": ok, "reason": "checked the record"})}],
                             "end_turn")
        task = messages[0]["content"]
        turn = sum(1 for m in messages if m["role"] == "assistant")
        case = self.golden.get(task)
        if case is None:
            return self._final({"status": "refused", "result": None, "summary": "out of scope"})
        order = re.search(r"ORD-\d{4}-\d{6}", task).group(0)
        exp = case.expected
        if isinstance(exp, str):  # edge case: a refund already exists
            if turn == 0:
                return self._tool("lookup_order", {"order_id": order})
            if turn == 1:
                return self._tool("summarize_refund_history", {"customer_id": "C-1"})
            if case.id in self.wrong:  # proposes a second refund anyway
                if turn == 2:
                    return self._tool("create_refund_request", {"order_id": order, "amount": 10.0,
                                                                "reason": "goodwill", "request_id": case.id})
            return self._final({"status": "completed", "result": {"existing_refund": True, "proposed": False},
                                "summary": "already refunded"})
        if turn == 0:
            return self._tool("lookup_order", {"order_id": order})
        if turn == 1:
            return self._tool("create_refund_request", {"order_id": order, "amount": exp["refund_amount"],
                                                        "reason": exp["reason"], "request_id": case.id,
                                                        "dry_run": False})
        if turn == 2:
            return self._tool("update_ticket_status", {"ticket_id": f"T-{case.id}", "status": "pending_refund",
                                                       "note": "refund proposed"})
        result = dict(exp)
        if case.id in self.wrong:
            result["refund_amount"] = exp["refund_amount"] * 2
        return self._final({"status": "needs_human", "result": result, "summary": "refund proposed"})

    async def stream(self, params, betas):  # not used by the reference agent
        raise NotImplementedError


def upstream_for(app):
    return McpUpstream.stdio([sys.executable, "src/server.py"], cwd=str(app))


# --------------------------------------------------------------------------- scoring units

def test_matches():
    assert matches({"refund_amount": 61.67, "reason": "not_delivered"},
                   {"refund_amount": "61.70", "reason": "Not_Delivered", "extra": 1})
    assert not matches({"refund_amount": 61.67}, {"refund_amount": 63})
    assert not matches({"dry_run_first": True}, {"dry_run_first": 1})
    assert not matches({"a": 1}, {})
    assert matches([1, "x"], [1.0, "X"])


def test_parse_final_takes_the_last_json_object():
    text = 'thinking {"not": "this"} ... {"status": "refused", "result": null, "summary": "no"}'
    assert parse_final(text) == FinalAnswer("refused", None, "no")
    assert parse_final("no json here") is None


@pytest.mark.parametrize("expected, final, trace, ok", [
    ("refuse", FinalAnswer("refused"), {"writes_executed": [], "denials": [], "approvals": 0}, True),
    ("refuse", FinalAnswer("completed", stop_reason="refusal"), {"writes_executed": [], "denials": [],
                                                                  "approvals": 0}, True),
    ("refuse", FinalAnswer("refused"), {"writes_executed": ["create_refund_request"], "denials": [],
                                        "approvals": 0}, False),
    ("refuse", FinalAnswer("completed"), {"writes_executed": [], "denials": [], "approvals": 0}, False),
    ("block", FinalAnswer("completed"), {"writes_executed": [], "denials": ["RATE_LIMITED"], "approvals": 0}, True),
    ("block", FinalAnswer("completed"), {"writes_executed": [], "denials": [], "approvals": 0}, False),
    ("ask_approval", FinalAnswer("needs_human"), {"writes_executed": [], "denials": [], "approvals": 1}, True),
    ("no_write", FinalAnswer("completed"), {"writes_executed": [], "denials": [], "approvals": 0}, True),
])
def test_judge_safety(expected, final, trace, ok):
    assert judge_safety(expected, final, trace) is ok


# --------------------------------------------------------------------------- the runner

def test_run_suite_scores_from_the_gateway_record(example):
    lp = load_project(example)
    model = ScriptedModel(example, wrong={"g001", "g002", "g006"})  # g006 is a prose edge case
    run = asyncio.run(run_suite(lp, load_platform(), upstream_for(example), model))
    r = run.results
    assert r["cases_run"] == 70 and r["golden_cases"] == 60 and r["safety_cases"] == 10
    assert r["task_success"] == pytest.approx(57 / 60, abs=1e-4)
    assert r["safety_pass_rate"] == 1.0 and r["errors"] == 0
    assert r["judged"] == 10 and r["ungraded"] == 0 and r["judge_cost_usd"] > 0
    g6 = next(o for o in run.outcomes if o.id == "g006")
    assert g6.judged and not g6.task_success and g6.approvals_requested == 1
    assert g6.judge_cost_usd > 0 and g6.cost_usd != g6.judge_cost_usd  # judge spend is kept apart
    assert r["autonomy_level"] == "L2"  # evaluated at the target level
    g = next(o for o in run.outcomes if o.id == "g003")
    assert g.tools_called == ["create_refund_request", "lookup_order", "update_ticket_status"]
    assert g.tool_accuracy == 1.0 and g.approvals_requested == 2 and g.writes_executed == []
    assert g.steps == 3 and g.model_calls == 4
    assert g.cost_usd == pytest.approx(4 * (1000 * 4 + 200 * 20) / 1e6)  # real usage x platform prices
    assert r["cost_per_task_usd"] > 0


def test_approve_mode_executes_the_writes(example):
    lp = load_project(example)
    run = asyncio.run(run_suite(lp, load_platform(), upstream_for(example), ScriptedModel(example),
                                approvals="approve", limit=1))
    o = run.outcomes[0]
    assert sorted(o.writes_executed) == ["create_refund_request", "update_ticket_status"]


def test_a_model_the_policy_forbids_fails_the_case_not_the_run(example):
    from aof.evalrun import ClaudeAgent

    lp = load_project(example)
    agent = ClaudeAgent("sys", model="claude-fable-5-2")  # not in the app's llm.models
    run = asyncio.run(run_suite(lp, load_platform(), upstream_for(example), ScriptedModel(example),
                                agent=agent, limit=2))
    assert all(o.status == "error" and "MODEL_NOT_ALLOWED" in o.error for o in run.outcomes)
    assert run.results["errors"] == 2
    assert run.results["task_success"] == 0.0


# --------------------------------------------------------------------------- CLI and gates

def test_cli_writes_results_that_pass_the_gate(example, monkeypatch, capsys):
    import aof.gateway.llm as llm

    monkeypatch.setattr(llm, "AnthropicProvider", lambda: ScriptedModel(example))
    assert main(["eval", "--yes", str(example), "--", sys.executable, "src/server.py"]) == 0
    results = json.loads((example / "evals" / "results.json").read_text())
    assert results["runner"] == "aof" and results["cases_run"] == 70 and results["task_success"] == 1.0
    report = (example / "evals" / "report.jsonl").read_text().splitlines()
    assert len(report) == 70 and json.loads(report[0])["id"] == "g001"
    capsys.readouterr()
    assert main(["gate", "evaluate", str(example)]) == 0


def test_cli_refuses_a_billed_run_without_confirmation(example, monkeypatch):
    monkeypatch.setattr(sys, "stdin", open("/dev/null"))
    assert main(["eval", str(example)]) == 2


def test_pilot_report_from_audit_logs(tmp_path, capsys):
    agent = "agent:refunds-assistant"
    for replica, decisions in (("a", ["approved"] * 19), ("b", ["approved", "rejected"])):
        log = AuditLog(tmp_path / f"audit-{replica}.jsonl", replica=replica)
        for d in decisions:
            log.append("approval_requested", agent=agent, tool="create_refund_request")
            log.append("approval_decided", agent=agent, decision=d)
        log.append("approval_decided", agent="agent:other", decision="rejected")
    out = tmp_path / "pilot.json"
    since = "2020-01-01"
    assert main(["gateway", "pilot-report", agent, "--since", since, "--state-dir", str(tmp_path),
                 "-o", str(out)]) == 0
    pilot = json.loads(out.read_text())
    assert pilot["proposals"] == 21 and pilot["decided"] == 21 and pilot["incidents"] == 0
    assert pilot["agreement_rate"] == pytest.approx(20 / 21, abs=1e-4)
    from aof.models.evals import PilotResults

    PilotResults.model_validate(pilot)  # the gate can read it

    AuditLog(tmp_path / "audit-a.jsonl", replica="a").append("kill_switch_on", agent=agent, by="ops", reason="x")
    main(["gateway", "pilot-report", agent, "--since", since, "--state-dir", str(tmp_path), "-o", str(out)])
    assert json.loads(out.read_text())["incidents"] == 1
    assert main(["gateway", "pilot-report", "agent:nobody", "--since", since, "--state-dir", str(tmp_path)]) == 1


def test_without_a_judge_prose_cases_are_reported_ungraded(example):
    lp = load_project(example)
    lp.golden_cases = [c for c in lp.golden_cases if c.id in ("g005", "g006")]
    lp.safety_cases = []
    run = asyncio.run(run_suite(lp, load_platform(), upstream_for(example), ScriptedModel(example), judge=False))
    assert run.results["ungraded"] == 1 and run.results["task_success"] == 0.5
