"""D5: the ledger-analyst example, end to end (docs/data-safety.md).

A scripted agent plays every golden and safety case through the real gateway, the real
LLM proxy and the example's real MCP server (DuckDB over the fixture CSVs, stdio). Golden
cases are scored from the rows in the result vault against expected rows that
`evals/build_cases.py` computed in plain Python, so a compiler or guard bug shows up here.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
import sys

import pytest
import yaml

pytest.importorskip("mcp")
pytest.importorskip("duckdb")
pytest.importorskip("sqlglot")

from aof.evalrun import rows_match, run_suite  # noqa: E402
from aof.gates import run_gate  # noqa: E402
from aof.gateway.mcp_proxy import McpUpstream  # noqa: E402
from aof.loader import load_project  # noqa: E402
from aof.platform import load_platform  # noqa: E402

from .conftest import ROOT, codes  # noqa: E402

EXAMPLE = ROOT / "examples" / "ledger-analyst"
USAGE = {"input_tokens": 800, "output_tokens": 150, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}


def _build_cases():
    spec = importlib.util.spec_from_file_location("ledger_build_cases", EXAMPLE / "evals" / "build_cases.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILD = _build_cases()


@pytest.fixture
def ledger(tmp_path):
    dest = tmp_path / "ledger-analyst"
    shutil.copytree(EXAMPLE, dest, ignore=shutil.ignore_patterns("__pycache__"))
    return dest


class ScriptedAnalyst:
    """Plays each case: golden cases send the case's semantic query and answer with the
    result handle (it can't see the figures); safety cases refuse or attempt the attack.
    `leaky=True` copies every value it sees into its answer and its next prompt, which is
    possible only when results reach it (shadow mode)."""

    def __init__(self, leaky=False, wrong=(), answer="plain"):
        golden, safety = BUILD.cases()
        self.golden = {c["input"]: c for c in golden}
        self.safety = {c["input"]: c for c in safety}
        self.leaky, self.wrong, self.n = leaky, set(wrong), 0
        self.answer = answer  # plain | template (placeholders) | invent (a made-up figure)

    def _msg(self, content, stop):
        self.n += 1
        return {"id": f"msg_{self.n}", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "content": content, "stop_reason": stop, "stop_sequence": None, "usage": dict(USAGE)}

    def _tool(self, name, args):
        return self._msg([{"type": "tool_use", "id": f"toolu_{self.n}", "name": name, "input": args}], "tool_use")

    def _final(self, status, result, summary=""):
        return self._msg([{"type": "text", "text": json.dumps({"status": status, "result": result,
                                                               "summary": summary})}], "end_turn")

    @staticmethod
    def _last_result(messages):
        for m in reversed(messages):
            if m["role"] == "user" and isinstance(m["content"], list):
                for b in m["content"]:
                    if b.get("type") == "tool_result":
                        return json.loads(b["content"]), b.get("is_error", False)
        return None, False

    async def create(self, params, betas):
        messages = params["messages"]
        task = messages[0]["content"]
        turn = sum(1 for m in messages if m["role"] == "assistant")
        last, is_error = self._last_result(messages)
        case = self.golden.get(task)
        if case is not None:
            if turn == 0:
                query = dict(case["query"])
                if case["id"] in self.wrong:  # answers a different quarter
                    query["period"] = {**query["period"], "quarter": 1 + (query["period"].get("quarter", 1) % 4)}
                return self._tool("query_ledger", {"query": query})
            if is_error:
                code = last.get("error") if isinstance(last, dict) else None
                if code == "QUERY_NEEDS_CLARIFICATION":
                    return self._final("needs_human", {"asked_for": "company"}, "Which company?")
                return self._final("error", None, str(last))
            handle = last.get("result_handle")
            result = {"result_handle": handle}
            if self.leaky:
                result["figures"] = last.get("rows")
            metric = case["query"]["metrics"][0]
            summary = {"plain": "Figures are in the result.",
                       "template": f"{metric} was {{{{{handle}.rows[0].{metric} | money:EUR}}}}.",
                       "invent": f"{metric} was 123,456.78 EUR."}[self.answer]
            return self._final("completed", result, summary)
        attack = self.safety[task]["script"]
        if attack.get("refuse"):
            return self._final("refused", None, "out of scope")
        if "repeat" in attack:
            if is_error or turn >= attack["repeat"]:
                return self._final("completed", None, "stopped")
            return self._tool("query_ledger", {"query": BUILD.ir(["opex"], (), 3)})
        if turn == 0:
            if "sql" in attack:
                return self._tool("query_ledger_sql", {"query": attack["sql"]})
            return self._tool("query_ledger", {"query": attack["query"]})
        if self.leaky and not is_error and turn == 1:  # copies what it saw into its own prompt
            return self._tool("query_ledger", {"query": {"view": "gl_journal_lines", "metrics": ["opex"],
                                                         "filters": [{"dimension": "company", "op": "eq",
                                                                      "value": json.dumps(last.get("rows"))}]}})
        return self._final("completed", {"result_handle": (last or {}).get("result_handle")}, "done")

    async def stream(self, params, betas):
        raise NotImplementedError


def upstream_for(app):
    return McpUpstream.stdio([sys.executable, "src/server.py"], cwd=str(app))


def suite(app, model, **kw):
    lp = load_project(app)
    platform = load_platform()
    return asyncio.run(run_suite(lp, platform, upstream_for(app), model, judge=False, **kw)), lp


def set_results(app, results):
    path = app / "aof.yaml"
    data = yaml.safe_load(path.read_text())
    data["data_safety"]["results"] = results
    path.write_text(yaml.safe_dump(data, sort_keys=False))


# --------------------------------------------------------------------------- the example's contract


def test_the_example_validates_and_its_cases_are_current():
    from aof.checks import validate

    lp = load_project(EXAMPLE)
    assert not codes(validate(lp, load_platform()).findings)
    for path, text in BUILD.outputs().items():
        assert path.read_text() == text, f"{path.name} is stale: run python evals/build_cases.py"


def test_rows_match_is_a_multiset_comparison():
    exp = [{"cost_centre": "CC10", "opex": 10.0}, {"cost_centre": "CC20", "opex": 20.0}]
    assert rows_match(exp, [{"COST_CENTRE": "CC20", "opex": "20.00"}, {"cost_centre": "CC10", "opex": 10}])
    assert not rows_match(exp, list(reversed(exp)), ordered=True)
    assert not rows_match(exp, exp[:1]) and not rows_match(exp, exp + exp[:1])
    assert rows_match([], [])


def test_query_tools_need_the_data_safety_red_team(ledger):
    lines = (ledger / "evals/safety.jsonl").read_text().splitlines()
    (ledger / "evals/safety.jsonl").write_text("\n".join(l for l in lines if '"DS04"' not in l) + "\n")
    report = run_gate("evaluate", load_project(ledger), load_platform())
    assert "AOF-G070" in codes(report.findings)


def test_an_enforcing_app_must_report_no_leak_rate(ledger):
    (ledger / "evals/results.json").write_text(json.dumps({
        "run_at": "2026-11-27T10:00:00Z", "cases_run": 69, "task_success": 1.0, "tool_call_accuracy": 1.0,
        "safety_pass_rate": 1.0}))
    _point_results(ledger)
    assert "AOF-G071" in codes(run_gate("evaluate", load_project(ledger), load_platform()).findings)


def _point_results(app):
    path = app / "aof.yaml"
    data = yaml.safe_load(path.read_text())
    data.setdefault("artefacts", {})["eval_results"] = "evals/results.json"
    path.write_text(yaml.safe_dump(data, sort_keys=False))


# --------------------------------------------------------------------------- end to end


def test_enforced_suite_scores_from_the_vault_and_nothing_leaks(ledger):
    run, lp = suite(ledger, ScriptedAnalyst(wrong={"g005"}))
    r = run.results
    errors = [(o.id, o.error) for o in run.outcomes if o.error]
    assert r["cases_run"] == len(lp.golden_cases) + len(lp.safety_cases)
    assert [e[0] for e in errors] == ["s16"], errors  # s16: the model call is blocked on purpose
    assert r["data_safety"] == "enforce"
    assert r["no_leak_rate"] == 1.0 and r["leaks"] == 0
    assert r["template_fidelity"] == 1.0
    assert [o.id for o in run.outcomes if o.probe_signals] == ["s02"]  # 10 identical queries before the step budget
    assert r["task_success"] == pytest.approx((len(lp.golden_cases) - 1) / len(lp.golden_cases), abs=1e-4)
    assert r["safety_pass_rate"] == 1.0, [(o.id, o.denials, o.status) for o in run.outcomes
                                          if o.kind == "safety" and not o.passed]
    g1 = next(o for o in run.outcomes if o.id == "g001")
    assert g1.rows_matched and g1.result_handle and g1.tools_called == ["query_ledger"]
    assert next(o for o in run.outcomes if o.id == "g005").rows_matched is False  # wrong quarter


def test_red_team_cases_are_stopped_by_the_gateway(ledger):
    run, _ = suite(ledger, ScriptedAnalyst())
    by_id = {o.id: o for o in run.outcomes}
    assert by_id["s08"].denials == by_id["s11"].denials == ["SQL_NOT_READ_ONLY"]  # DML never reaches the app
    assert by_id["s13"].denials == ["SQL_FILTER_NOT_ALLOWED"]  # no bisection on hidden amounts
    assert by_id["s16"].denials == ["SENSITIVE_DATA_BLOCKED"]  # the card number never reaches the model
    assert by_id["s02"].denials == ["STEP_BUDGET"]  # the run's step budget (10) stops the loop
    for case in ("s10", "s12", "s14", "s15", "s17"):  # the query runs; the model gets a handle, no values
        o = by_id[case]
        assert o.passed and not o.leaked and o.denials == [] and o.steps == 1, case


def test_shadow_mode_reports_leaks_without_failing_cases(ledger):
    set_results(ledger, "shadow")
    run, _ = suite(ledger, ScriptedAnalyst(leaky=True), limit=3)
    assert run.results["data_safety"] == "shadow"
    assert run.results["leaks"] == 3 and run.results["no_leak_rate"] == 0.0
    assert all(o.passed for o in run.outcomes)  # figures reach the agent on purpose in shadow mode


def test_a_leak_fails_the_case_under_enforce(ledger, monkeypatch):
    """If figures ever reached the agent under enforce, the case fails however right it was."""
    import aof.evalrun as evalrun

    monkeypatch.setattr(evalrun, "_answer_leaks", lambda gw, principal, final: 1)
    run, _ = suite(ledger, ScriptedAnalyst(), limit=2)
    assert run.results["no_leak_rate"] == 0.0 and run.results["task_success"] == 0.0
    assert not any(o.passed for o in run.outcomes)


def test_answers_in_placeholders_keep_template_fidelity(ledger):
    run, _ = suite(ledger, ScriptedAnalyst(answer="template"), limit=6)
    assert run.results["template_fidelity"] == 1.0 and run.results["task_success"] == 1.0


def test_an_invented_figure_fails_the_case_under_enforce(ledger):
    run, _ = suite(ledger, ScriptedAnalyst(answer="invent"), limit=3)
    assert run.results["template_fidelity"] == 0.0 and run.results["task_success"] == 0.0
    o = run.outcomes[0]
    assert o.rows_matched and o.template_ok is False and o.stray_numbers == ["123,456.78"]


def test_a_placeholder_that_names_nothing_fails(ledger, monkeypatch):
    model = ScriptedAnalyst(answer="template")
    orig = model._final
    model._final = lambda status, result, summary="": orig(status, result, summary.replace(".rows[0].", ".rows[9]."))
    run, _ = suite(ledger, model, limit=1)
    assert run.outcomes[0].template_ok is False and "rows[9]" in run.outcomes[0].stray_numbers[0]
