"""D6: answer templates, POST /render, template fidelity and the probe signal."""

from __future__ import annotations

import json

import httpx2
import pytest

from aof.gateway.render import UNAVAILABLE, apply_filter, render, stray_numbers

from .test_gateway_vault import (OPEX_Q3, call, gateway, has_number, results_app, run,  # noqa: F401
                                 app)

pytest.importorskip("duckdb")


# --------------------------------------------------------------------------- the template language


@pytest.mark.parametrize("value, name, arg, out", [
    ("180.00", "money", None, "180.00"),
    (1234567.891, "money", "EUR", "1,234,567.89 EUR"),
    (0.125, "pct", None, "12.5%"),
    ("0.1", "pct", "0", "10%"),
    (1234.5, "number", None, "1,234.5"),
    (1234.5678, "number", "2", "1,234.57"),
    ("41.6", "int", None, "42"),
    ("2025-10-01 00:00:00", "date", None, "2025-10-01"),
    (180.0, None, None, "180"),
    ("CC10", None, None, "CC10"),
])
def test_filters(value, name, arg, out):
    assert apply_filter(value, name, arg) == out


def test_render_fills_placeholders_and_marks_what_it_cannot():
    data = {"res_0123456789ab": {"columns": ["cc", "opex"], "rows": [["CC10", 100.0], ["CC20", 2500.5]]}}

    def lookup(handle, path):
        from aof.gateway.shield import _follow
        return _follow(data[handle], path, handle)

    out = render("CC20 spent {{ res_0123456789ab.rows[1].opex | money:EUR }}; "
                 "{{res_0123456789ab.opex}} {{res_0123456789ab.rows[0].opex | pct}} "
                 "{{res_ffffffffffff.x}} {{res_0123456789ab.rows[0].cc | bogus}}", lookup)
    assert out.text.startswith("CC20 spent 2,500.50 EUR; ")
    assert out.text.count(UNAVAILABLE) == 3  # two rows; unknown handle; unknown filter
    assert out.references == 5 and out.handles == ["res_0123456789ab", "res_ffffffffffff"]
    assert "10,000.0%" in out.text and len(out.missing) == 3


def test_stray_numbers_are_figures_outside_placeholders():
    q = "What was opex by cost centre for DE01 in FY2026 Q3? Compare with 120,000."
    assert stray_numbers("Opex was {{res_0123456789ab.opex | money}} across 3 cost centres in FY2026 Q3.", q) == []
    assert stray_numbers("Opex was 1,234.50 EUR, up 4.2% on 2025.", q) == ["1,234.50", "4.2%"]
    assert stray_numbers("Above the 120,000 you mentioned; see res_0123456789ab.", q) == []
    assert stray_numbers("Roughly 350 thousand.", q) == ["350"]


# --------------------------------------------------------------------------- POST /render


def post(asgi, path, body, token=None):
    async def go():
        headers = {"authorization": f"Bearer {token}"} if token else {}
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=asgi), base_url="https://gw.test") as c:
            r = await c.post(path, headers=headers, content=json.dumps(body) if body is not None else b"{")
            return r.status_code, r.json()
    return run(go())


def test_ui_renders_the_agents_template(results_app):
    gw, asgi, handle = results_app
    status, body = post(asgi, "/render", {"template": f"Q3 opex: {{{{{handle}.opex | money:EUR}}}}."}, "ui-alice")
    assert status == 200 and body == {"text": "Q3 opex: 180.00 EUR.", "references": 1, "missing": []}
    rec = gw.audit.read()[-1]
    assert rec["event"] == "answer_rendered" and rec["result_handles"] == [handle] and rec["references"] == 1
    assert not has_number(rec, "180")


def test_render_refuses_the_agent_and_other_users(results_app):
    gw, asgi, handle = results_app
    tpl = {"template": f"{{{{{handle}.opex}}}}"}
    assert post(asgi, "/render", tpl, "agent-alice")[0] == 403
    assert gw.audit.read()[-1]["event"] == "render_refused"
    assert post(asgi, "/render", tpl)[0] == 401
    status, body = post(asgi, "/render", tpl, "ui-mallory")  # not her result: nothing filled
    assert status == 200 and body["text"] == UNAVAILABLE and body["missing"] == [tpl["template"]]
    assert post(asgi, "/render", None, "ui-alice")[1]["error"] == "TEMPLATE_INVALID"
    assert post(asgi, "/render", {"template": 7}, "ui-alice")[0] == 400


# --------------------------------------------------------------------------- probe signal


def test_queries_differing_only_by_constants_raise_a_signal(app):
    gw, _ = gateway(app, mode="contract")
    for vendor in ("V1", "V2", "V3", "V4", "V5", "V6"):  # same query, different constant
        call(gw, "query_ledger", {"query": {**OPEX_Q3, "filters": [{"dimension": "company", "op": "eq",
                                                                     "value": vendor}]}})
    events = [r for r in gw.audit.read() if r["event"] == "query_probe_suspected"]
    assert len(events) == 1 and events[0]["queries"] == 5 and events[0]["views"] == ["gl_journal_lines"]
    assert not any("V5" in json.dumps(r) for r in events)  # the shape, never the constants


def test_different_questions_raise_no_signal(app):
    gw, _ = gateway(app, mode="contract")
    for dims in ([], ["company"], ["posting_date:month"], ["company", "posting_date:month"], ["company"]):
        call(gw, "query_ledger", {"query": {**OPEX_Q3, "dimensions": dims,
                                            "filters": [{"dimension": "company", "op": "eq", "value": "DE01"}]}})
    assert not [r for r in gw.audit.read() if r["event"] == "query_probe_suspected"]
