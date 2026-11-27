"""DS8: agents that must decide on values they may not see (docs/data-safety.md).

The refunds example is T3, so the platform puts it on metadata_only. Under
`results: enforce` its agent can't see an order's status or amount. Three things let
it work anyway: verdicts (typed decisions the app computes), value references
(`{{res_<id>.amount}}` resolved by the gateway before the policy), and exceptions the
review board signs for single fields.
"""

from __future__ import annotations

import asyncio

import pytest
import yaml

from aof.checks import validate
from aof.enums import AutonomyLevel
from aof.gateway import APPROVAL_ARG, Gateway, Principal, ToolResult, UpstreamTool
from aof.gateway.compiled import CompiledPolicy
from aof.loader import load_project
from aof.models.project import Autonomy
from aof.platform import load_platform
from aof.policy import compile_policy

from .conftest import codes
from .test_gateway_vault import has_number

ALICE = Principal.of("alice", ["orders:read", "refunds:read", "refunds:create", "tickets:write"], tenant="DE01",
                     roles={"support-lead"})
BOB = Principal.of("bob", ["orders:read", "refunds:create"], tenant="DE01")
LEAD = Principal.of("lena", roles={"support-lead"})
VERDICTS = {"status": {"type": "enum", "values": ["delivered", "in_transit", "lost", "returned"]},
            "refundable": {"type": "boolean"}}
ORDERS = {"ORD-1": ("delivered", True, 49.9), "ORD-BIG": ("delivered", True, 250.0),
          "ORD-ODD": ("delivered on 2026-10-01, total 4711.00", True, 4711.0)}


class RefundsUpstream:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def list_tools(self, token=None):
        return [UpstreamTool(n, n, {"type": "object"}) for n in
                ("lookup_order", "create_refund_request", "update_ticket_status")]

    async def call_tool(self, name, args, token=None):
        self.calls.append((name, dict(args)))
        if name == "lookup_order":
            status, refundable, amount = ORDERS[args["order_id"]]
            return ToolResult({"order_id": args["order_id"], "status": status, "refundable": refundable,
                               "amount": amount, "customer_id": "CUS-88123"})
        if name == "create_refund_request":
            if args["amount"] > 1000:
                return ToolResult(f"amount {args['amount']:.2f} exceeds the order total", is_error=True)
            if args.get("dry_run"):
                return ToolResult({"dry_run": True, "would_create": {"amount": args["amount"]}})
            return ToolResult({"created": True, "amount": args["amount"]})
        return ToolResult({"applied": True, **args})


def edit(path, fn):
    data = yaml.safe_load(path.read_text())
    fn(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


@pytest.fixture
def refunds(example):
    """The refunds example on metadata_only + enforce, with verdicts on lookup_order."""
    def manifest(d):
        lookup = next(t for t in d["tools"] if t["name"] == "lookup_order")
        lookup["verdicts"] = VERDICTS
    edit(example / "aof/tools.manifest.yaml", manifest)
    edit(example / "aof.yaml", lambda d: d.setdefault("data_safety", {}).update(results="enforce"))
    return example


def policy(app, level="L2", within_limits=False) -> CompiledPolicy:
    lp = load_project(app)
    lp.project.autonomy = Autonomy(current=AutonomyLevel(level), target=AutonomyLevel(level))
    data = compile_policy(lp.project, lp.manifest, load_platform(), lp.data_contracts)
    if within_limits:  # L3: refunds up to the limit run without a human
        rule = next(t for t in data["tools"] if t["name"] == "create_refund_request")
        rule.update(decision="allow_within_limits", limits={"max_amount": 200})
    return CompiledPolicy.model_validate(data)


def gateway(app, **kw):
    up = RefundsUpstream()
    return Gateway(policy(app, **kw), up), up


def call(gw, tool, args, who=ALICE, run_id="run-1"):
    return asyncio.run(gw.call_tool(who, tool, args, run_id=run_id))


def errors(app):
    return codes(validate(load_project(app), load_platform()).findings)


# --------------------------------------------------------------------------- contract rules


def test_the_example_with_verdicts_validates(refunds):
    assert errors(refunds) == set()
    rule = next(t for t in policy(refunds).tools if t.name == "lookup_order")
    assert rule.verdicts["status"]["values"][0] == "delivered" and rule.verdicts["refundable"]["type"] == "boolean"


def test_verdict_rules(refunds):
    def wide(d):
        lookup = next(t for t in d["tools"] if t["name"] == "lookup_order")
        lookup["verdicts"]["status"]["values"] = [f"v{i}" for i in range(9)]  # platform allows 8
        lookup["result_keys"] = {"refundable": "token"}
    edit(refunds / "aof/tools.manifest.yaml", wide)
    lp = load_project(refunds)
    msgs = [f.message for f in validate(lp, load_platform()).findings if f.code == "AOF-P079"]
    assert len(msgs) == 2 and any("9 values" in m for m in msgs) and any("both" in m for m in msgs)


def test_an_enum_verdict_needs_two_values(refunds):
    edit(refunds / "aof/tools.manifest.yaml", lambda d: next(t for t in d["tools"] if t["name"] == "lookup_order")
         ["verdicts"].update(status={"type": "enum", "values": ["delivered"]}))
    assert load_project(refunds).load_findings  # schema error


SIGNOFF = {"by": "review-board", "date": "2026-11-28", "ref": "RB-77"}


def test_exceptions_must_name_a_field_and_stay_within_the_contract(refunds):
    edit(refunds / "aof.yaml", lambda d: d["data_safety"].update(exceptions=[
        {"field": "order_facts.nope", "exposure": "allowed", "reason": "the agent compares amounts", "signoff": SIGNOFF},
        {"field": "order_facts.customer_id", "exposure": "allowed", "reason": "the agent needs the customer",
         "signoff": SIGNOFF},  # confidential: the contract allows none
        {"field": "lookup_order.ticket_ref", "exposure": "allowed", "reason": "the agent links the ticket",
         "signoff": SIGNOFF},
    ]))
    findings = [f for f in validate(load_project(refunds), load_platform()).findings if f.code in ("AOF-P077", "AOF-P078")]
    assert sorted(f.code for f in findings) == ["AOF-P077", "AOF-P077", "AOF-P078"]


def test_a_signed_exception_lifts_metadata_only_for_one_field(refunds):
    edit(refunds / "aof.yaml", lambda d: d["data_safety"].update(exceptions=[
        {"field": "order_facts.amount", "exposure": "aggregate", "reason": "refund totals per customer",
         "signoff": SIGNOFF}]))
    assert errors(refunds) == set()
    views = policy(refunds).data_safety["views"]
    cols = views["order_facts"]["columns"]
    assert cols["amount"]["exposure"] == "aggregate" and cols["order_id"]["exposure"] == "none"


def test_an_exception_needs_a_reason_and_signoff(refunds):
    edit(refunds / "aof.yaml", lambda d: d["data_safety"].update(exceptions=[
        {"field": "order_facts.amount", "exposure": "aggregate", "reason": "x"}]))
    assert load_project(refunds).load_findings


# --------------------------------------------------------------------------- verdicts


def test_verdicts_are_shown_on_metadata_only_and_values_are_not(refunds):
    gw, _ = gateway(refunds)
    body = call(gw, "lookup_order", {"order_id": "ORD-1"}).content
    assert body["result"] == {"status": "delivered", "refundable": True}
    assert "amount" in body["hidden_keys"] and not has_number(body, "49.9")
    assert "{{" + body["result_handle"] + ".amount}}" in body["next"]  # how to pass it on


def test_a_verdict_outside_its_type_is_dropped(refunds):
    gw, _ = gateway(refunds)
    body = call(gw, "lookup_order", {"order_id": "ORD-ODD"}).content
    assert body["result"] == {"refundable": True} and "status" in body["hidden_keys"]
    assert not has_number(body, "4711")


# --------------------------------------------------------------------------- value references


def test_a_reference_reaches_the_approver_and_the_app_but_not_the_agent(refunds):
    gw, up = gateway(refunds)
    handle = call(gw, "lookup_order", {"order_id": "ORD-1"}).content["result_handle"]
    args = {"order_id": "ORD-1", "amount": f"{{{{{handle}.amount}}}}", "reason": "not_delivered",
            "request_id": "6f1c2a9e-0000-4000-8000-000000000001"}
    res = call(gw, "create_refund_request", args).content
    assert res["status"] == "approval_required" and not has_number(res, "49.9")
    approval = gw.approvals.get(res["approval_id"])
    assert approval.args["amount"] == 49.9 and approval.preview["would_create"]["amount"] == 49.9  # the human sees it
    gw.approvals.approve(res["approval_id"], LEAD)
    done = call(gw, "create_refund_request", {**args, APPROVAL_ARG: res["approval_id"]})
    assert up.calls[-1] == ("create_refund_request", {**args, "amount": 49.9, "dry_run": False})
    assert not has_number(done.content, "49.9")  # the app's echo is shaped too
    rec = [r for r in gw.audit.read() if r["event"] == "approval_requested"][-1]
    assert rec["references"] == 1 and not has_number(rec, "49.9")


def test_limits_apply_to_the_resolved_value(refunds):
    gw, up = gateway(refunds, level="L3", within_limits=True)
    small = call(gw, "lookup_order", {"order_id": "ORD-1"}).content["result_handle"]
    big = call(gw, "lookup_order", {"order_id": "ORD-BIG"}).content["result_handle"]
    base = {"order_id": "ORD-1", "reason": "goodwill", "request_id": "6f1c2a9e-0000-4000-8000-000000000002"}
    ok = call(gw, "create_refund_request", {**base, "amount": f"{{{{{small}.amount}}}}"})
    assert not ok.is_error and up.calls[-1][1]["amount"] == 49.9
    held = call(gw, "create_refund_request", {**base, "amount": f"{{{{{big}.amount}}}}"}).content
    assert held["status"] == "approval_required"
    assert "exceeds limit 200" in held["reason"] and not has_number(held, "250")  # no echo of the hidden amount


def test_references_in_text_and_on_ungoverned_tools(refunds):
    gw, up = gateway(refunds)
    handle = call(gw, "lookup_order", {"order_id": "ORD-1"}).content["result_handle"]
    res = call(gw, "update_ticket_status", {"ticket_id": "T-1", "status": "pending_refund",
                                            "note": f"refund of {{{{{handle}.amount}}}} EUR proposed",
                                            "dry_run": True})
    assert up.calls[-1][1]["note"] == "refund of 49.9 EUR proposed"
    assert not has_number(res.content, "49.9")  # the echoed note is hidden from the agent


def test_app_errors_after_a_reference_are_hidden(refunds):
    gw, _ = gateway(refunds, level="L3", within_limits=True)
    odd = call(gw, "lookup_order", {"order_id": "ORD-ODD"}).content["result_handle"]
    base = {"order_id": "ORD-ODD", "reason": "goodwill", "request_id": "x", "amount": f"{{{{{odd}.amount}}}}"}
    held = call(gw, "create_refund_request", base).content  # over the limit: approval, dry run fails
    assert held["error"] == "DRY_RUN_FAILED" and "upstream" not in held and not has_number(held, "4711")
    gw2, _ = gateway(refunds, level="L3", within_limits=True)
    gw2.policy.tools[[t.name for t in gw2.policy.tools].index("create_refund_request")].limits = {"max_amount": 10000}
    odd2 = call(gw2, "lookup_order", {"order_id": "ORD-ODD"}).content["result_handle"]
    res = call(gw2, "create_refund_request", {**base, "amount": f"{{{{{odd2}.amount}}}}"})
    assert res.is_error and res.content["error"] == "TOOL_FAILED" and not has_number(res.content, "4711")


def test_bad_and_foreign_references_are_refused(refunds):
    gw, up = gateway(refunds)
    handle = call(gw, "lookup_order", {"order_id": "ORD-1"}).content["result_handle"]
    n = len(up.calls)
    bad = call(gw, "create_refund_request", {"order_id": "ORD-1", "amount": f"{{{{{handle}.nope}}}}",
                                             "reason": "goodwill", "request_id": "x"})
    assert bad.is_error and bad.content["error"] == "REFERENCE_INVALID"
    foreign = call(gw, "create_refund_request", {"order_id": "ORD-1", "amount": f"{{{{{handle}.amount}}}}",
                                                 "reason": "goodwill", "request_id": "x"}, who=BOB)
    assert foreign.is_error and foreign.content["error"] == "RESULT_NOT_FOUND"
    assert len(up.calls) == n  # nothing reached the app
    assert [r["code"] for r in gw.audit.read() if r["event"] == "reference_refused"] == \
        ["REFERENCE_INVALID", "RESULT_NOT_FOUND"]


def test_query_results_need_a_row_unless_there_is_one():
    from aof.gateway.shield import _follow
    from aof.gateway.vault import VaultError

    one = {"columns": ["opex"], "rows": [[180.0]]}
    two = {"columns": ["cc", "opex"], "rows": [["CC10", 1.0], ["CC20", 2.0]]}
    assert _follow(one, "opex", "res_x") == 180.0 and _follow(two, "rows[1].OPEX", "res_x") == 2.0
    with pytest.raises(VaultError, match="2 rows"):
        _follow(two, "opex", "res_x")
    with pytest.raises(VaultError, match="single value"):
        _follow({"items": [{"sku": "A"}]}, "items", "res_x")
