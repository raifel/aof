from __future__ import annotations

import asyncio
import json

import pytest

from aof.enums import ApprovalMode, AutonomyLevel
from aof.gateway import (
    APPROVAL_ARG,
    ApprovalError,
    AuditLog,
    DurableStore,
    Gateway,
    GatewayState,
    Principal,
    ToolResult,
    UpstreamTool,
    verify,
)
from aof.gateway.compiled import CompiledPolicy
from aof.loader import load_project
from aof.models.project import Autonomy
from aof.platform import load_platform
from aof.policy import compile_policy

from .conftest import EXAMPLE

ALICE = Principal.of("alice", ["orders:read", "refunds:read", "refunds:create", "tickets:write"])
LEAD = Principal.of("bob", roles=["support-lead"])
REFUND = {"order_id": "ORD-2026-000184", "amount": 49.9, "reason": "damaged_in_transit", "request_id": "r-1"}


def make_policy(level: str = "L2", **budget_overrides) -> CompiledPolicy:
    lp = load_project(EXAMPLE)
    lvl = AutonomyLevel(level)
    lp.project.autonomy = Autonomy(current=lvl, target=max(lvl, AutonomyLevel.L2))
    if lvl >= AutonomyLevel.L3:
        lp.manifest.tool("update_ticket_status").approval.mode = ApprovalMode.WITHIN_LIMITS
    data = compile_policy(lp.project, lp.manifest, load_platform())
    data["budgets"].update(budget_overrides)
    return CompiledPolicy.model_validate(data)


class FakeUpstream:
    def __init__(self, policy: CompiledPolicy):
        self.calls: list[tuple[str, dict]] = []
        self.tokens: list[str | None] = []
        self.names = [t.name for t in policy.tools if t.risk_tier.value != "T4"] + ["export_everything"]

    async def list_tools(self, token=None):
        self.tokens.append(token)
        return [UpstreamTool(n, f"{n} tool", {"type": "object", "properties": {"x": {"type": "string"}}})
                for n in self.names]

    async def call_tool(self, name, args, token=None):
        self.calls.append((name, dict(args)))
        self.tokens.append(token)
        if args.get("dry_run"):
            return ToolResult({"dry_run": True, "would": name, "args": args})
        return ToolResult({"ok": True, "tool": name})


def make_gateway(level="L2", *, state=None, clock=None, **budgets):
    policy = make_policy(level, **budgets)
    up = FakeUpstream(policy)
    gw = Gateway(policy, up, state=state, **({"clock": clock} if clock else {}))
    return gw, up


def run(coro):
    return asyncio.run(coro)


def call(gw, tool, args=None, who=ALICE, run_id="run-1", **kw):
    return run(gw.call_tool(who, tool, args or {}, run_id=run_id, **kw))


# --------------------------------------------------------------------------- basics

def test_read_allowed_and_audited():
    gw, up = make_gateway()
    res = call(gw, "lookup_order", {"order_id": "ORD-1"})
    assert not res.is_error and up.calls == [("lookup_order", {"order_id": "ORD-1"})]
    rec = gw.audit.read()[-1]
    assert rec["event"] == "tool_executed" and rec["user"] == "alice"
    assert "ORD-1" not in json.dumps(rec)  # args are hashed, not stored
    assert verify(gw.audit.read()) == (True, None)


def test_writes_denied_at_read_only_level():
    gw, up = make_gateway("L1")
    res = call(gw, "create_refund_request", REFUND)
    assert res.is_error and res.content["error"] == "DENIED_BY_POLICY"
    assert up.calls == []


def test_unknown_tool_is_denied_and_demotes_on_violation():
    gw, up = make_gateway("L2")
    res = call(gw, "export_everything")
    assert res.content["error"] == "UNKNOWN_TOOL" and up.calls == []
    # platform SLO: max_policy_violations = 0, so one violation demotes one level
    assert gw.state.demoted_level(gw.agent_id) is AutonomyLevel.L1
    assert call(gw, "create_refund_request", REFUND).content["error"] == "DENIED_BY_POLICY"
    assert any(r["event"] == "autonomy_demoted" for r in gw.audit.read())


def test_t4_tool_always_denied():
    gw, _ = make_gateway("L3")
    gw.auto_demote = False
    res = call(gw, "delete_customer_account", {"customer_id": "CUS-1"})
    assert res.content["error"] == "DENIED_BY_POLICY"


def test_missing_scope_denied():
    gw, up = make_gateway()
    gw.auto_demote = False
    reader = Principal.of("carol", ["orders:read"])
    assert call(gw, "summarize_refund_history", {"customer_id": "C"}, who=reader).content["error"] == "MISSING_SCOPE"
    assert up.calls == []


def test_step_budget():
    gw, _ = make_gateway(max_steps_per_run=3)
    for _ in range(3):
        assert not call(gw, "lookup_order", {"order_id": "O"}).is_error
    assert call(gw, "lookup_order", {"order_id": "O"}).content["error"] == "STEP_BUDGET"
    assert not call(gw, "lookup_order", {"order_id": "O"}, run_id="run-2").is_error  # budgets are per run


def test_cost_budget():
    gw, _ = make_gateway()
    gw.record_model_cost("run-1", 0.60)  # example caps runs at $0.50
    assert call(gw, "lookup_order", {"order_id": "O"}).content["error"] == "COST_BUDGET"


def test_delegation_depth():
    gw, _ = make_gateway()
    res = call(gw, "lookup_order", {"order_id": "O"}, delegation_depth=11)
    assert res.content["error"] == "DELEGATION_DEPTH"


def test_rate_limit():
    gw, _ = make_gateway(max_steps_per_run=1000)
    gw.policy.rule("summarize_refund_history").rate_limit.calls = 2
    for _ in range(2):
        assert not call(gw, "summarize_refund_history", {"customer_id": "C"}).is_error
    assert call(gw, "summarize_refund_history", {"customer_id": "C"}).content["error"] == "RATE_LIMITED"


# --------------------------------------------------------------------------- approvals

def test_approval_flow_end_to_end():
    gw, up = make_gateway("L2")
    first = call(gw, "create_refund_request", REFUND)
    assert first.content["status"] == "approval_required"
    assert first.content["preview"]["dry_run"] is True  # preview came from a real dry-run
    assert up.calls[-1][1]["dry_run"] is True
    aid = first.content["approval_id"]

    # not approved yet
    assert call(gw, "create_refund_request", {**REFUND, APPROVAL_ARG: aid}).content["error"] == "APPROVAL_PENDING"
    # approver must hold the role, and cannot be the requester
    with pytest.raises(ApprovalError, match="role"):
        gw.approvals.approve(aid, Principal.of("dave"))
    with pytest.raises(ApprovalError) as exc:
        gw.approvals.approve(aid, Principal.of("alice", roles=["support-lead"]))
    assert exc.value.code == "SELF_APPROVAL"
    gw.approvals.approve(aid, LEAD)

    # arguments must match what was approved
    tampered = call(gw, "create_refund_request", {**REFUND, "amount": 999, APPROVAL_ARG: aid})
    assert tampered.content["error"] == "APPROVAL_MISMATCH"

    done = call(gw, "create_refund_request", {**REFUND, APPROVAL_ARG: aid})
    assert done.content == {"ok": True, "tool": "create_refund_request"}
    assert up.calls[-1] == ("create_refund_request", {**REFUND, "dry_run": False})

    # single use
    again = call(gw, "create_refund_request", {**REFUND, APPROVAL_ARG: aid})
    assert again.content["error"] == "APPROVAL_NOT_USABLE"
    executed = [r for r in gw.audit.read() if r["event"] == "tool_executed"]
    assert executed[-1]["approved_by"] == "bob"


def test_rejected_approval_cannot_execute():
    gw, _ = make_gateway("L2")
    aid = call(gw, "create_refund_request", REFUND).content["approval_id"]
    gw.approvals.reject(aid, LEAD, note="duplicate")
    assert call(gw, "create_refund_request", {**REFUND, APPROVAL_ARG: aid}).content["error"] == "APPROVAL_NOT_USABLE"


def test_explicit_dry_run_needs_no_approval():
    gw, up = make_gateway("L2")
    res = call(gw, "create_refund_request", {**REFUND, "dry_run": True})
    assert res.content["dry_run"] is True and gw.approvals.list() == []


def test_approval_expires():
    t = [1_000_000.0]
    gw, _ = make_gateway("L2", clock=lambda: t[0])
    aid = call(gw, "create_refund_request", REFUND).content["approval_id"]
    gw.approvals.approve(aid, LEAD, now=t[0])
    t[0] += 7200
    assert call(gw, "create_refund_request", {**REFUND, APPROVAL_ARG: aid}).content["error"] == "APPROVAL_EXPIRED"


# --------------------------------------------------------------------------- bounded autonomy (L3)

def test_l3_within_limits_then_escalates():
    gw, up = make_gateway("L3", max_steps_per_run=1000)
    rule = gw.policy.rule("update_ticket_status")
    assert rule.decision == "allow_within_limits"
    rule.limits["max_per_hour"] = 2
    args = {"ticket_id": "T-1", "status": "resolved", "note": "done"}
    assert call(gw, "update_ticket_status", args).content["ok"]
    assert call(gw, "update_ticket_status", args).content["ok"]
    third = call(gw, "update_ticket_status", args)
    assert third.content["status"] == "approval_required"  # over the limit: a human decides
    # T3 refunds still need a human at L3
    assert call(gw, "create_refund_request", REFUND).content["status"] == "approval_required"


def test_manual_demotion_from_l3_to_l2_requires_approval():
    gw, _ = make_gateway("L3")
    gw.state.demote(gw.agent_id, AutonomyLevel.L2, by="ops", reason="incident")
    res = call(gw, "update_ticket_status", {"ticket_id": "T-1", "status": "resolved", "note": "x"})
    assert res.content["status"] == "approval_required"


# --------------------------------------------------------------------------- kill switch, discovery, state

def test_kill_switch_blocks_and_hides_everything():
    gw, up = make_gateway()
    gw.state.kill(gw.agent_id, by="ops", reason="runaway costs")
    assert call(gw, "lookup_order", {"order_id": "O"}).content["error"] == "KILL_SWITCH"
    assert run(gw.visible_tools(ALICE)) == []
    gw.state.revive(gw.agent_id)
    assert not call(gw, "lookup_order", {"order_id": "O"}).is_error


def test_visible_tools_filters_and_extends_schema():
    gw, _ = make_gateway("L2")
    names = {t.name: t for t in run(gw.visible_tools(ALICE))}
    assert "export_everything" not in names  # served, not in policy
    assert "delete_customer_account" not in names  # T4
    assert APPROVAL_ARG in names["create_refund_request"].input_schema["properties"]
    assert APPROVAL_ARG not in names["lookup_order"].input_schema["properties"]
    reader = Principal.of("carol", ["orders:read"])
    assert {t.name for t in run(gw.visible_tools(reader))} == {"lookup_order"}


def test_durable_state_is_shared_across_processes(tmp_path):
    path = tmp_path / "state.json"
    gw, _ = make_gateway(state=GatewayState(DurableStore(path)))
    operator = GatewayState(DurableStore(path))  # e.g. `aof gateway kill` in another shell
    operator.kill(gw.agent_id, by="ops", reason="test")
    assert call(gw, "lookup_order", {"order_id": "O"}).content["error"] == "KILL_SWITCH"


def test_audit_tamper_is_detected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.append("tool_executed", n=i)
    assert verify(log.read()) == (True, None)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["n"] = 99
    lines[1] = json.dumps(rec)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    assert verify(log.read()) == (False, 2)


def test_upstream_failure_is_contained():
    gw, up = make_gateway()

    async def boom(name, args):
        raise RuntimeError("connection reset")

    up.call_tool = boom
    res = call(gw, "lookup_order", {"order_id": "O"})
    assert res.is_error and res.content["error"] == "UPSTREAM_ERROR"
    assert "connection reset" not in json.dumps(res.content)  # internal detail stays in the audit log
