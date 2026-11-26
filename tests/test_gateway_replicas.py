"""Multi-replica state.

The store contract runs against every backend. Replica tests run two Gateway instances
that share one Redis (fakeredis: two clients on one in-process server), and thread
races check that the atomic steps hold under real concurrency.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

fakeredis = pytest.importorskip("fakeredis")

from aof.enums import AutonomyLevel  # noqa: E402
from aof.gateway import APPROVAL_ARG, ApprovalError, ApprovalService, AuditLog, Gateway, Principal  # noqa: E402
from aof.gateway.state import Abort, DurableStore, GatewayState, RedisStore, open_store  # noqa: E402

from .test_gateway_core import ALICE, LEAD, REFUND, FakeUpstream, make_policy  # noqa: E402


def redis_pair():
    server = fakeredis.FakeServer()
    return (RedisStore(fakeredis.FakeRedis(server=server)), RedisStore(fakeredis.FakeRedis(server=server)))


@pytest.fixture(params=["memory", "file", "redis"])
def store(request, tmp_path):
    if request.param == "memory":
        return DurableStore()
    if request.param == "file":
        return DurableStore(tmp_path / "state.json")
    return redis_pair()[0]


# --------------------------------------------------------------------------- store contract

def test_documents(store):
    assert store.get("ns", "a") is None and store.all("ns") == {}
    store.put("ns", "a", {"x": 1})
    assert store.get("ns", "a") == {"x": 1}
    assert store.put_if_absent("ns", "a", {"x": 2}) is False and store.get("ns", "a") == {"x": 1}
    assert store.put_if_absent("ns", "b", {"x": 3}) is True
    assert store.all("ns") == {"a": {"x": 1}, "b": {"x": 3}}
    assert store.update("ns", "a", lambda d: {**d, "x": d["x"] + 1}) == {"x": 2}
    with pytest.raises(Abort):
        store.update("ns", "a", lambda d: (_ for _ in ()).throw(Abort()))
    assert store.get("ns", "a") == {"x": 2}  # an aborted update leaves it unchanged
    assert store.delete("ns", "a") is True and store.delete("ns", "a") is False
    assert store.update("ns", "b", lambda d: None) is None and store.get("ns", "b") is None


def test_counters_and_windows(store):
    assert store.counter("c") == 0
    assert store.incr("c", 1, 60) == 1 and store.incr("c", 0.25, 60) == pytest.approx(1.25)
    assert store.counter("c") == pytest.approx(1.25)
    now = 1000.0
    assert store.window_acquire("w", now, 60, 2) == (True, 1)
    store.window_add("w", now + 1, 60)
    assert store.window_acquire("w", now + 2, 60, 2) == (False, 2)
    assert store.window_count("w", now + 60.5, 60) == 1  # the first event left the window
    assert store.window_acquire("w", now + 61.5, 60, 2)[0] is True
    store.window_reset("w")
    assert store.window_count("w", now + 62, 60) == 0


def test_gateway_state_on_every_backend(store):
    state = GatewayState(store)
    state.kill("agent:x", by="ops", reason="r")
    assert state.killed("agent:x")["by"] == "ops"
    assert state.revive("agent:x") and not state.killed("agent:x")
    run = state.run("r1")
    assert run.reserve("delegations", 1) and not run.reserve("delegations", 1) and run.delegations == 1


def test_open_store():
    assert isinstance(open_store(None), DurableStore)
    with pytest.raises(ValueError):
        open_store("http://redis:6379")


# --------------------------------------------------------------------------- races

def _race(n, fn):
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker(i):
        barrier.wait()
        r = fn(i)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_window_acquire_never_oversells_under_contention():
    a, b = redis_pair()
    got = _race(40, lambda i: (a if i % 2 else b).window_acquire("rate", 1000.0, 60, 10)[0])
    assert got.count(True) == 10


def test_run_budget_reservation_never_oversells():
    a, b = redis_pair()
    runs = [GatewayState(a).run("r"), GatewayState(b).run("r")]
    got = _race(30, lambda i: runs[i % 2].reserve("model_calls", 7))
    assert got.count(True) == 7 and runs[0].model_calls == 7


def test_an_approval_is_consumed_exactly_once_across_replicas():
    a, b = redis_pair()
    svc_a, svc_b = ApprovalService(a), ApprovalService(b)
    apr = svc_a.request(agent_id="agent:x", tool="t", principal=ALICE, run_id="r", args={"n": 1},
                        preview=None, approver_role=None)
    svc_b.approve(apr.id, LEAD)

    def consume(i):
        try:
            (svc_a if i % 2 else svc_b).consume(apr.id, agent_id="agent:x", tool="t", principal=ALICE, args={"n": 1})
            return True
        except ApprovalError:
            return False

    assert _race(20, consume).count(True) == 1


def test_demotion_moves_one_level_when_replicas_race():
    a, b = redis_pair()
    states = [GatewayState(a), GatewayState(b)]
    got = _race(10, lambda i: states[i % 2].demote_from("agent:x", AutonomyLevel.L3, AutonomyLevel.L3,
                                                        AutonomyLevel.L2, by="gateway", reason="slo"))
    assert got.count(True) == 1 and states[0].demoted_level("agent:x") == AutonomyLevel.L2


# --------------------------------------------------------------------------- two gateways, one Redis

def replicas(level="L2", **budgets):
    a, b = redis_pair()
    policy = make_policy(level, **budgets)
    up = FakeUpstream(policy)
    return Gateway(policy, up, state=GatewayState(a)), Gateway(policy, up, state=GatewayState(b)), up


def call(gw, tool, args=None, who=ALICE, run_id="run-1"):
    return asyncio.run(gw.call_tool(who, tool, args or {"order_id": "ORD-1"}, run_id=run_id))


def test_kill_switch_on_one_replica_stops_the_other():
    gw_a, gw_b, _ = replicas()
    gw_a.state.kill(gw_a.agent_id, by="ops", reason="drill")
    assert call(gw_b, "lookup_order").content["error"] == "KILL_SWITCH"


def test_step_budget_is_shared():
    gw_a, gw_b, _ = replicas(max_steps_per_run=4)
    codes = [call(g, "lookup_order").content.get("error") for g in (gw_a, gw_b, gw_a, gw_b, gw_a)]
    assert codes == [None, None, None, None, "STEP_BUDGET"]


def test_cost_budget_is_shared():
    gw_a, gw_b, _ = replicas(max_cost_usd_per_run=0.10)
    gw_a.record_model_cost("run-1", 0.10)
    assert call(gw_b, "lookup_order").content["error"] == "COST_BUDGET"


def test_approval_requested_on_one_replica_used_on_the_other_once():
    gw_a, gw_b, up = replicas()
    pending = call(gw_a, "create_refund_request", REFUND)
    aid = pending.content["approval_id"]
    gw_b.approvals.approve(aid, LEAD)
    done = call(gw_b, "create_refund_request", {**REFUND, APPROVAL_ARG: aid})
    assert done.content == {"ok": True, "tool": "create_refund_request"}
    replay = call(gw_a, "create_refund_request", {**REFUND, APPROVAL_ARG: aid})
    assert replay.content["error"] == "APPROVAL_NOT_USABLE"
    assert [c[0] for c in up.calls].count("create_refund_request") == 2  # one preview, one execution


def test_llm_budget_and_rate_limit_are_shared():
    from aof.gateway.llm import LlmProxy

    from .test_gateway_llm import BODY, FakeProvider

    gw_a, gw_b, _ = replicas()
    pa, pb = LlmProxy(gw_a, FakeProvider()), LlmProxy(gw_b, FakeProvider())
    pa.rule.max_model_calls_per_run = 3  # one LlmRule object: both replicas load the same policy
    statuses = [asyncio.run(p.handle(ALICE, BODY, run_id="r")).status for p in (pa, pb, pa, pb)]
    assert statuses == [200, 200, 200, 403]
    pa.rule.max_model_calls_per_run, pa.rule.rate_limit.calls = 50, 2
    statuses = [asyncio.run(p.handle(ALICE, BODY, run_id=f"x{i}")).status for i, p in enumerate((pa, pb, pa))]
    assert statuses[-1] == 429


def test_a2a_task_owner_is_shared():
    from aof.gateway.a2a_proxy import A2aProxy, Call

    from .test_gateway_a2a import FakeTransport, a2a_policy, err, rpc

    a, b = redis_pair()
    policy = a2a_policy()
    up = FakeUpstream(policy)
    env = {"BILLING_TOKEN": "t"}
    pa = A2aProxy(Gateway(policy, up, state=GatewayState(a)), FakeTransport(), env=env)
    pb = A2aProxy(Gateway(policy, up, state=GatewayState(b)), FakeTransport(), env=env)
    asyncio.run(pa.delegate("billing", Call(ALICE, rpc(), run_id="r")))  # task-1 on replica A
    follow = asyncio.run(pb.delegate("billing", Call(ALICE, rpc("GetTask", {"id": "task-1"}), run_id="r")))
    assert err(follow) is None
    pb.gw.auto_demote = False
    other = asyncio.run(pb.delegate("billing", Call(Principal.of("dave"), rpc("GetTask", {"id": "task-1"}),
                                                    run_id="r")))
    assert err(other) == "TASK_NOT_OWNED"


# --------------------------------------------------------------------------- audit chains per replica

def test_audit_verify_checks_every_replica_chain(tmp_path, capsys):
    from aof.cli import main

    for replica in ("gw-a", "gw-b"):
        log = AuditLog(tmp_path / f"audit-{replica}.jsonl", replica=replica)
        log.append("gateway_started")
        log.append("tool_executed", tool="lookup_order")
    assert main(["gateway", "audit", "--verify", "--state-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "audit-gw-a.jsonl: chain OK (2 records)" in out and "audit-gw-b.jsonl: chain OK (2 records)" in out
    assert AuditLog(tmp_path / "audit-gw-a.jsonl").read()[0]["replica"] == "gw-a"

    path = tmp_path / "audit-gw-b.jsonl"
    lines = path.read_text().splitlines()
    path.write_text(lines[0].replace("gateway_started", "gateway_stopped") + "\n" + lines[1] + "\n")
    assert main(["gateway", "audit", "--verify", "--state-dir", str(tmp_path)]) == 1
    assert "audit-gw-b.jsonl: chain BROKEN at seq 1" in capsys.readouterr().out
