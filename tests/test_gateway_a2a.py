"""A2A path.

Unit tests drive A2aProxy with a fake transport. The end-to-end test runs real a2a-sdk
agents in process: an a2a-sdk client -> gateway routes -> HttpTransport -> an a2a-sdk
server. No network.
"""

from __future__ import annotations

import asyncio

import pytest

from aof.enums import ApprovalMode, AutonomyLevel
from aof.gateway import Gateway, Principal
from aof.gateway.a2a_proxy import A2aProxy, A2aReply, Call, canonical_method
from aof.gateway.compiled import CompiledPolicy
from aof.loader import load_project
from aof.models.project import A2aConfig, A2aPeer, Autonomy
from aof.platform import load_platform
from aof.policy import check_policy, compile_policy

from .conftest import EXAMPLE, codes
from .test_gateway_core import ALICE, FakeUpstream

PEER_CARD_URL = "https://billing.test/.well-known/agent-card.json"
UPSTREAM = "https://refunds-agent.test/"
DAVE = Principal.of("dave")


def a2a_project(level="L4", **a2a_kw):
    lp = load_project(EXAMPLE)
    lp.project.hosts_agent = True
    lp.project.autonomy = Autonomy(current=AutonomyLevel(level), target=AutonomyLevel.L4)
    lp.manifest.tool("update_ticket_status").approval.mode = ApprovalMode.WITHIN_LIMITS
    a2a_kw.setdefault("peers", [A2aPeer(name="billing", card_url=PEER_CARD_URL, skills=["invoice_lookup"],
                                        credential_env="BILLING_TOKEN")])
    a2a_kw.setdefault("allowed_callers", ["agent:orchestrator"])
    lp.project.a2a = A2aConfig(**a2a_kw)
    return lp


def a2a_policy(level="L4", **a2a_kw) -> CompiledPolicy:
    lp = a2a_project(level, **a2a_kw)
    return CompiledPolicy.model_validate(compile_policy(lp.project, lp.manifest, load_platform()))


def card(skills=("invoice_lookup",), url="https://billing.test/"):
    return {"name": "billing", "description": "billing agent", "version": "1.0.0",
            "supportedInterfaces": [{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "skills": [{"id": s, "name": s, "description": s} for s in skills]}


class FakeTransport:
    def __init__(self, peer_card=None):
        self.peer_card = peer_card or card()
        self.posts: list[tuple[str, dict, dict]] = []
        self.n = 0

    async def get_json(self, url):
        if url == PEER_CARD_URL:
            return self.peer_card
        return card(("refund_status",), url="https://refunds-agent.internal/")

    async def post(self, url, body, headers, stream):
        self.posts.append((url, body, headers))
        self.n += 1
        method = canonical_method(body["method"])
        if method in ("SendMessage", "message/send"):
            return A2aReply(200, {"jsonrpc": "2.0", "id": body.get("id"),
                                  "result": {"task": {"id": f"task-{self.n}", "contextId": "c1",
                                                      "status": {"state": "TASK_STATE_COMPLETED"}}}})
        if method == "ListTasks":
            return A2aReply(200, {"jsonrpc": "2.0", "id": body.get("id"),
                                  "result": {"tasks": [{"id": "task-1"}, {"id": "someone-elses"}]}})
        if method == "SendStreamingMessage":
            async def events():
                yield {"jsonrpc": "2.0", "id": body.get("id"), "result": {"task": {"id": "task-s"}}}
                yield {"jsonrpc": "2.0", "id": body.get("id"),
                       "result": {"statusUpdate": {"taskId": "task-s", "status": {"state": "TASK_STATE_COMPLETED"}}}}
            return A2aReply(200, events=events())
        return A2aReply(200, {"jsonrpc": "2.0", "id": body.get("id"), "result": {"task": {"id": body["params"]["id"]}}})


def make(level="L4", transport=None, env=None, **a2a_kw):
    policy = a2a_policy(level, **a2a_kw)
    gw = Gateway(policy, FakeUpstream(policy))
    proxy = A2aProxy(gw, transport or FakeTransport(), upstream_url=UPSTREAM,
                     public_url="https://gw.test/a2a", env={"BILLING_TOKEN": "peer-secret"} if env is None else env)
    return proxy, gw


def rpc(method="SendMessage", params=None, rid=1):
    if params is None:
        params = {"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "invoice for ORD-1?"}]}}
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def out(proxy, body=None, who=ALICE, peer="billing", run_id="run-1", depth=0):
    return asyncio.run(proxy.delegate(peer, Call(who, body or rpc(), run_id=run_id, depth=depth)))


def inb(proxy, body=None, caller="agent:orchestrator", who=ALICE, run_id="r", depth=1):
    return asyncio.run(proxy.receive(Call(who, body or rpc(), run_id=run_id, depth=depth, caller=caller)))


def err(reply):
    return (reply.body.get("error") or {}).get("data", {}).get("error")


# --------------------------------------------------------------------------- contract checks

def test_policy_requires_l4_target(platform):
    lp = a2a_project()
    lp.project.autonomy = Autonomy(current=AutonomyLevel.L2, target=AutonomyLevel.L3)
    assert "AOF-P050" in codes(check_policy(lp.project, lp.manifest, platform))


def test_policy_inbound_needs_hosts_agent_and_https_unique_peers(platform):
    peer = A2aPeer(name="billing", card_url="http://billing.test/card.json", skills=["x"])
    lp = a2a_project(peers=[peer, peer])
    lp.project.hosts_agent = False
    found = codes(check_policy(lp.project, lp.manifest, platform))
    assert {"AOF-P051", "AOF-P052", "AOF-P053"} <= found


def test_compiled_section():
    rule = a2a_policy().a2a
    assert rule.enabled and rule.inbound and rule.peer("billing").skills == ["invoice_lookup"]
    assert not a2a_policy("L3").a2a.enabled  # a2a follows the current level, not the target


# --------------------------------------------------------------------------- outbound

def test_delegation_forwarded_with_hop_and_credential():
    proxy, gw = make()
    res = out(proxy, depth=1)
    assert res.body["result"]["task"]["id"] == "task-1"
    url, body, headers = proxy.transport.posts[-1]
    assert url == "https://billing.test/" and body == rpc()  # payload passed through unchanged
    assert headers["x-aof-delegation-depth"] == "2" and headers["authorization"] == "Bearer peer-secret"
    assert headers["x-aof-on-behalf-of"] == "alice"
    rec = gw.audit.read()[-1]
    assert rec["event"] == "a2a_call" and rec["task_ids"] == ["task-1"] and "invoice" not in str(rec)
    assert gw.state.run("run-1", gw.clock()).delegations == 1


def test_v03_method_names_accepted():
    proxy, _ = make()
    assert out(proxy, rpc("message/send")).body["result"]["task"]["id"] == "task-1"


@pytest.mark.parametrize("kw, code", [
    ({"peer": "payroll"}, "PEER_NOT_ALLOWED"),
    ({"body": rpc("CreateTaskPushNotificationConfig", {"taskId": "t"})}, "PUSH_NOT_ALLOWED"),
    ({"body": rpc("tasks/pushNotificationConfig/set", {"taskId": "t"})}, "PUSH_NOT_ALLOWED"),
    ({"body": rpc("DeleteEverything", {})}, "METHOD_NOT_ALLOWED"),
    ({"body": {"id": 1, "method": "SendMessage"}}, "INVALID_REQUEST"),
    ({"depth": 10}, "DELEGATION_DEPTH"),  # platform max 10; the gateway adds this hop
])
def test_outbound_denials(kw, code):
    proxy, gw = make()
    gw.auto_demote = False
    res = out(proxy, **kw)
    assert err(res) == code and "[AOF:" in res.body["error"]["message"]
    assert proxy.transport.posts == []
    assert gw.audit.read()[-1]["event"] == "a2a_denied"


def test_not_enabled_below_l4_or_after_demotion():
    proxy, _ = make("L3")
    assert err(out(proxy)) == "A2A_NOT_ENABLED"
    proxy, gw = make()
    gw.state.demote(gw.agent_id, AutonomyLevel.L3, by="ops", reason="incident")
    assert err(out(proxy)) == "A2A_NOT_ENABLED"


def test_kill_switch():
    proxy, gw = make()
    gw.state.kill(gw.agent_id, by="ops", reason="drill")
    assert err(out(proxy)) == "KILL_SWITCH" and err(inb(proxy)) == "KILL_SWITCH"


def test_unknown_peer_is_a_violation_and_demotes():
    proxy, gw = make()
    out(proxy, peer="payroll")
    assert gw.state.demoted_level(gw.agent_id) == AutonomyLevel.L3


def test_delegation_budget_counts_new_tasks_only():
    proxy, _ = make(max_delegations_per_run=2)
    assert [err(out(proxy)) for _ in range(3)] == [None, None, "DELEGATION_BUDGET"]
    # follow-ups on a task the run started are not new delegations
    assert err(out(proxy, rpc("GetTask", {"id": "task-1"}))) is None
    assert err(out(proxy, run_id="run-2")) is None


def test_cost_budget_shared_with_other_paths():
    proxy, gw = make()
    gw.record_model_cost("run-1", 10.0)
    assert err(out(proxy)) == "COST_BUDGET"


def test_task_ownership():
    proxy, gw = make()
    gw.auto_demote = False
    out(proxy)  # alice starts task-1
    assert err(out(proxy, rpc("GetTask", {"id": "task-1"}))) is None
    assert err(out(proxy, rpc("CancelTask", {"id": "task-1"}), who=DAVE)) == "TASK_NOT_OWNED"
    assert err(out(proxy, rpc("tasks/get", {"id": "unknown"}))) == "TASK_NOT_OWNED"
    follow_up = {"message": {"messageId": "m2", "taskId": "task-1", "role": "ROLE_USER", "parts": []}}
    assert err(out(proxy, rpc("SendMessage", follow_up), who=DAVE)) == "TASK_NOT_OWNED"
    listed = out(proxy, rpc("ListTasks", {}))
    assert [t["id"] for t in listed.body["result"]["tasks"]] == ["task-1"]


def test_peer_card_must_keep_contracted_skills():
    proxy, _ = make(transport=FakeTransport(card(("something_else",))))
    assert err(out(proxy)) == "PEER_SKILL_MISSING"
    proxy, _ = make(transport=FakeTransport(card(url="http://billing.test/")))
    assert err(out(proxy)) == "PEER_CARD_INVALID"


def test_missing_peer_credential():
    proxy, _ = make(env={})
    assert err(out(proxy)) == "PEER_CREDENTIAL_MISSING"


def test_streaming_relayed_and_tasks_claimed():
    proxy, gw = make()
    res = out(proxy, rpc("SendStreamingMessage"))

    async def drain():
        return [e async for e in res.events]

    events = asyncio.run(drain())
    assert len(events) == 2 and gw.audit.read()[-1]["task_ids"] == ["task-s"]
    assert err(out(proxy, rpc("SubscribeToTask", {"id": "task-s"}))) is None


# --------------------------------------------------------------------------- inbound

def test_inbound_allowed_caller_forwarded_to_app():
    proxy, gw = make()
    res = inb(proxy)
    assert res.body["result"]["task"]["id"] == "task-1"
    url, _, headers = proxy.transport.posts[-1]
    assert url == UPSTREAM and headers["x-aof-caller"] == "agent:orchestrator"
    assert headers["x-aof-delegation-depth"] == "1"
    assert gw.audit.read()[-1]["direction"] == "inbound"


def test_inbound_denials():
    proxy, gw = make()
    assert err(inb(proxy, caller="agent:stranger")) == "CALLER_NOT_ALLOWED"
    assert err(inb(proxy, depth=11)) == "DELEGATION_DEPTH"
    inb(proxy)
    assert err(inb(proxy, rpc("GetTask", {"id": "task-1"}), caller="agent:orchestrator", who=DAVE)) == "TASK_NOT_OWNED"
    proxy, _ = make()
    proxy.upstream_url = None
    assert err(inb(proxy)) == "A2A_NOT_ENABLED"


def test_inbound_needs_hosts_agent():
    policy = a2a_policy()
    policy.a2a.inbound = False  # what compile_policy writes when hosts_agent is false
    proxy = A2aProxy(Gateway(policy, FakeUpstream(policy)), FakeTransport(), upstream_url=UPSTREAM)
    assert err(inb(proxy)) == "A2A_NOT_ENABLED"


def test_own_card_points_at_gateway():
    proxy, _ = make()
    c = asyncio.run(proxy.own_card())
    assert c["supportedInterfaces"][0]["url"] == "https://gw.test/a2a"


# --------------------------------------------------------------------------- end to end with a2a-sdk

a2a = pytest.importorskip("a2a")


def _sdk_agent_app(name: str, skill: str, url: str):
    from a2a.helpers import new_task_from_user_message, new_text_part
    from a2a.server.agent_execution import AgentExecutor
    from a2a.server.request_handlers import DefaultRequestHandlerV2
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
    from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
    from a2a.types import a2a_pb2 as pb
    from starlette.applications import Starlette

    class Echo(AgentExecutor):
        async def execute(self, context, event_queue):
            task = context.current_task or new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)
            updater = TaskUpdater(event_queue, task.id, task.context_id)
            await updater.add_artifact([new_text_part(f"{name}: {context.get_user_input()}")])
            await updater.complete()

        async def cancel(self, context, event_queue):
            raise NotImplementedError

    card = pb.AgentCard(
        name=name, description=f"{name} agent", version="1.0.0",
        supported_interfaces=[pb.AgentInterface(url=url, protocol_binding="JSONRPC", protocol_version="1.0")],
        capabilities=pb.AgentCapabilities(streaming=True),
        default_input_modes=["text/plain"], default_output_modes=["text/plain"],
        skills=[pb.AgentSkill(id=skill, name=skill, description=skill, tags=["test"])],
    )
    handler = DefaultRequestHandlerV2(agent_executor=Echo(), task_store=InMemoryTaskStore(), agent_card=card)
    app = Starlette(routes=[*create_agent_card_routes(card), *create_jsonrpc_routes(handler, "/")])
    return app, card


class _Tokens:
    async def verify_token(self, token):
        from mcp.server.auth.provider import AccessToken

        who = {"tok-alice": ("refunds-ui", "alice"), "tok-orch": ("agent:orchestrator", "alice")}.get(token)
        if who is None:
            return None
        return AccessToken(token=token, client_id=who[0], scopes=[], subject=who[1])


async def _e2e():
    import httpx2
    from a2a.client import ClientConfig, create_client
    from a2a.helpers import get_artifact_text, new_text_message
    from a2a.types import a2a_pb2 as pb
    from starlette.applications import Starlette

    from aof.gateway.a2a_proxy import HttpTransport, a2a_routes

    billing_app, billing_card = _sdk_agent_app("billing", "invoice_lookup", "https://billing.test/")
    refunds_app, _ = _sdk_agent_app("refunds", "refund_status", UPSTREAM)

    class Router(httpx2.AsyncBaseTransport):  # the gateway's outbound network: two agents
        def __init__(self):
            self.apps = {"billing.test": httpx2.ASGITransport(app=billing_app),
                         "refunds-agent.test": httpx2.ASGITransport(app=refunds_app)}

        async def handle_async_request(self, request):
            return await self.apps[request.url.host].handle_async_request(request)

    policy = a2a_policy()
    gw = Gateway(policy, FakeUpstream(policy))
    proxy = A2aProxy(gw, HttpTransport(httpx2.AsyncClient(transport=Router())), upstream_url=UPSTREAM,
                     public_url="http://gw/a2a", env={"BILLING_TOKEN": "peer-secret"})
    gateway = Starlette(routes=a2a_routes(proxy, _Tokens()))

    async def client_for(card, token):
        http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gateway),
                                  headers={"authorization": f"Bearer {token}", "x-aof-run-id": "e2e"})
        return await create_client(card, client_config=ClientConfig(streaming=False, httpx_client=http))

    # outbound: the refunds agent delegates to billing through the gateway
    via_gateway = pb.AgentCard()
    via_gateway.CopyFrom(billing_card)
    via_gateway.supported_interfaces[0].url = "http://gw/a2a/peers/billing"
    client = await client_for(via_gateway, "tok-alice")
    replies = [r async for r in client.send_message(pb.SendMessageRequest(message=new_text_message("ORD-1", role=pb.Role.ROLE_USER)))]
    task = replies[-1].task
    out_text = get_artifact_text(task.artifacts[0])

    # inbound: the orchestrator calls the refunds agent through the gateway
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gateway)) as http:
        served_card = (await http.get("http://gw/.well-known/agent-card.json")).json()
    inbound_card = pb.AgentCard()
    inbound_card.CopyFrom(billing_card)
    inbound_card.supported_interfaces[0].url = served_card["supportedInterfaces"][0]["url"]
    orch = await client_for(inbound_card, "tok-orch")
    in_task = [r async for r in orch.send_message(pb.SendMessageRequest(message=new_text_message("status?", role=pb.Role.ROLE_USER)))][-1].task
    in_text = get_artifact_text(in_task.artifacts[0])

    # an agent that is not allow-listed gets a JSON-RPC error
    stranger = await client_for(inbound_card, "tok-alice")  # client_id refunds-ui is not an allowed caller
    with pytest.raises(Exception) as denied:
        [r async for r in stranger.send_message(pb.SendMessageRequest(message=new_text_message("hi", role=pb.Role.ROLE_USER)))]
    return out_text, in_text, served_card, denied.value, gw


def test_end_to_end_with_a2a_sdk():
    out_text, in_text, served_card, denied, gw = asyncio.run(_e2e())
    assert out_text == "billing: ORD-1"
    assert in_text == "refunds: status?"
    assert served_card["supportedInterfaces"][0]["url"] == "http://gw/a2a"
    assert "CALLER_NOT_ALLOWED" in str(denied)
    events = [r["event"] for r in gw.audit.read()]
    assert events.count("a2a_call") == 2 and events[-1] == "a2a_denied"
