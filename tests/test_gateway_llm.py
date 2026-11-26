"""LLM proxy path.

End-to-end tests use the real Anthropic SDK on both sides, in process:
  agent's AsyncAnthropic -> gateway /v1/messages -> AnthropicProvider (AsyncAnthropic) -> fake Messages API
No network, no API key, no cost.
"""

from __future__ import annotations

import asyncio
import json

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse, StreamingResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from aof.gateway import Gateway, Principal  # noqa: E402
from aof.gateway.llm import AnthropicProvider, LlmProxy, ProviderError, error_body, llm_route  # noqa: E402

from .test_gateway_core import ALICE, FakeUpstream, make_policy  # noqa: E402

USAGE = {"input_tokens": 1000, "output_tokens": 500, "cache_read_input_tokens": 2000,
         "cache_creation_input_tokens": 0}
# opus-5-5: 1000*4 + 2000*0.20 + 500*20 = 14400 per 1M -> $0.0144
EXPECTED_COST = 0.0144


def _message(model="claude-opus-5-5"):
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": "hello"}], "stop_reason": "end_turn",
            "stop_sequence": None, "usage": dict(USAGE)}


def _events(model="claude-opus-5-5"):
    start = _message(model)
    start["content"], start["stop_reason"] = [], None
    start["usage"] = {**USAGE, "output_tokens": 1}
    return [
        {"type": "message_start", "message": start},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": 500}},
        {"type": "message_stop"},
    ]


class FakeProvider:
    def __init__(self):
        self.calls: list[tuple[dict, list]] = []

    async def create(self, params, betas):
        self.calls.append((params, betas))
        return _message(params["model"])

    async def stream(self, params, betas):
        self.calls.append((params, betas))
        for e in _events(params["model"]):
            yield e


def make_proxy(level="L2", provider=None, **budgets):
    policy = make_policy(level, **budgets)
    gw = Gateway(policy, FakeUpstream(policy))
    return LlmProxy(gw, provider or FakeProvider()), gw


def handle(proxy, body, who=ALICE, run_id="run-1", **kw):
    return asyncio.run(proxy.handle(who, body, run_id=run_id, **kw))


BODY = {"model": "claude-opus-5-5", "max_tokens": 1024, "messages": [{"role": "user", "content": "hi"}]}


# --------------------------------------------------------------------------- policy checks

def test_allowed_call_is_forwarded_charged_and_audited():
    proxy, gw = make_proxy()
    res = handle(proxy, BODY)
    assert res.status == 200 and res.body["content"][0]["text"] == "hello"
    run = gw.state.run("run-1", gw.clock())
    assert run.model_calls == 1 and run.cost_usd == pytest.approx(EXPECTED_COST)
    rec = gw.audit.read()[-1]
    assert rec["event"] == "llm_call" and rec["cost_usd"] == pytest.approx(EXPECTED_COST)
    assert rec["input_tokens"] == 1000 and "hello" not in json.dumps(rec)  # no content in the audit log


def test_default_model_alias():
    proxy, _ = make_proxy()
    handle(proxy, {**BODY, "model": "aof:default"})
    assert proxy.provider.calls[-1][0]["model"] == "claude-opus-5-5"


@pytest.mark.parametrize("change, status, code", [
    ({"model": "claude-sonnet-5-5"}, 403, "MODEL_NOT_ALLOWED"),
    ({"max_tokens": 64000}, 400, "MAX_TOKENS_CAP"),
    ({"max_tokens": None}, 400, "MAX_TOKENS_REQUIRED"),
    ({"fallbacks": "default"}, 403, "FALLBACK_NOT_ALLOWED"),
    ({"fallbacks": [{"model": "claude-opus-4-8"}]}, 403, "FALLBACK_NOT_ALLOWED"),
    ({"mcp_servers": [{"type": "url", "url": "https://x", "name": "x"}]}, 403, "MCP_CONNECTOR_NOT_ALLOWED"),
    ({"tools": [{"name": "export_everything", "input_schema": {"type": "object"}}]}, 403, "TOOL_NOT_ALLOWED"),
    ({"tools": [{"name": "delete_customer_account", "input_schema": {"type": "object"}}]}, 403, "TOOL_NOT_ALLOWED"),
    ({"tools": [{"type": "web_search_20260209", "name": "web_search"}]}, 403, "SERVER_TOOL_NOT_ALLOWED"),
])
def test_request_checks(change, status, code):
    proxy, gw = make_proxy()
    gw.auto_demote = False
    res = handle(proxy, {**BODY, **change})
    assert res.status == status and f"[AOF:{code}]" in res.body["error"]["message"]
    assert proxy.provider.calls == []
    assert gw.audit.read()[-1]["event"] == "llm_denied"


def test_declared_policy_tools_are_allowed():
    proxy, _ = make_proxy()
    tools = [{"name": "lookup_order", "input_schema": {"type": "object"}},
             {"name": "create_refund_request", "input_schema": {"type": "object"}}]
    assert handle(proxy, {**BODY, "tools": tools}).status == 200


def test_write_tools_not_declarable_at_read_only_level():
    proxy, gw = make_proxy("L1")
    gw.auto_demote = False
    res = handle(proxy, {**BODY, "tools": [{"name": "create_refund_request", "input_schema": {"type": "object"}}]})
    assert res.status == 403 and "TOOL_NOT_ALLOWED" in res.body["error"]["message"]


def test_beta_allowlist():
    proxy, _ = make_proxy()
    assert handle(proxy, BODY, betas=["server-side-fallback-2026-07-01"]).status == 403
    proxy.rule.allowed_betas.append("server-side-fallback-2026-07-01")
    assert handle(proxy, BODY, betas=["server-side-fallback-2026-07-01"]).status == 200


def test_model_violation_demotes_agent():
    proxy, gw = make_proxy("L2")
    handle(proxy, {**BODY, "model": "claude-fable-5-2"})
    assert gw.state.demoted_level(gw.agent_id).value == "L1"


def test_kill_switch_blocks_model_calls():
    proxy, gw = make_proxy()
    gw.state.kill(gw.agent_id, by="ops", reason="drill")
    assert "KILL_SWITCH" in handle(proxy, BODY).body["error"]["message"]


def test_model_call_budget():
    proxy, gw = make_proxy()
    proxy.rule.max_model_calls_per_run = 2
    assert [handle(proxy, BODY).status for _ in range(3)] == [200, 200, 403]
    assert handle(proxy, BODY, run_id="run-2").status == 200


def test_cost_budget_shared_with_tool_path():
    proxy, gw = make_proxy(max_cost_usd_per_run=0.02)
    assert handle(proxy, BODY).status == 200  # $0.0144
    assert handle(proxy, BODY).status == 200  # $0.0288: one call may overshoot
    res = handle(proxy, BODY)
    assert res.status == 403 and "COST_BUDGET" in res.body["error"]["message"]
    # the tool path sees the same run cost
    tool = asyncio.run(gw.call_tool(ALICE, "lookup_order", {"order_id": "O"}, run_id="run-1"))
    assert tool.content["error"] == "COST_BUDGET"


def test_rate_limit_per_user():
    proxy, _ = make_proxy()
    proxy.rule.rate_limit.calls = 2
    assert [handle(proxy, BODY, run_id=f"r{i}").status for i in range(3)] == [200, 200, 429]
    res = handle(proxy, BODY, who=Principal.of("dave"), run_id="r9")
    assert res.status == 200  # another user has their own window


def test_unknown_model_price_is_charged_conservatively():
    proxy, _ = make_proxy()
    usd, priced = proxy.cost_usd("claude-new-model", {"output_tokens": 1_000_000})
    assert not priced and usd == pytest.approx(40.0)  # highest listed output price (fable-5-2)
    usd, _ = proxy.cost_usd("claude-opus-5-5", {"output_tokens": 1_000_000, "speed": "fast"})
    assert usd == pytest.approx(40.0)  # opus fast mode: 2 x $20


def test_streaming_is_passed_through_and_charged():
    proxy, gw = make_proxy()
    res = handle(proxy, {**BODY, "stream": True})

    async def drain():
        return [chunk async for chunk in res.events]

    chunks = asyncio.run(drain())
    assert chunks[0].startswith(b"event: message_start") and chunks[-1].startswith(b"event: message_stop")
    assert gw.state.run("run-1", gw.clock()).cost_usd == pytest.approx(EXPECTED_COST)


def test_provider_error_is_relayed():
    class Failing(FakeProvider):
        async def create(self, params, betas):
            raise ProviderError(529, error_body(529, "OVERLOADED", "overloaded"))

    proxy, gw = make_proxy(provider=Failing())
    res = handle(proxy, BODY)
    assert res.status == 529 and gw.audit.read()[-1]["event"] == "llm_failed"


# --------------------------------------------------------------------------- end to end with the real SDK

def _fake_anthropic_api(seen: list) -> Starlette:
    async def messages(request: Request):
        body = await request.json()
        seen.append({"body": body, "headers": dict(request.headers)})
        if body.get("stream"):
            async def sse():
                for e in _events(body["model"]):
                    yield f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode()
            return StreamingResponse(sse(), media_type="text/event-stream")
        return JSONResponse(_message(body["model"]))

    return Starlette(routes=[Route("/v1/messages", messages, methods=["POST"])])


class _Tokens:
    async def verify_token(self, token):
        from mcp.server.auth.provider import AccessToken

        if token != "gw-token-alice":
            return None
        return AccessToken(token=token, client_id="dev", scopes=sorted(ALICE.scopes), subject="alice")


def _client_for(app, **kw):
    return anthropic.AsyncAnthropic(
        base_url="http://testserver", max_retries=0,
        http_client=anthropic.DefaultAsyncHttpxClient(transport=httpx2.ASGITransport(app=app)), **kw)


async def _e2e():
    seen: list = []
    provider_client = _client_for(_fake_anthropic_api(seen), api_key="sk-gateway-secret")
    proxy, gw = make_proxy(provider=AnthropicProvider(provider_client))
    gateway_app = Starlette(routes=[llm_route(proxy, _Tokens())])
    agent = _client_for(gateway_app, api_key="gw-token-alice")

    msg = await agent.messages.create(**BODY, extra_headers={"x-aof-run-id": "e2e"})
    async with agent.messages.stream(**BODY, extra_headers={"x-aof-run-id": "e2e"}) as stream:
        text = "".join([t async for t in stream.text_stream])
        final = await stream.get_final_message()
    with pytest.raises(anthropic.PermissionDeniedError) as denied:
        await agent.messages.create(**{**BODY, "model": "claude-sonnet-5-5"})
    with pytest.raises(anthropic.AuthenticationError):
        await _client_for(gateway_app, api_key="wrong").messages.create(**BODY)
    return msg, text, final, denied.value, seen, gw


def test_end_to_end_with_real_sdk():
    msg, text, final, denied, seen, gw = asyncio.run(_e2e())
    assert msg.content[0].text == "hello" and msg.usage.output_tokens == 500
    assert text == "hello" and final.stop_reason == "end_turn"
    assert "MODEL_NOT_ALLOWED" in str(denied)
    # the provider saw the gateway's credential, never the agent's token
    for s in seen:  # SDK 2.x sends the key as a bearer token; older SDKs use x-api-key
        sent = s["headers"].get("x-api-key") or s["headers"].get("authorization", "").removeprefix("Bearer ")
        assert sent == "sk-gateway-secret"
        assert "gw-token-alice" not in json.dumps(s["headers"])
    assert len(seen) == 2  # the denied and unauthenticated calls never reached the provider
    assert gw.state.run("e2e", gw.clock()).cost_usd == pytest.approx(2 * EXPECTED_COST)
