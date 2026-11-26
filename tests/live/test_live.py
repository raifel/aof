"""Live smoke tests against real services. Never part of the normal run.

    AOF_LIVE=1 .venv/bin/pytest -m live tests/live -v

Each test needs its own environment variables and skips without them; see README.md
in this folder. The Claude tests are billed (a few cents in total; the eval smoke test
is gated separately by AOF_LIVE_EVAL=1).
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import uuid

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("AOF_LIVE") != "1", reason="set AOF_LIVE=1 to run live tests"),
]


def need(*names: str) -> dict[str, str]:
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        pytest.skip(f"set {', '.join(missing)}")
    return {n: os.environ[n] for n in names}


# --------------------------------------------------------------------------- Redis


@pytest.fixture
def redis_store():
    env = need("AOF_LIVE_REDIS_URL")
    from aof.gateway.state import RedisStore

    store = RedisStore.from_url(env["AOF_LIVE_REDIS_URL"], prefix=f"aof-live-{uuid.uuid4().hex[:8]}:")
    yield store
    keys = list(store.r.scan_iter(match=f"{store.prefix}*"))
    if keys:
        store.r.delete(*keys)


def test_redis_store_contract(redis_store):
    s = redis_store
    s.put("ns", "a", {"x": 1}, ttl=60)
    assert s.get("ns", "a") == {"x": 1} and s.r.ttl(s._doc("ns", "a")) > 0
    s.update("ns", "a", lambda d: {**d, "x": 2})
    assert s.get("ns", "a") == {"x": 2} and s.r.ttl(s._doc("ns", "a")) > 0  # KEEPTTL (Redis >= 6.0)
    assert s.put_if_absent("ns", "a", {"x": 3}) is False
    assert s.incr("c", 0.5, 60) == pytest.approx(0.5)
    assert s.window_acquire("w", 1000.0, 60, 1) == (True, 1) and s.window_acquire("w", 1000.1, 60, 1)[0] is False


def test_redis_window_never_oversells(redis_store):
    from aof.gateway.state import RedisStore

    other = RedisStore(type(redis_store.r).from_url(os.environ["AOF_LIVE_REDIS_URL"]), prefix=redis_store.prefix)
    barrier, got, lock = threading.Barrier(40), [], threading.Lock()

    def worker(i):
        barrier.wait()
        ok = (redis_store if i % 2 else other).window_acquire("rate", 1000.0, 60, 10)[0]
        with lock:
            got.append(ok)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert got.count(True) == 10


# --------------------------------------------------------------------------- IdP


def test_idp_token_verifies_and_tampering_is_rejected():
    env = need("AOF_LIVE_ISSUER", "AOF_LIVE_AUDIENCE", "AOF_LIVE_TOKEN")
    from aof.gateway.jwt_verifier import JwtVerifier

    v = JwtVerifier(env["AOF_LIVE_ISSUER"], env["AOF_LIVE_AUDIENCE"],
                    roles_claim=os.environ.get("AOF_LIVE_ROLES_CLAIM", "roles"))
    access = asyncio.run(v.verify_token(env["AOF_LIVE_TOKEN"]))
    assert access is not None, "the IdP's token was rejected: check issuer, audience and expiry"
    print(f"\nverified: sub={access.subject} client={access.client_id} scopes={access.scopes} "
          f"roles={access.claims['roles']}")
    head, body, sig = env["AOF_LIVE_TOKEN"].split(".")
    assert asyncio.run(v.verify_token(f"{head}.{body}.{sig[:-4]}AAAA")) is None


def test_token_exchange_at_the_idp():
    env = need("AOF_LIVE_TOKEN_ENDPOINT", "AOF_LIVE_CLIENT_ID", "AOF_LIVE_CLIENT_SECRET", "AOF_LIVE_TOKEN",
               "AOF_LIVE_OBO_AUDIENCE")
    from aof.gateway.obo import TokenExchanger

    ex = TokenExchanger(env["AOF_LIVE_TOKEN_ENDPOINT"], env["AOF_LIVE_CLIENT_ID"], env["AOF_LIVE_CLIENT_SECRET"])
    scopes = os.environ.get("AOF_LIVE_OBO_SCOPES", "").split()
    tok = asyncio.run(ex.exchange(env["AOF_LIVE_TOKEN"], audience=env["AOF_LIVE_OBO_AUDIENCE"], scopes=scopes))
    assert tok.access_token and tok.access_token != env["AOF_LIVE_TOKEN"]
    print(f"\nexchanged: {tok.audit()}")


# --------------------------------------------------------------------------- Claude API (billed)


def _proxy(model: str):
    from aof.gateway import Gateway
    from aof.gateway.llm import AnthropicProvider, LlmProxy

    from ..test_gateway_core import FakeUpstream, make_policy

    policy = make_policy("L2")
    policy.llm.models = [model]
    policy.llm.default_model = model
    gw = Gateway(policy, FakeUpstream(policy))
    return LlmProxy(gw, AnthropicProvider()), gw


def test_claude_through_the_gateway():
    need("ANTHROPIC_API_KEY")
    from ..test_gateway_core import ALICE

    model = os.environ.get("AOF_LIVE_MODEL", "claude-haiku-5-5")
    proxy, gw = _proxy(model)
    body = {"model": model, "max_tokens": 64, "messages": [{"role": "user", "content": "Reply with the word ok."}]}
    res = asyncio.run(proxy.handle(ALICE, body, run_id="live"))
    assert res.status == 200, res.body
    assert res.body["usage"]["output_tokens"] > 0
    stream = asyncio.run(proxy.handle(ALICE, {**body, "stream": True}, run_id="live"))

    async def drain():
        return [chunk async for chunk in stream.events]

    chunks = asyncio.run(drain())
    assert chunks[0].startswith(b"event: message_start") and chunks[-1].startswith(b"event: message_stop")
    run = gw.state.run("live")
    assert run.model_calls == 2 and run.cost_usd > 0
    denied = asyncio.run(proxy.handle(ALICE, {**body, "model": "claude-fable-5-2"}, run_id="live"))
    assert denied.status == 403  # the allowlist holds against the real API too
    print(f"\n2 calls, ${run.cost_usd:.6f}")


def test_eval_smoke_two_cases():
    need("ANTHROPIC_API_KEY")
    if os.environ.get("AOF_LIVE_EVAL") != "1":
        pytest.skip("set AOF_LIVE_EVAL=1: runs 2 eval cases with the app's model (a few cents)")
    from aof.evalrun import run_suite
    from aof.gateway.llm import AnthropicProvider
    from aof.gateway.mcp_proxy import McpUpstream
    from aof.loader import load_project
    from aof.platform import load_platform

    from ..conftest import EXAMPLE

    lp = load_project(EXAMPLE)
    lp.golden_cases = lp.golden_cases[:1]
    lp.safety_cases = lp.safety_cases[:1]
    upstream = McpUpstream.stdio([sys.executable, "src/server.py"], cwd=str(EXAMPLE))
    run = asyncio.run(run_suite(lp, load_platform(), upstream, AnthropicProvider()))
    print("\n" + "\n".join(f"{o.id}: passed={o.passed} status={o.status} tools={o.tools_called} "
                           f"cost=${o.cost_usd:.4f} {o.error or ''}" for o in run.outcomes))
    assert run.results["errors"] == 0
    assert run.outcomes[0].tools_called, "the agent called no tools"
