"""On-behalf-of token exchange (RFC 8693).

A fake IdP (Starlette, in process) implements the token-exchange grant. The end-to-end
test runs an authenticated MCP app server that only accepts exchanged tokens.
"""

from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import parse_qs, unquote

import pytest

httpx2 = pytest.importorskip("httpx2")

from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from aof.gateway import Gateway, Principal  # noqa: E402
from aof.gateway.obo import (  # noqa: E402
    ACCESS_TOKEN_TYPE,
    GRANT_TOKEN_EXCHANGE,
    OboBroker,
    TokenExchanger,
    TokenExchangeError,
)
from aof.platform import load_platform  # noqa: E402
from aof.policy import check_policy  # noqa: E402

from .conftest import codes  # noqa: E402
from .test_gateway_core import REFUND, FakeUpstream, make_policy  # noqa: E402

USER_TOKENS = {"user-tok-alice": "alice", "user-tok-dave": "dave"}
USER_SCOPES = {"alice": {"orders:read", "refunds:read", "refunds:create", "tickets:write"}, "dave": set()}
APP = "https://refunds.internal/mcp"
ALICE = Principal.of("alice", sorted(USER_SCOPES["alice"]), token="user-tok-alice")


class FakeIdp:
    """RFC 8693 token endpoint. `mode` changes its behaviour for failure tests."""

    def __init__(self):
        self.requests: list[dict] = []
        self.issued: dict[str, str] = {}  # token -> audience
        self.mode = "ok"
        self.n = 0

    def app(self):
        async def token(request: Request):
            form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
            auth = request.headers.get("authorization", "")
            if auth.startswith("Basic "):  # RFC 6749 2.3.1: id and secret are form-urlencoded
                cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
                form["_client"] = f"{unquote(cid)}:{unquote(secret)}"
            else:
                form["_client"] = None
            self.requests.append(form)
            if form.get("_client") != "agent:refunds-assistant:s3cret":
                return JSONResponse({"error": "invalid_client"}, 401)
            if form.get("grant_type") != GRANT_TOKEN_EXCHANGE:
                return JSONResponse({"error": "unsupported_grant_type"}, 400)
            user = USER_TOKENS.get(form.get("subject_token"))
            if user is None or self.mode == "deny":
                return JSONResponse({"error": "invalid_grant"}, 400)
            requested = set(form.get("scope", "").split()) - {""}
            granted = requested & USER_SCOPES[user]  # the IdP downscopes to what the user holds
            if self.mode == "widen":
                granted |= {"admin:all"}
            self.n += 1
            body = {"access_token": f"obo-{self.n}-{user}", "issued_token_type": ACCESS_TOKEN_TYPE,
                    "token_type": "Bearer", "expires_in": 3600, "scope": " ".join(sorted(granted))}
            self.issued[body["access_token"]] = form.get("audience")
            if self.mode == "no_scope":
                del body["scope"]
            return JSONResponse(body)

        return Starlette(routes=[Route("/token", token, methods=["POST"])])


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def exchanger(idp, clock=None, secret="s3cret"):
    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=idp.app()))
    return TokenExchanger("https://idp.test/token", "agent:refunds-assistant", secret, http=http,
                          max_ttl=900, clock=clock or Clock())


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- the exchange

def test_exchange_request_and_ttl_cap():
    idp, clock = FakeIdp(), Clock()
    tok = run(exchanger(idp, clock).exchange("user-tok-alice", audience=APP, scopes=["orders:read"],
                                             resource=APP))
    req = idp.requests[-1]
    assert req["grant_type"] == GRANT_TOKEN_EXCHANGE and req["subject_token_type"] == ACCESS_TOKEN_TYPE
    assert req["requested_token_type"] == ACCESS_TOKEN_TYPE
    assert req["audience"] == APP and req["resource"] == APP and req["scope"] == "orders:read"
    assert tok.access_token == "obo-1-alice" and tok.scopes == ("orders:read",)
    assert tok.expires_at == clock.t + 900  # IdP said 3600; the platform caps at scope_ttl_seconds
    assert "obo-1-alice" not in repr(tok)


def test_cache_per_token_audience_and_scopes():
    idp, clock = FakeIdp(), Clock()
    ex = exchanger(idp, clock)

    async def go():
        a = await ex.exchange("user-tok-alice", audience=APP, scopes=["orders:read"])
        b = await ex.exchange("user-tok-alice", audience=APP, scopes=["orders:read"])
        c = await ex.exchange("user-tok-alice", audience=APP, scopes=["refunds:read"])
        d = await ex.exchange("user-tok-dave", audience=APP)
        clock.t += 900 - 29  # inside the 30 s skew: refresh
        e = await ex.exchange("user-tok-alice", audience=APP, scopes=["orders:read"])
        return a, b, c, d, e

    a, b, c, d, e = run(go())
    assert b.cached and b.access_token == a.access_token
    assert not c.cached and not d.cached and c.access_token != a.access_token
    assert not e.cached and len(idp.requests) == 4


@pytest.mark.parametrize("mode, scopes, code", [
    ("deny", ["orders:read"], "TOKEN_EXCHANGE_FAILED"),
    ("widen", ["orders:read"], "OBO_SCOPE_WIDENED"),
    ("ok", ["payroll:read"], "OBO_SCOPE_DENIED"),
])
def test_exchange_failures(mode, scopes, code):
    idp = FakeIdp()
    idp.mode = mode
    with pytest.raises(TokenExchangeError) as exc:
        run(exchanger(idp).exchange("user-tok-alice", audience=APP, scopes=scopes))
    assert exc.value.code == code and "user-tok-alice" not in str(exc.value)


def test_absent_scope_means_as_requested():
    idp = FakeIdp()
    idp.mode = "no_scope"
    assert run(exchanger(idp).exchange("user-tok-alice", audience=APP, scopes=["orders:read"])).access_token


def test_bad_client_secret_and_unreachable_idp():
    with pytest.raises(TokenExchangeError) as exc:
        run(exchanger(FakeIdp(), secret="wrong").exchange("user-tok-alice", audience=APP))
    assert exc.value.code == "TOKEN_EXCHANGE_FAILED" and "invalid_client" in str(exc.value)

    class Down(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx2.ConnectError("down")

    ex = TokenExchanger("https://idp.test/token", "c", "s", http=httpx2.AsyncClient(transport=Down()))
    with pytest.raises(TokenExchangeError) as exc:
        run(ex.exchange("user-tok-alice", audience=APP))
    assert exc.value.code == "TOKEN_EXCHANGE_UNAVAILABLE"


# --------------------------------------------------------------------------- in the gateway

def make_gw(level="L2", idp=None):
    idp = idp or FakeIdp()
    policy = make_policy(level)
    up = FakeUpstream(policy)
    gw = Gateway(policy, up, obo=OboBroker(exchanger(idp), audience=APP, resource=APP))
    return gw, up, idp


def test_tool_call_uses_per_tool_token():
    gw, up, idp = make_gw()
    res = run(gw.call_tool(ALICE, "lookup_order", {"order_id": "ORD-1"}, run_id="r"))
    assert not res.is_error
    assert up.tokens[-1] == "obo-1-alice" and idp.requests[-1]["scope"] == "orders:read"
    rec = gw.audit.read()[-1]
    assert rec["on_behalf_of"] == {"audience": APP, "scopes": ["orders:read"], "expires_in": 900, "cached": False}
    assert "obo-1-alice" not in json.dumps(gw.audit.read()) and "user-tok" not in json.dumps(gw.audit.read())


def test_denied_calls_never_reach_the_idp():
    gw, up, idp = make_gw()
    res = run(gw.call_tool(ALICE, "delete_customer_account", {}, run_id="r"))
    assert res.is_error and idp.requests == [] and up.calls == []


def test_no_user_token_fails_closed():
    gw, up, _ = make_gw()
    who = Principal.of("alice", sorted(USER_SCOPES["alice"]))  # e.g. stdio: no bearer token
    res = run(gw.call_tool(who, "lookup_order", {"order_id": "O"}, run_id="r"))
    assert res.content["error"] == "NO_SUBJECT_TOKEN" and up.calls == []
    assert gw.audit.read()[-1]["event"] == "token_exchange_failed"


def test_exchange_failure_is_a_tool_error_not_a_crash():
    idp = FakeIdp()
    idp.mode = "deny"
    gw, up, _ = make_gw(idp=idp)
    res = run(gw.call_tool(ALICE, "lookup_order", {"order_id": "O"}, run_id="r"))
    assert res.is_error and res.content["error"] == "TOKEN_EXCHANGE_FAILED" and up.calls == []
    assert run(gw.visible_tools(ALICE)) == []  # discovery fails closed too


def test_visible_tools_use_an_unscoped_token():
    gw, up, idp = make_gw()
    assert run(gw.visible_tools(ALICE))
    assert up.tokens[-1] and "scope" not in idp.requests[-1]


def test_approval_preview_uses_the_tool_scopes():
    gw, up, idp = make_gw()
    res = run(gw.call_tool(ALICE, "create_refund_request", REFUND, run_id="r"))
    assert res.content["status"] == "approval_required"
    assert idp.requests[-1]["scope"] == "refunds:create" and up.calls[-1][1]["dry_run"] is True


def test_a2a_peer_gets_an_obo_token_when_no_static_credential():
    from .test_gateway_a2a import FakeTransport, a2a_policy, rpc
    from aof.gateway.a2a_proxy import A2aProxy, Call
    from aof.models.project import A2aPeer

    peer = A2aPeer(name="billing", card_url="https://billing.test/.well-known/agent-card.json",
                   skills=["invoice_lookup"], scopes=["invoices:read"])
    policy = a2a_policy(peers=[peer])
    idp = FakeIdp()
    USER_SCOPES["alice"].add("invoices:read")
    try:
        gw = Gateway(policy, FakeUpstream(policy), obo=OboBroker(exchanger(idp), audience=APP))
        proxy = A2aProxy(gw, FakeTransport(), env={})
        run(proxy.delegate("billing", Call(ALICE, rpc(), run_id="r")))
    finally:
        USER_SCOPES["alice"].discard("invoices:read")
    _, _, headers = proxy.transport.posts[-1]
    assert headers["authorization"] == "Bearer obo-1-alice"
    assert idp.requests[-1]["audience"] == "https://billing.test/" and idp.requests[-1]["scope"] == "invoices:read"
    assert gw.audit.read()[-1]["on_behalf_of"]["audience"] == "https://billing.test/"


# --------------------------------------------------------------------------- config

def test_policy_requires_https_token_endpoint(example):
    from aof.loader import load_project

    lp = load_project(example)
    platform = load_platform()
    platform.identity.token_endpoint = "http://idp.local/token"
    assert "AOF-P060" in codes(check_policy(lp.project, lp.manifest, platform))


def test_compiled_identity():
    from aof.loader import load_project
    from aof.policy import compile_policy
    from aof.gateway.compiled import CompiledPolicy

    from .conftest import EXAMPLE

    lp = load_project(EXAMPLE)
    platform = load_platform()
    platform.identity.token_endpoint = "https://idp.example/token"
    ident = CompiledPolicy.model_validate(compile_policy(lp.project, lp.manifest, platform)).identity
    assert ident.mode == "on_behalf_of" and ident.token_endpoint == "https://idp.example/token"
    assert ident.scope_ttl_seconds == 900


def test_cli_turns_obo_off_loudly_without_a_user_token(capsys):
    import argparse

    from aof.gateway.cli import _obo_broker

    policy = make_policy()
    policy.identity.token_endpoint = "https://idp.example/token"
    args = argparse.Namespace(token_endpoint=None, no_obo=False, transport="stdio", upstream_url=None,
                              allow_insecure_idp=False, client_id=None, client_secret_env="X")
    assert _obo_broker(args, policy) is None
    assert "OFF" in capsys.readouterr().err
    args.transport, args.upstream_url, args.token_endpoint = "http", APP, "http://idp.local/token"
    assert _obo_broker(args, policy) == 2
    args.token_endpoint = None
    assert isinstance(_obo_broker(args, policy), OboBroker)


# --------------------------------------------------------------------------- end to end

pytest.importorskip("mcp")


APP_URL = "http://127.0.0.1:8000/mcp"


def _app_server(seen: list, idp: FakeIdp):
    """The app's MCP server as a resource server: it accepts only exchanged tokens."""
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import MCPServer

    class Verifier:
        async def verify_token(self, token):
            seen.append(token)
            if token not in idp.issued:
                return None  # the user's own token is not valid for the app
            return AccessToken(token=token, client_id="gw", scopes=["orders:read"], subject=token.split("-")[-1],
                               resource=idp.issued[token])

    # validate_token_resource: the app refuses tokens issued for another audience
    app = MCPServer("refunds", token_verifier=Verifier(),
                    auth=AuthSettings(issuer_url="https://idp.test", resource_server_url=APP_URL,
                                      validate_token_resource=True))

    @app.tool()
    def lookup_order(order_id: str) -> dict:
        from mcp.server.auth.middleware.auth_context import get_access_token

        return {"order_id": order_id, "seen_as": get_access_token().subject}

    return app.streamable_http_app()


async def _e2e():
    from aof.gateway.mcp_proxy import McpUpstream

    seen: list[str] = []
    idp = FakeIdp()
    asgi = _app_server(seen, idp)
    upstream = McpUpstream(APP_URL, per_user=True,
                           http_client_factory=lambda h: httpx2.AsyncClient(
                               transport=httpx2.ASGITransport(app=asgi), headers=h))
    policy = make_policy("L2")
    gw = Gateway(policy, upstream, obo=OboBroker(exchanger(idp), audience=APP_URL, resource=APP_URL))
    wrong = Gateway(policy, upstream, obo=OboBroker(exchanger(idp), audience="https://other.example/mcp"))
    async with asgi.router.lifespan_context(asgi), upstream:
        tools = await gw.visible_tools(ALICE)
        res = await gw.call_tool(ALICE, "lookup_order", {"order_id": "ORD-9"}, run_id="r")
        misdirected = await wrong.call_tool(ALICE, "lookup_order", {"order_id": "ORD-9"}, run_id="r2")
    return tools, res, misdirected, seen


def test_end_to_end_app_sees_only_exchanged_tokens():
    tools, res, misdirected, seen = asyncio.run(_e2e())
    assert [t.name for t in tools] == ["lookup_order"]
    assert res.content == {"order_id": "ORD-9", "seen_as": "alice"}
    assert seen and all(t.startswith("obo-") for t in seen)  # the user's token never reached the app
    assert misdirected.is_error and misdirected.content["error"] == "UPSTREAM_ERROR"  # wrong audience refused
