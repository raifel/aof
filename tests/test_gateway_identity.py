"""Production identity: JWT verification against an IdP's JWKS, and the /admin API.

A fake IdP (Starlette, in process) serves OIDC discovery metadata and a JWKS, and
signs tokens with real RSA and EC keys.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

jwt = pytest.importorskip("jwt")
httpx2 = pytest.importorskip("httpx2")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

from aof.gateway import Gateway  # noqa: E402
from aof.gateway.admin import admin_routes  # noqa: E402
from aof.gateway.jwt_verifier import IdentityConfigError, JwtVerifier  # noqa: E402
from aof.platform import load_platform  # noqa: E402
from aof.policy import check_policy  # noqa: E402

from .conftest import codes  # noqa: E402
from .test_gateway_core import REFUND, FakeUpstream, make_policy  # noqa: E402

ISSUER = "https://idp.test/realms/agents"
AUD = "https://gw.test/mcp"


def _jwk(key, kid: str, alg: str) -> dict:
    algo = jwt.algorithms.RSAAlgorithm if alg.startswith(("RS", "PS")) else jwt.algorithms.ECAlgorithm
    jwk = json.loads(algo.to_jwk(key.public_key()))
    return {**jwk, "kid": kid, "alg": alg, "use": "sig"}


class FakeIdp:
    def __init__(self):
        self.keys = {"rsa-1": (rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256"),
                     "ec-1": (ec.generate_private_key(ec.SECP256R1()), "ES256")}
        self.published = ["rsa-1", "ec-1"]
        self.jwks_hits = 0
        self.meta_issuer = ISSUER

    def app(self):
        async def meta(request):
            return JSONResponse({"issuer": self.meta_issuer, "jwks_uri": f"{ISSUER}/certs",
                                 "token_endpoint": f"{ISSUER}/token"})

        async def certs(request):
            self.jwks_hits += 1
            return JSONResponse({"keys": [_jwk(self.keys[k][0], k, self.keys[k][1]) for k in self.published]})

        return Starlette(routes=[Route("/realms/agents/.well-known/openid-configuration", meta),
                                 Route("/realms/agents/certs", certs)])

    def token(self, sub="alice", *, kid="rsa-1", aud=AUD, iss=ISSUER, ttl=300, extra=None, headers=None,
              drop=()):
        now = int(time.time())
        claims = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl, "azp": "refunds-ui",
                  "scope": "orders:read refunds:read", "realm_access": {"roles": ["support-lead"]},
                  "tenant": "eu-1", **(extra or {})}
        for k in drop:
            claims.pop(k, None)
        key, alg = self.keys[kid]
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid, "typ": "at+jwt", **(headers or {})})


def verifier(idp, **kw):
    http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=idp.app()))
    kw.setdefault("roles_claim", "realm_access.roles")
    return JwtVerifier(ISSUER, AUD, http=http, **kw)


def verify(v, token):
    return asyncio.run(v.verify_token(token))


# --------------------------------------------------------------------------- verification

def test_valid_rs256_and_es256_tokens_map_to_a_principal():
    from aof.gateway.identity import principal_from_access_token

    idp = FakeIdp()
    v = verifier(idp)
    for kid in ("rsa-1", "ec-1"):
        access = verify(v, idp.token(kid=kid))
        assert access is not None and access.subject == "alice" and access.client_id == "refunds-ui"
        assert access.resource == AUD
    p = principal_from_access_token(access)
    assert p.scopes == {"orders:read", "refunds:read"} and p.roles == {"support-lead"} and p.tenant == "eu-1"
    assert idp.jwks_hits == 1  # cached


def test_scp_list_claim():
    idp = FakeIdp()
    access = verify(verifier(idp), idp.token(extra={"scp": ["a", "b"]}, drop=("scope",)))
    assert access.scopes == ["a", "b"]


@pytest.mark.parametrize("make", [
    lambda idp: idp.token(ttl=-120),                                   # expired beyond leeway
    lambda idp: idp.token(aud="https://someone-else/mcp"),             # wrong audience
    lambda idp: idp.token(iss="https://evil.test"),                    # wrong issuer
    lambda idp: idp.token(drop=("exp",)),                              # no expiry
    lambda idp: idp.token(drop=("sub",)),                              # no subject
    lambda idp: idp.token(extra={"nbf": int(time.time()) + 3600}),     # not yet valid
    lambda idp: idp.token(headers={"typ": "id+jwt"}),                  # not an access token
    lambda idp: idp.token()[:-4] + "AAAA",                             # bad signature
])
def test_rejected_tokens(make):
    idp = FakeIdp()
    assert verify(verifier(idp), make(idp)) is None


def test_alg_none_and_hs256_key_confusion_rejected():
    idp = FakeIdp()
    v = verifier(idp)
    claims = {"iss": ISSUER, "sub": "mallory", "aud": AUD, "exp": int(time.time()) + 300}
    none_token = jwt.encode(claims, None, algorithm="none", headers={"kid": "rsa-1"})
    assert verify(v, none_token) is None
    # sign HS256 with the RSA public key as the secret: classic algorithm confusion
    pub_pem = idp.keys["rsa-1"][0].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64
    import hashlib
    import hmac

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    signing_input = b64(json.dumps({"alg": "HS256", "kid": "rsa-1", "typ": "JWT"}).encode()) + "." + \
        b64(json.dumps(claims).encode())
    sig = hmac.new(pub_pem, signing_input.encode(), hashlib.sha256).digest()
    assert verify(v, f"{signing_input}.{b64(sig)}") is None


def test_symmetric_algorithms_refused_at_startup():
    with pytest.raises(IdentityConfigError):
        JwtVerifier(ISSUER, AUD, algorithms=["RS256", "HS256"])
    with pytest.raises(IdentityConfigError):
        JwtVerifier(ISSUER, AUD, algorithms=["none"])


def test_key_rotation_and_refresh_rate_limit():
    idp = FakeIdp()
    idp.published = ["rsa-1"]
    now = [1000.0]
    v = verifier(idp, clock=lambda: now[0], min_refresh_seconds=30)
    assert verify(v, idp.token()) is not None
    idp.keys["rsa-2"] = (rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256")
    new = idp.token(kid="rsa-2")
    assert verify(v, new) is None  # unknown kid within 30 s of the last fetch: no refetch storm
    assert idp.jwks_hits == 1
    idp.published = ["rsa-1", "rsa-2"]
    now[0] += 31
    assert verify(v, new) is not None  # rotated key picked up
    assert idp.jwks_hits == 2


def test_discovery_issuer_mismatch_rejects_everything():
    idp = FakeIdp()
    idp.meta_issuer = "https://attacker.test"
    assert verify(verifier(idp), idp.token()) is None


def test_explicit_jwks_uri_skips_discovery():
    idp = FakeIdp()
    idp.meta_issuer = "https://broken.test"
    assert verify(verifier(idp, jwks_uri=f"{ISSUER}/certs"), idp.token()) is not None


# --------------------------------------------------------------------------- config

def test_policy_checks_and_compile(example):
    from aof.gateway.compiled import CompiledPolicy
    from aof.loader import load_project
    from aof.policy import compile_policy

    lp = load_project(example)
    platform = load_platform()
    platform.identity.issuer = "http://idp.local"
    platform.identity.algorithms = ["RS256", "HS256"]
    found = codes(check_policy(lp.project, lp.manifest, platform))
    assert {"AOF-P061", "AOF-P062"} <= found
    platform.identity.issuer, platform.identity.algorithms = ISSUER, ["ES256"]
    ident = CompiledPolicy.model_validate(compile_policy(lp.project, lp.manifest, platform)).identity
    assert ident.issuer == ISSUER and ident.algorithms == ["ES256"] and ident.operator_role == "aof-operator"


def test_serve_picks_a_verifier(capsys, tmp_path):
    import argparse

    from aof.gateway.cli import _verifier
    from aof.gateway.identity import StaticTokenVerifier

    policy = make_policy()
    args = argparse.Namespace(tokens=None, issuer_url=None, audience=None, allow_insecure_idp=False)
    assert _verifier(args, policy, AUD) == (None, None)  # no IdP and no dev tokens: refuse to start
    policy.identity.issuer = "http://idp.local"
    assert _verifier(args, policy, AUD) == (None, None)  # issuer must be https
    policy.identity.issuer = ISSUER
    v, issuer = _verifier(args, policy, AUD)
    assert isinstance(v, JwtVerifier) and v.audiences == [AUD] and issuer == ISSUER
    (tmp_path / "t.json").write_text("{}")
    args.tokens = str(tmp_path / "t.json")
    v, _ = _verifier(args, policy, AUD)
    assert isinstance(v, StaticTokenVerifier) and "DEV ONLY" in capsys.readouterr().err


# --------------------------------------------------------------------------- admin API

def admin_app(idp):
    policy = make_policy("L2")
    gw = Gateway(policy, FakeUpstream(policy))
    app = Starlette(routes=admin_routes(gw, verifier(idp)))
    return gw, app


async def _admin(app, method, path, token=None, body=None):
    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="https://gw.test") as c:
        res = await c.request(method, path, json=body, headers=headers)
        return res.status_code, res.json()


def admin(app, *a, **kw):
    return asyncio.run(_admin(app, *a, **kw))


def _pending(gw):
    from .test_gateway_core import ALICE

    res = asyncio.run(gw.call_tool(ALICE, "create_refund_request", REFUND, run_id="r"))
    return res.content["approval_id"]


def test_admin_requires_a_verified_token():
    idp = FakeIdp()
    gw, app = admin_app(idp)
    assert admin(app, "POST", "/admin/kill", body={"reason": "x"})[0] == 401
    forged = idp.token(sub="ops", extra={"realm_access": {"roles": ["aof-operator"]}}, aud="https://other")
    assert admin(app, "POST", "/admin/kill", forged, {"reason": "x"})[0] == 401
    assert not gw.state.killed(gw.agent_id)


def test_admin_kill_needs_operator_role_and_records_verified_identity():
    idp = FakeIdp()
    gw, app = admin_app(idp)
    status, body = admin(app, "POST", "/admin/kill", idp.token(sub="bob"), {"reason": "x"})
    assert (status, body["error"]) == (403, "NOT_OPERATOR")
    ops = idp.token(sub="ops-1", extra={"realm_access": {"roles": ["aof-operator"]}})
    status, _ = admin(app, "POST", "/admin/kill", ops, {"reason": "cost spike", "agent": gw.agent_id})
    assert status == 200 and gw.state.killed(gw.agent_id)["by"] == "ops-1"
    rec = gw.audit.read()[-1]
    assert rec["event"] == "kill_switch_on" and rec["by"] == "ops-1" and rec["verified"] is True
    assert admin(app, "POST", "/admin/kill", ops, {"reason": "x", "agent": "agent:other"})[0] == 409
    assert admin(app, "POST", "/admin/revive", ops)[0] == 200 and not gw.state.killed(gw.agent_id)
    assert admin(app, "POST", "/admin/demote", ops, {"to": "L1", "reason": "incident"})[1]["capped_at"] == "L1"
    assert admin(app, "POST", "/admin/restore", ops)[0] == 200


def test_admin_approvals_use_token_roles_and_block_self_approval():
    idp = FakeIdp()
    gw, app = admin_app(idp)
    aid = _pending(gw)
    no_role = idp.token(sub="carol", extra={"realm_access": {"roles": []}})
    assert admin(app, "GET", "/admin/approvals", no_role)[0] == 403
    assert admin(app, "POST", f"/admin/approvals/{aid}/approve", no_role)[1]["error"] == "APPROVER_ROLE"
    self_approve = idp.token(sub="alice")  # alice requested it, and holds support-lead in this token
    assert admin(app, "POST", f"/admin/approvals/{aid}/approve", self_approve)[1]["error"] == "SELF_APPROVAL"
    lead = idp.token(sub="bob")
    status, listed = admin(app, "GET", "/admin/approvals", lead)
    assert status == 200 and [a["id"] for a in listed] == [aid]
    status, decided = admin(app, "POST", f"/admin/approvals/{aid}/approve", lead, {"note": "ok"})
    assert status == 200 and decided["status"] == "approved" and decided["decided_by"] == "bob"
    events = [(r["event"], r.get("code")) for r in gw.audit.read()]
    assert ("approval_refused", "SELF_APPROVAL") in events and events[-1] == ("approval_decided", None)


def test_cli_remote_mode(monkeypatch, capsys, tmp_path):
    from aof.cli import main
    from aof.gateway import cli as gcli

    idp = FakeIdp()
    gw, app = admin_app(idp)
    monkeypatch.setattr(gcli, "_admin_client", lambda base: httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=base))
    monkeypatch.setenv("AOF_OPERATOR_TOKEN", idp.token(sub="ops-1",
                                                       extra={"realm_access": {"roles": ["aof-operator"]}}))
    remote = ["--gateway-url", "https://gw.test", "--state-dir", str(tmp_path)]
    assert main(["gateway", "kill", gw.agent_id, "--reason", "drill", *remote]) == 0
    assert gw.state.killed(gw.agent_id)["by"] == "ops-1"
    assert not (tmp_path / "state.json").exists()  # nothing written locally
    monkeypatch.setenv("AOF_OPERATOR_TOKEN", idp.token(sub="bob"))
    assert main(["gateway", "revive", gw.agent_id, *remote]) == 1
    assert "NOT_OPERATOR" in capsys.readouterr().err
    monkeypatch.delenv("AOF_OPERATOR_TOKEN")
    assert main(["gateway", "revive", gw.agent_id, *remote]) == 2
    assert main(["gateway", "revive", gw.agent_id, "--state-dir", str(tmp_path)]) == 2  # local needs --by
