"""Production identity: verify JWT access tokens signed by the platform's IdP.

Implements the MCP SDK's TokenVerifier protocol (`async verify_token(token) ->
AccessToken | None`), so the same verifier guards /mcp, /v1/messages, /a2a and /admin.

A token is accepted only if all of these hold:
  - the signature verifies with a key from the IdP's JWKS (matched by `kid`),
    using an allow-listed asymmetric algorithm (never `none` or HS*);
  - `iss` equals the configured issuer and `aud` contains this gateway's audience;
  - `exp` is present and in the future, `nbf`/`iat` are not in the future (with leeway);
  - `sub` is present: decisions are made for a named user or agent.

Keys are discovered from the issuer's metadata (OpenID Connect discovery, then OAuth
authorization server metadata, RFC 8414), and the metadata's `issuer` must match
(mix-up protection). The JWKS is cached and refetched when a token names an unknown
`kid` (key rotation), at most once per `min_refresh_seconds`.

Claim mapping: scopes from `scope` (space-separated) or `scp` (list or string), roles
from `roles_claim` (dotted path, e.g. realm_access.roles), tenant from `tenant_claim`,
client id from `client_id` or `azp` (for A2A this is the calling agent).

Not built: opaque tokens (RFC 7662 introspection), revocation checks before `exp`,
DPoP / mTLS-bound tokens (RFC 9449 / 8705).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Iterable

log = logging.getLogger("aof.gateway.auth")

_DISCOVERY = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
ACCEPTED_TYP = {"jwt", "at+jwt", "application/at+jwt"}


class IdentityConfigError(Exception):
    pass


def _claim(claims: dict[str, Any], path: str | None) -> Any:
    if not path:
        return None
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return []


class JwtVerifier:
    def __init__(self, issuer: str, audience: str | Iterable[str], *, jwks_uri: str | None = None,
                 algorithms: Iterable[str] = ("RS256", "PS256", "ES256", "EdDSA"),
                 roles_claim: str = "roles", tenant_claim: str | None = "tenant", leeway: float = 60,
                 jwks_ttl: float = 3600, min_refresh_seconds: float = 30, http: Any = None, clock=time.time):
        self.algorithms = [a for a in algorithms]
        weak = [a for a in self.algorithms if a.lower() == "none" or a.upper().startswith("HS")]
        if weak or not self.algorithms:
            raise IdentityConfigError(f"refusing algorithms {weak or '[]'}: use asymmetric algorithms only")
        self.issuer = issuer
        self.audiences = [audience] if isinstance(audience, str) else list(audience)
        if not self.audiences:
            raise IdentityConfigError("an audience is required")
        self.jwks_uri = jwks_uri
        self.roles_claim = roles_claim
        self.tenant_claim = tenant_claim
        self.leeway = leeway
        self.jwks_ttl = jwks_ttl
        self.min_refresh_seconds = min_refresh_seconds
        self.clock = clock
        self._http = http
        self._keys: dict[str | None, Any] = {}
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()
        self.fetches = 0

    # ------------------------------------------------------------------ keys

    def _client(self):
        if self._http is None:
            import httpx2

            self._http = httpx2.AsyncClient(timeout=10.0)
        return self._http

    async def _get_json(self, url: str) -> dict[str, Any]:
        res = await self._client().get(url, headers={"accept": "application/json"})
        res.raise_for_status()
        body = res.json()
        if not isinstance(body, dict):
            raise ValueError(f"{url} did not return a JSON object")
        return body

    async def _discover(self) -> str:
        base = self.issuer.rstrip("/")
        for path in _DISCOVERY:
            try:
                meta = await self._get_json(base + path)
            except Exception:  # noqa: BLE001 - try the next well-known document
                continue
            if meta.get("issuer") != self.issuer:
                raise IdentityConfigError(f"metadata at {path} names issuer {meta.get('issuer')!r}, "
                                          f"expected {self.issuer!r}")
            if isinstance(meta.get("jwks_uri"), str):
                return meta["jwks_uri"]
        raise IdentityConfigError(f"no jwks_uri in {self.issuer}'s metadata; set identity.jwks_uri")

    async def _refresh(self, *, force: bool) -> None:
        import jwt

        async with self._lock:
            now = self.clock()
            if self._fetched_at is not None:
                age = now - self._fetched_at
                if (not force and age < self.jwks_ttl) or age < self.min_refresh_seconds:
                    return
            if self.jwks_uri is None:
                self.jwks_uri = await self._discover()
            jwks = await self._get_json(self.jwks_uri)
            keys: dict[str | None, Any] = {}
            for jwk in jwks.get("keys", []):
                if jwk.get("use", "sig") != "sig":
                    continue
                try:
                    keys[jwk.get("kid")] = jwt.PyJWK(jwk)
                except Exception:  # noqa: BLE001 - skip keys of unsupported types
                    continue
            self._keys, self._fetched_at = keys, now
            self.fetches += 1

    async def _key_for(self, kid: str | None):
        await self._refresh(force=False)
        key = self._keys.get(kid) if kid is not None else (
            next(iter(self._keys.values())) if len(self._keys) == 1 else None)
        if key is None and kid is not None:
            await self._refresh(force=True)  # key rotation
            key = self._keys.get(kid)
        return key

    # ------------------------------------------------------------------ verification

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        try:
            claims = await self.decode(token)
        except Exception as exc:  # noqa: BLE001 - every failure is a 401, never a crash
            log.info("token rejected: %s", type(exc).__name__ if not isinstance(exc, ValueError) else exc)
            return None
        aud = claims.get("aud")
        auds = [aud] if isinstance(aud, str) else list(aud or [])
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or claims["sub"]),
            scopes=_strings(claims.get("scope")) or _strings(claims.get("scp")),
            expires_at=int(claims["exp"]),
            resource=next((a for a in auds if a in self.audiences), None),
            subject=str(claims["sub"]),
            claims={
                "roles": _strings(_claim(claims, self.roles_claim)),
                "tenant": _claim(claims, self.tenant_claim),
                "iss": claims.get("iss"),
            },
        )

    async def decode(self, token: str) -> dict[str, Any]:
        """Verified claims, or an exception saying why not."""
        import jwt

        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise ValueError(f"algorithm {alg!r} is not allowed")
        typ = header.get("typ")
        if typ is not None and str(typ).lower() not in ACCEPTED_TYP:
            raise ValueError(f"token type {typ!r} is not an access token")
        key = await self._key_for(header.get("kid"))
        if key is None:
            raise ValueError("no signing key matches the token's kid")
        return jwt.decode(
            token, key, algorithms=[alg], audience=self.audiences, issuer=self.issuer, leeway=self.leeway,
            options={"require": ["exp", "iss", "aud", "sub"], "verify_signature": True},
        )


def verifier_from_policy(identity, audience: str | Iterable[str], **kw) -> JwtVerifier:
    if not identity.issuer:
        raise IdentityConfigError("no identity.issuer in the policy")
    return JwtVerifier(identity.issuer, audience, jwks_uri=identity.jwks_uri, algorithms=identity.algorithms,
                       roles_claim=identity.roles_claim, tenant_claim=identity.tenant_claim,
                       leeway=identity.leeway_seconds, **kw)
