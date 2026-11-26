"""On-behalf-of credentials: OAuth 2.0 Token Exchange (RFC 8693).

The gateway never forwards the user's own token and never uses a shared service
account for user-facing apps. For each upstream call it exchanges the user's token
(the subject token) at the IdP for a new access token that is:

  - bound to one audience: the app's MCP server (or the A2A peer),
  - limited to the scopes the tool needs (the manifest's per-tool scopes),
  - short-lived: never used past platform.yaml identity.scope_ttl_seconds.

The gateway authenticates to the IdP as its own OAuth client (client_secret_basic).
Exchanged tokens are cached per (user token, audience, scopes) until shortly before
they expire. Tokens never reach the audit log; only audience, scopes and lifetime do.

Not built: private_key_jwt / mTLS client authentication, actor tokens (RFC 8693
`actor_token`, for "gateway acting for user" delegation chains), DPoP binding.
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import quote

from .identity import Principal

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class TokenExchangeError(Exception):
    """A stable code the agent can act on, and a reason without secrets."""

    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class ExchangedToken:
    access_token: str = field(repr=False)
    audience: str
    scopes: tuple[str, ...]
    expires_at: float
    expires_in: int  # seconds left when it was handed out
    cached: bool = False

    def audit(self) -> dict[str, Any]:
        return {"audience": self.audience, "scopes": list(self.scopes), "expires_in": self.expires_in,
                "cached": self.cached}


class TokenExchanger:
    def __init__(self, token_endpoint: str, client_id: str, client_secret: str | None, *,
                 subject_token_type: str = ACCESS_TOKEN_TYPE, max_ttl: float = 900, skew: float = 30,
                 http: Any = None, clock=time.time, max_cache: int = 10_000):
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self._client_secret = client_secret
        self.subject_token_type = subject_token_type
        self.max_ttl = max_ttl
        self.skew = skew
        self.clock = clock
        self.max_cache = max_cache
        self._http = http
        self._cache: OrderedDict[tuple, ExchangedToken] = OrderedDict()

    def _client(self):
        if self._http is None:
            import httpx2

            self._http = httpx2.AsyncClient(timeout=10.0)
        return self._http

    def _auth_header(self) -> dict[str, str]:
        if self._client_secret is None:
            return {}
        # RFC 6749 2.3.1: form-urlencode the id and secret before base64.
        raw = f"{quote(self.client_id, safe='')}:{quote(self._client_secret, safe='')}".encode()
        return {"authorization": "Basic " + base64.b64encode(raw).decode()}

    async def exchange(self, subject_token: str, *, audience: str, scopes: Iterable[str] = (),
                       resource: str | None = None) -> ExchangedToken:
        requested = tuple(sorted(set(scopes)))
        now = self.clock()
        key = (hashlib.sha256(subject_token.encode()).hexdigest(), audience, resource, requested)
        hit = self._cache.get(key)
        if hit is not None and hit.expires_at - self.skew > now:
            self._cache.move_to_end(key)
            return ExchangedToken(hit.access_token, hit.audience, hit.scopes, hit.expires_at,
                                  round(hit.expires_at - now), cached=True)

        form = {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": self.subject_token_type,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
        }
        if resource:
            form["resource"] = resource
        if requested:
            form["scope"] = " ".join(requested)
        if self._client_secret is None:
            form["client_id"] = self.client_id  # public client
        try:
            res = await self._client().post(self.token_endpoint, data=form,
                                            headers={"accept": "application/json", **self._auth_header()})
        except Exception as exc:  # noqa: BLE001 - IdP unreachable
            raise TokenExchangeError("TOKEN_EXCHANGE_UNAVAILABLE",
                                     f"the identity provider could not be reached ({type(exc).__name__})") from exc
        try:
            body = res.json()
        except ValueError:
            body = {}
        if res.status_code != 200:
            err = body.get("error", f"http_{res.status_code}") if isinstance(body, dict) else f"http_{res.status_code}"
            raise TokenExchangeError("TOKEN_EXCHANGE_FAILED",
                                     f"the identity provider refused the exchange: {err}")
        token = self._validate(body, requested)
        expires_in = body.get("expires_in")
        ttl = min(float(expires_in), self.max_ttl) if isinstance(expires_in, (int, float)) else self.max_ttl
        out = ExchangedToken(token, audience, requested, now + ttl, round(ttl))
        self._cache[key] = out
        while len(self._cache) > self.max_cache:
            self._cache.popitem(last=False)
        return out

    @staticmethod
    def _validate(body: Any, requested: tuple[str, ...]) -> str:
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise TokenExchangeError("TOKEN_EXCHANGE_FAILED", "the identity provider returned no access_token")
        issued = body.get("issued_token_type")
        if issued is not None and issued != ACCESS_TOKEN_TYPE:
            raise TokenExchangeError("TOKEN_EXCHANGE_FAILED", f"unexpected issued_token_type {issued}")
        if str(body.get("token_type", "")).lower() != "bearer":
            raise TokenExchangeError("TOKEN_EXCHANGE_FAILED", "only Bearer tokens are supported")
        if "scope" in body:  # absent means "as requested" (RFC 6749 5.1)
            granted = set(str(body["scope"]).split())
            wider = granted - set(requested)
            if wider:
                raise TokenExchangeError("OBO_SCOPE_WIDENED",
                                         f"the identity provider granted unrequested scopes: {sorted(wider)}")
            missing = set(requested) - granted
            if missing:
                raise TokenExchangeError("OBO_SCOPE_DENIED",
                                         f"the user may not delegate scopes: {sorted(missing)}")
        return body["access_token"]


class OboBroker:
    """Tokens for the app's MCP server (and for A2A peers) on behalf of the caller."""

    def __init__(self, exchanger: TokenExchanger, *, audience: str, resource: str | None = None):
        self.exchanger = exchanger
        self.audience = audience
        self.resource = resource  # RFC 8707 resource indicator: the MCP server's URL

    async def for_upstream(self, principal: Principal, scopes: Iterable[str] = ()) -> ExchangedToken:
        return await self.for_audience(principal, self.audience, scopes, resource=self.resource)

    async def for_audience(self, principal: Principal, audience: str, scopes: Iterable[str] = (),
                           resource: str | None = None) -> ExchangedToken:
        if not principal.token:
            raise TokenExchangeError("NO_SUBJECT_TOKEN",
                                     "this call carries no user token to act on behalf of (use the HTTP gateway "
                                     "with a bearer token)")
        return await self.exchanger.exchange(principal.token, audience=audience, scopes=scopes, resource=resource)
