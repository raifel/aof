"""Who is calling: the human the agent acts for, with their scopes and roles.

User-facing agents act on behalf of the signed-in user, so every decision is made
against the user's scopes, never a shared service account. In production the
principal comes from a JWT verified by `jwt_verifier.JwtVerifier`. The
StaticTokenVerifier below is for local development only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Principal:
    user_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    tenant: str | None = None
    # The caller's verified bearer token: the subject token for on-behalf-of exchange.
    # Never logged, compared or serialised.
    token: str | None = field(default=None, repr=False, compare=False)

    @classmethod
    def of(cls, user_id: str, scopes=(), roles=(), tenant: str | None = None,
           token: str | None = None) -> "Principal":
        return cls(user_id, frozenset(scopes), frozenset(roles), tenant, token)


def principal_from_access_token(token) -> Principal:
    """Map an MCP SDK AccessToken (verified bearer token) to a Principal."""
    claims = token.claims or {}
    return Principal.of(
        user_id=token.subject or token.client_id,
        scopes=token.scopes,
        roles=claims.get("roles", []),
        tenant=claims.get("tenant"),
        token=token.token,
    )


class StaticTokenVerifier:
    """DEV ONLY. Maps opaque bearer tokens to identities from a JSON file:

    {"<token>": {"subject": "alice", "scopes": ["orders:read"], "roles": ["support-lead"]}}

    Production uses jwt_verifier.JwtVerifier (signature, issuer, audience, expiry).
    """

    def __init__(self, path: str | Path):
        self._tokens: dict[str, dict] = json.loads(Path(path).read_text())

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        entry = self._tokens.get(token)
        if entry is None:
            return None
        return AccessToken(
            token=token,
            client_id=entry.get("client_id", "aof-dev"),
            scopes=list(entry.get("scopes", [])),
            subject=entry["subject"],
            claims={"roles": entry.get("roles", []), "tenant": entry.get("tenant")},
        )
