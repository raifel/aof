"""Result vault: tool results the model must not see, held at the gateway (docs/data-safety.md).

The agent gets a handle (`res_...`); the user's UI reads the rows with `GET /results/{handle}`.
Identifiers the agent must pass between tools are replaced by tokens (`tok_...`) that
the gateway swaps back for the real value in the next upstream call, for the same user
and run only.

Values are encrypted at rest with AES-GCM under `AOF_VAULT_KEY` (32 bytes, base64), so a
shared Redis holds ciphertext only. Every record is bound to its owner (user and
tenant); a handle or token of another user resolves to nothing. Records expire after
`vault.ttl_seconds`.

Use a Store of its own (a separate Redis prefix and ACL user from the gateway state), so
that a credential for kill switches and counters does not also read results.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .identity import Principal
from .state import DurableStore, Store

KEY_ENV = "AOF_VAULT_KEY"
TOKEN_RE = re.compile(r"^tok_[0-9a-f]{20}$")
_RESULTS, _TOKENS = "vault_results", "vault_tokens"


class VaultError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def load_key(value: str | None = None) -> bytes:
    raw = value if value is not None else os.environ.get(KEY_ENV)
    if not raw:
        raise VaultError("VAULT_KEY_MISSING", f"set {KEY_ENV} to 32 random bytes, base64-encoded")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError:
        raise VaultError("VAULT_KEY_INVALID", f"{KEY_ENV} is not base64") from None
    if len(key) != 32:
        raise VaultError("VAULT_KEY_INVALID", f"{KEY_ENV} must decode to 32 bytes, got {len(key)}")
    return key


def new_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


@dataclass(frozen=True)
class StoredResult:
    handle: str
    tool: str
    run_id: str
    created_at: float
    expires_at: float
    meta: dict[str, Any]  # columns and exposures: metadata, not values
    content: Any


class ResultVault:
    def __init__(self, store: Store | None = None, key: bytes | None = None, *, ttl_seconds: int = 3600,
                 max_bytes: int = 5_000_000, clock=time.time):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.store = store or DurableStore()
        self.ephemeral = key is None  # a per-process key: fine for one replica, lost on restart
        self._key = key or secrets.token_bytes(32)
        self._aead = AESGCM(self._key)
        self._mac_key = hmac.new(self._key, b"aof-vault-token", hashlib.sha256).digest()
        self.ttl = ttl_seconds
        self.max_bytes = max_bytes
        self.clock = clock
        self._puts = 0

    def _sweep(self) -> None:
        """Drop expired records. Redis expires them itself; the in-memory store doesn't."""
        self._puts += 1
        if self._puts % 100 or not isinstance(self.store, DurableStore):
            return
        now = self.clock()
        for ns in (_RESULTS, _TOKENS):
            for key, rec in self.store.all(ns).items():
                if rec.get("expires_at", 0) < now:
                    self.store.delete(ns, key)

    # ------------------------------------------------------------------ crypto

    def _seal(self, value: Any, aad: str) -> str:
        nonce = secrets.token_bytes(12)
        data = json.dumps(value, default=str, separators=(",", ":")).encode()
        if len(data) > self.max_bytes:
            raise VaultError("RESULT_TOO_LARGE", f"result is {len(data)} bytes; the limit is {self.max_bytes}")
        return base64.b64encode(nonce + self._aead.encrypt(nonce, data, aad.encode())).decode()

    def _open(self, sealed: str, aad: str) -> Any:
        raw = base64.b64decode(sealed)
        return json.loads(self._aead.decrypt(raw[:12], raw[12:], aad.encode()))

    @staticmethod
    def _owner(principal: Principal) -> dict[str, Any]:
        return {"user": principal.user_id, "tenant": principal.tenant}

    # ------------------------------------------------------------------ results

    def put(self, principal: Principal, *, agent_id: str, run_id: str, tool: str, content: Any,
            meta: dict[str, Any] | None = None) -> str:
        self._sweep()
        handle = "res_" + secrets.token_hex(12)
        now = self.clock()
        self.store.put(_RESULTS, handle, {
            **self._owner(principal), "agent": agent_id, "run_id": run_id, "tool": tool,
            "created_at": now, "expires_at": now + self.ttl, "meta": meta or {},
            "sealed": self._seal(content, handle),
        }, ttl=self.ttl)
        return handle

    def get(self, handle: str, principal: Principal) -> StoredResult:
        """The result, if it exists, hasn't expired and belongs to this user and tenant."""
        rec = self.store.get(_RESULTS, handle) if handle.startswith("res_") else None
        if rec is None or rec["expires_at"] < self.clock() or rec.get("user") != principal.user_id \
                or rec.get("tenant") != principal.tenant:
            raise VaultError("RESULT_NOT_FOUND", "no such result for this user (or it expired)")
        return StoredResult(handle, rec["tool"], rec["run_id"], rec["created_at"], rec["expires_at"],
                            rec.get("meta", {}), self._open(rec["sealed"], handle))

    # ------------------------------------------------------------------ tokens

    def tokenize(self, principal: Principal, run_id: str, column: str, value: Any) -> str:
        """A stable token for this value within the run; the same value gets the same token."""
        if value is None:
            return None  # type: ignore[return-value]
        msg = json.dumps([run_id, principal.user_id, column, value], default=str).encode()
        token = "tok_" + hmac.new(self._mac_key, msg, hashlib.sha256).hexdigest()[:20]
        key = f"{run_id}:{token}"
        if self.store.get(_TOKENS, key) is None:
            self.store.put(_TOKENS, key, {**self._owner(principal), "expires_at": self.clock() + self.ttl,
                                          "sealed": self._seal(value, key)}, ttl=self.ttl)
        return token

    def resolve(self, token: str, principal: Principal, run_id: str) -> tuple[bool, Any]:
        """(found, value) for a token minted in this run for this user."""
        if not TOKEN_RE.match(token):
            return False, None
        key = f"{run_id}:{token}"
        rec = self.store.get(_TOKENS, key)
        if rec is None or rec["expires_at"] < self.clock() or rec.get("user") != principal.user_id \
                or rec.get("tenant") != principal.tenant:
            return False, None
        return True, self._open(rec["sealed"], key)

    def detokenize(self, value: Any, principal: Principal, run_id: str) -> Any:
        """Replace every string that is exactly a known token, anywhere in a JSON value."""
        if isinstance(value, str):
            found, real = self.resolve(value, principal, run_id)
            return real if found else value
        if isinstance(value, dict):
            return {k: self.detokenize(v, principal, run_id) for k, v in value.items()}
        if isinstance(value, list):
            return [self.detokenize(v, principal, run_id) for v in value]
        return value
