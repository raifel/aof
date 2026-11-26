"""Human approvals: one action, one approval (ASI09: no bulk approvals).

Flow:
  1. The agent calls a tool whose decision is require_approval.
  2. The gateway runs the tool with dry_run=true (when the tool supports it), stores
     a pending Approval with that preview, and tells the agent to wait.
  3. A human approves or rejects that one approval id.
  4. The agent repeats the same call with `aof_approval_id`. The gateway checks it
     is approved, unexpired, unused, for the same user, tool and arguments, then
     executes it exactly once.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .audit import args_digest
from .identity import Principal
from .state import Store

APPROVAL_ARG = "aof_approval_id"
_IGNORED_ARGS = {"dry_run", APPROVAL_ARG}


def approval_digest(args: dict[str, Any]) -> str:
    return args_digest({k: v for k, v in args.items() if k not in _IGNORED_ARGS})


@dataclass
class Approval:
    id: str
    agent_id: str
    tool: str
    user_id: str
    run_id: str
    args: dict[str, Any]
    args_hash: str
    preview: Any
    approver_role: str | None
    created_at: float
    expires_at: float
    status: str = "pending"  # pending | approved | rejected | consumed
    decided_by: str | None = None
    decided_at: float | None = None
    note: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class ApprovalService:
    """Approvals live in the gateway store, so any replica can request, decide or consume
    them. Decide and consume are atomic read-modify-writes: an approval is used once."""

    RETENTION_S = 7 * 24 * 3600  # kept this long after expiry, for operators and audits

    def __init__(self, store: Store, ttl_seconds: int = 3600):
        self.store = store
        self.ttl = ttl_seconds

    def request(self, *, agent_id: str, tool: str, principal: Principal, run_id: str,
                args: dict[str, Any], preview: Any, approver_role: str | None,
                now: float | None = None) -> Approval:
        now = now or time.time()
        a = Approval(
            id="apr_" + secrets.token_hex(8), agent_id=agent_id, tool=tool, user_id=principal.user_id,
            run_id=run_id, args=args, args_hash=approval_digest(args), preview=preview,
            approver_role=approver_role, created_at=now, expires_at=now + self.ttl,
        )
        self.store.put("approvals", a.id, asdict(a), ttl=self.ttl + self.RETENTION_S)
        return a

    def get(self, approval_id: str) -> Approval | None:
        raw = self.store.get("approvals", approval_id)
        return Approval(**raw) if raw else None

    def list(self, status: str | None = None) -> list[Approval]:
        items = [Approval(**r) for r in self.store.all("approvals").values()]
        return sorted((a for a in items if status is None or a.status == status), key=lambda a: a.created_at)

    def _transition(self, approval_id: str, check) -> Approval:
        out: list[Approval] = []

        def fn(raw):
            if raw is None:
                raise ApprovalError("APPROVAL_NOT_FOUND", f"no approval {approval_id}")
            a = Approval(**raw)
            check(a)  # raises ApprovalError, or mutates a
            out.append(a)
            return asdict(a)

        self.store.update("approvals", approval_id, fn)
        return out[-1]

    def _decide(self, approval_id: str, approver: Principal, status: str, note: str | None,
                now: float | None) -> Approval:
        now = now or time.time()

        def check(a: Approval) -> None:
            if a.status != "pending":
                raise ApprovalError("APPROVAL_NOT_PENDING", f"approval is {a.status}")
            if now > a.expires_at:
                raise ApprovalError("APPROVAL_EXPIRED", "approval request expired")
            if a.approver_role and a.approver_role not in approver.roles:
                raise ApprovalError("APPROVER_ROLE", f"approver needs role {a.approver_role}")
            if approver.user_id == a.user_id:
                raise ApprovalError("SELF_APPROVAL", "the requesting user cannot decide their own action")
            a.status, a.decided_by, a.decided_at, a.note = status, approver.user_id, now, note
            a.history.append({"status": status, "by": approver.user_id, "at": now})

        return self._transition(approval_id, check)

    def approve(self, approval_id: str, approver: Principal, note: str | None = None,
                now: float | None = None) -> Approval:
        return self._decide(approval_id, approver, "approved", note, now)

    def reject(self, approval_id: str, approver: Principal, note: str | None = None,
               now: float | None = None) -> Approval:
        return self._decide(approval_id, approver, "rejected", note, now)

    def consume(self, approval_id: str, *, agent_id: str, tool: str, principal: Principal,
                args: dict[str, Any], now: float | None = None) -> Approval:
        """Single use: marks the approval consumed if it matches this exact call."""
        now = now or time.time()

        def check(a: Approval) -> None:
            if a.status == "pending":
                raise ApprovalError("APPROVAL_PENDING", "still waiting for a human decision")
            if a.status != "approved":
                raise ApprovalError("APPROVAL_NOT_USABLE", f"approval is {a.status}")
            if now > a.expires_at:
                raise ApprovalError("APPROVAL_EXPIRED", "approval expired; request a new one")
            if (a.agent_id, a.tool, a.user_id) != (agent_id, tool, principal.user_id):
                raise ApprovalError("APPROVAL_MISMATCH", "approval is for a different agent, tool or user")
            if a.args_hash != approval_digest(args):
                raise ApprovalError("APPROVAL_MISMATCH", "arguments differ from what was approved")
            a.status = "consumed"
            a.history.append({"status": "consumed", "at": now})

        return self._transition(approval_id, check)
