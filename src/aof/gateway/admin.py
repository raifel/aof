"""Operator API: approvals, kill switch and demotion with a verified identity.

The local CLI commands (`aof gateway approve --by ...`) take the operator's identity on
trust and are for development. In production operators call these routes with an
IdP-issued token; `decided_by` / `by` comes from the token's subject.

  GET  /admin/approvals?status=pending   operators, or holders of a tool's approver role
  POST /admin/approvals/{id}/approve     the tool's approver role; never the requesting user
  POST /admin/approvals/{id}/reject      same
  POST /admin/kill      {"reason"}       operator role
  POST /admin/revive    {}               operator role
  POST /admin/demote    {"to","reason"}  operator role
  POST /admin/restore   {}               operator role

Every decision, allowed or refused, is written to the audit log with `verified: true`.
"""

from __future__ import annotations

from typing import Any

from ..enums import AutonomyLevel
from .approvals import ApprovalError
from .core import Gateway
from .identity import Principal, principal_from_access_token

_STATUS = {"APPROVAL_NOT_FOUND": 404, "APPROVER_ROLE": 403, "SELF_APPROVAL": 403}


def _approval_json(a) -> dict[str, Any]:
    return {k: getattr(a, k) for k in ("id", "agent_id", "tool", "user_id", "run_id", "args", "preview",
                                       "approver_role", "status", "created_at", "expires_at", "decided_by",
                                       "decided_at")}


def admin_routes(gateway: Gateway, token_verifier) -> list:
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    operator_role = gateway.policy.identity.operator_role
    approver_roles = {t.approver_role for t in gateway.policy.tools if t.approver_role}

    def fail(status: int, code: str, reason: str) -> JSONResponse:
        return JSONResponse({"error": code, "reason": reason}, status)

    async def principal(request: Request) -> Principal | None:
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else None
        access = await token_verifier.verify_token(token) if token else None
        return principal_from_access_token(access) if access else None

    async def body(request: Request) -> dict[str, Any]:
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def audit(event: str, who: Principal, **fields) -> None:
        gateway.audit.append(event, agent=gateway.agent_id, by=who.user_id, verified=True, **fields)

    def endpoint(handler, *, operator: bool):
        async def run(request: Request):
            who = await principal(request)
            if who is None:
                return fail(401, "UNAUTHENTICATED", "a valid operator token is required")
            if operator and operator_role not in who.roles:
                audit("admin_refused", who, action=handler.__name__, code="NOT_OPERATOR")
                return fail(403, "NOT_OPERATOR", f"requires role {operator_role}")
            data = await body(request)
            agent = data.get("agent")
            if agent is not None and agent != gateway.agent_id:
                return fail(409, "AGENT_MISMATCH", f"this gateway serves {gateway.agent_id}, not {agent}")
            return await handler(request, who, data)

        run.__name__ = handler.__name__
        return run

    async def list_approvals(request, who, data):
        if operator_role not in who.roles and not (approver_roles & who.roles):
            return fail(403, "NOT_APPROVER", "requires the operator role or a tool's approver role")
        status = request.query_params.get("status", "pending")
        items = gateway.approvals.list(None if status == "all" else status)
        if operator_role not in who.roles:  # approvers see what they may decide
            items = [a for a in items if a.approver_role in who.roles]
        return JSONResponse([_approval_json(a) for a in items if a.agent_id == gateway.agent_id])

    def decide(approve: bool):
        async def decide_approval(request, who, data):
            aid = request.path_params["approval_id"]
            a = gateway.approvals.get(aid)
            if a is not None and a.agent_id != gateway.agent_id:
                return fail(404, "APPROVAL_NOT_FOUND", f"no approval {aid} for this agent")
            try:
                fn = gateway.approvals.approve if approve else gateway.approvals.reject
                a = fn(aid, who, note=data.get("note"), now=gateway.clock())
            except ApprovalError as exc:
                audit("approval_refused", who, approval_id=aid, code=exc.code, reason=str(exc))
                return fail(_STATUS.get(exc.code, 409), exc.code, str(exc))
            audit("approval_decided", who, approval_id=a.id, tool=a.tool, user=a.user_id, decision=a.status,
                  decided_by=who.user_id)
            return JSONResponse(_approval_json(a))

        decide_approval.__name__ = "approve" if approve else "reject"
        return decide_approval

    async def kill(request, who, data):
        reason = data.get("reason")
        if not reason:
            return fail(400, "REASON_REQUIRED", "give a reason")
        gateway.state.kill(gateway.agent_id, by=who.user_id, reason=reason)
        audit("kill_switch_on", who, reason=reason)
        return JSONResponse({"agent": gateway.agent_id, "killed": True})

    async def revive(request, who, data):
        if not gateway.state.revive(gateway.agent_id):
            return fail(409, "NOT_KILLED", f"{gateway.agent_id} was not disabled")
        audit("kill_switch_off", who)
        return JSONResponse({"agent": gateway.agent_id, "killed": False})

    async def demote(request, who, data):
        try:
            level = AutonomyLevel(data.get("to"))
        except ValueError:
            return fail(400, "INVALID_LEVEL", "to must be one of " + ", ".join(lv.value for lv in AutonomyLevel))
        if not data.get("reason"):
            return fail(400, "REASON_REQUIRED", "give a reason")
        gateway.state.demote(gateway.agent_id, level, by=who.user_id, reason=data["reason"])
        audit("autonomy_demoted", who, to_level=level.value, reason=data["reason"])
        return JSONResponse({"agent": gateway.agent_id, "capped_at": level.value})

    async def restore(request, who, data):
        if not gateway.state.clear_demotion(gateway.agent_id):
            return fail(409, "NOT_DEMOTED", f"{gateway.agent_id} has no demotion")
        audit("autonomy_restored", who)
        return JSONResponse({"agent": gateway.agent_id, "capped_at": None})

    return [
        Route("/admin/approvals", endpoint(list_approvals, operator=False), methods=["GET"]),
        Route("/admin/approvals/{approval_id}/approve", endpoint(decide(True), operator=False), methods=["POST"]),
        Route("/admin/approvals/{approval_id}/reject", endpoint(decide(False), operator=False), methods=["POST"]),
        Route("/admin/kill", endpoint(kill, operator=True), methods=["POST"]),
        Route("/admin/revive", endpoint(revive, operator=True), methods=["POST"]),
        Route("/admin/demote", endpoint(demote, operator=True), methods=["POST"]),
        Route("/admin/restore", endpoint(restore, operator=True), methods=["POST"]),
    ]
