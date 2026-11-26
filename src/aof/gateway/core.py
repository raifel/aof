"""The gateway core: every tool call from an agent passes through `Gateway.call_tool`.

Transport-free: `mcp_proxy.py` puts an MCP server in front of it and MCP clients
behind it, but tests and other transports can drive it directly.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from ..enums import AutonomyLevel
from .approvals import APPROVAL_ARG, ApprovalError, ApprovalService
from .audit import AuditLog, args_digest
from .compiled import CompiledPolicy
from .engine import Action, PolicyEngine, Verdict, effective_decision, effective_level
from .identity import Principal
from .obo import OboBroker, TokenExchangeError
from .state import GatewayState
from .telemetry import tool_span


@dataclass
class ToolResult:
    content: Any  # JSON-able payload returned to the agent
    is_error: bool = False


@dataclass
class UpstreamTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: Any = None


class Upstream(Protocol):
    """The app's tool server. With on-behalf-of exchange the gateway passes `token=`, the
    exchanged per-user access token; without it the upstream uses its own connection."""

    async def list_tools(self, **kw: Any) -> list[UpstreamTool]: ...

    async def call_tool(self, name: str, args: dict[str, Any], **kw: Any) -> ToolResult: ...


def _deny_payload(v: Verdict) -> dict[str, Any]:
    out = {"error": v.code, "reason": v.reason}
    if v.hint:
        out["hint"] = v.hint
    return out


class Gateway:
    def __init__(self, policy: CompiledPolicy, upstream: Upstream, *, state: GatewayState | None = None,
                 audit: AuditLog | None = None, approvals: ApprovalService | None = None,
                 auto_demote: bool = True, clock=time.time, obo: OboBroker | None = None):
        self.policy = policy
        self.upstream = upstream
        self.state = state or GatewayState()
        self.audit = audit or AuditLog()
        self.approvals = approvals or ApprovalService(self.state.store)
        self.engine = PolicyEngine(policy, self.state)
        self.auto_demote = auto_demote
        self.clock = clock
        self.obo = obo  # on-behalf-of token exchange towards the upstream app

    @property
    def agent_id(self) -> str:
        return self.policy.agent.id

    # ------------------------------------------------------------------ discovery

    async def visible_tools(self, principal: Principal) -> list[UpstreamTool]:
        """Only tools this user could call right now. Approval-gated tools gain aof_approval_id."""
        if self.state.killed(self.agent_id):
            return []
        level = effective_level(self.policy, self.state)
        try:
            kw, _ = await self._credential(principal, ())
        except TokenExchangeError as exc:
            self.audit.append("token_exchange_failed", agent=self.agent_id, user=principal.user_id,
                              operation="list_tools", code=exc.code, reason=str(exc))
            return []
        out = []
        for t in await self.upstream.list_tools(**kw):
            rule = self.policy.rule(t.name)
            if rule is None:
                continue  # served but not in policy: hidden and denied
            decision, _ = effective_decision(rule, level)
            if decision == "deny" or not set(rule.scopes) <= principal.scopes:
                continue
            schema = dict(t.input_schema or {"type": "object", "properties": {}})
            if decision in ("require_approval", "allow_within_limits"):
                props = dict(schema.get("properties") or {})
                props[APPROVAL_ARG] = {
                    "type": "string",
                    "description": "Approval id returned by the gateway; pass it when retrying an approved call.",
                }
                schema["properties"] = props
            out.append(UpstreamTool(t.name, t.description, schema, t.annotations))
        return out

    # ------------------------------------------------------------------ calls

    async def call_tool(self, principal: Principal, tool: str, args: dict[str, Any] | None, *,
                        run_id: str, delegation_depth: int = 0, call_id: str | None = None) -> ToolResult:
        args = dict(args or {})
        approval_id = args.pop(APPROVAL_ARG, None)
        call_id = call_id or uuid.uuid4().hex[:16]
        now = self.clock()
        run = self.state.run(run_id, now)
        base = {"agent": self.agent_id, "user": principal.user_id, "run_id": run_id, "call_id": call_id,
                "tool": tool, "args_sha256": args_digest(args), "arg_keys": sorted(args)}

        with tool_span(tool, agent_id=self.agent_id, call_id=call_id, run_id=run_id,
                       user_id=principal.user_id) as span:
            # Count the step first (atomic across replicas), then decide; kill-switch denials are free.
            step = None if self.state.killed(self.agent_id) else int(run.add("steps"))
            verdict = self.engine.evaluate(principal, tool, args, run, now, delegation_depth, step=step)
            span.set_attribute("aof.decision", verdict.action.value)
            span.set_attribute("aof.code", verdict.code)
            if verdict.rule:
                span.set_attribute("aof.risk_tier", verdict.rule.risk_tier.value)

            if verdict.action is Action.DENY:
                span.set_error(verdict.code)
                self.audit.append("tool_denied", **base, code=verdict.code, reason=verdict.reason)
                if verdict.violation:
                    self.record_violation(now)
                return ToolResult(_deny_payload(verdict), is_error=True)

            if verdict.action is Action.APPROVAL:
                if args.get("dry_run") is True and verdict.rule.dry_run_preview and approval_id is None:
                    verdict.code = "DRY_RUN"  # a preview has no side effects; no approval needed
                    return await self._execute(principal, tool, args, verdict, base, span, now)
                if approval_id is None:
                    return await self._request_approval(principal, tool, args, run_id, verdict, base, span, now)
                try:
                    approval = self.approvals.consume(approval_id, agent_id=self.agent_id, tool=tool,
                                                      principal=principal, args=args, now=now)
                except ApprovalError as exc:
                    span.set_error(exc.code)
                    self.audit.append("approval_refused", **base, approval_id=approval_id, code=exc.code,
                                      reason=str(exc))
                    return ToolResult({"error": exc.code, "reason": str(exc), "approval_id": approval_id},
                                      is_error=True)
                span.set_attribute("aof.approval_id", approval.id)
                return await self._execute(principal, tool, args, verdict, base, span, now,
                                           approved_by=approval.decided_by, approval_id=approval.id)

            return await self._execute(principal, tool, args, verdict, base, span, now)

    async def _request_approval(self, principal, tool, args, run_id, verdict, base, span, now) -> ToolResult:
        rule = verdict.rule
        preview = None
        if rule.dry_run_preview:
            try:
                kw, _ = await self._credential(principal, rule.scopes)
            except TokenExchangeError as exc:
                return self._exchange_failed(exc, base, span)
            dry = await self.upstream.call_tool(tool, {**args, "dry_run": True}, **kw)
            if dry.is_error:
                self.audit.append("dry_run_failed", **base)
                return ToolResult({"error": "DRY_RUN_FAILED", "reason": "the preview failed; fix the call first",
                                   "upstream": dry.content}, is_error=True)
            preview = dry.content
        approval = self.approvals.request(agent_id=self.agent_id, tool=tool, principal=principal, run_id=run_id,
                                          args=args, preview=preview, approver_role=rule.approver_role, now=now)
        span.set_attribute("aof.approval_id", approval.id)
        self.audit.append("approval_requested", **base, approval_id=approval.id, code=verdict.code,
                          reason=verdict.reason, approver_role=rule.approver_role)
        return ToolResult({
            "status": "approval_required",
            "approval_id": approval.id,
            "reason": verdict.reason,
            "approver_role": rule.approver_role,
            "preview": preview,
            "expires_at": approval.expires_at,
            "next": f"Tell the user it awaits approval. After approval, repeat the same call with "
                    f"{APPROVAL_ARG}='{approval.id}'. Do not change the arguments.",
        })

    async def _execute(self, principal, tool, args, verdict, base, span, now, *,
                       approved_by: str | None = None, approval_id: str | None = None) -> ToolResult:
        try:
            kw, credential = await self._credential(principal, verdict.rule.scopes)
        except TokenExchangeError as exc:
            return self._exchange_failed(exc, base, span)
        key = (self.agent_id, principal.user_id, tool)
        if verdict.rule.access == "write" and verdict.code != "DRY_RUN" and not verdict.details.get("write_slot"):
            self.state.writes.add(key, now, 3600)  # the engine already took a slot for within-limits writes
        if approval_id and verdict.rule.dry_run_preview:
            args = {**args, "dry_run": False}  # the approved action itself, not another preview
        try:
            result = await self.upstream.call_tool(tool, args, **kw)
        except Exception as exc:  # noqa: BLE001 - upstream failure is reported, never raised to the agent
            span.set_error("UPSTREAM_ERROR")
            self.audit.append("tool_failed", **base, code="UPSTREAM_ERROR", reason=str(exc))
            return ToolResult({"error": "UPSTREAM_ERROR", "reason": "the app's tool failed; try again later"},
                              is_error=True)
        if result.is_error:
            span.set_error("TOOL_ERROR")
        self.audit.append("tool_executed", **base, code=verdict.code, upstream_error=result.is_error,
                          sampled_for_review=verdict.sampled, approval_id=approval_id, approved_by=approved_by,
                          on_behalf_of=credential)
        return result

    async def _credential(self, principal: Principal, scopes) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Upstream call kwargs and an audit summary. Raises TokenExchangeError."""
        if self.obo is None:
            return {}, None
        token = await self.obo.for_upstream(principal, scopes)
        return {"token": token.access_token}, token.audit()

    def _exchange_failed(self, exc: TokenExchangeError, base: dict[str, Any], span) -> ToolResult:
        span.set_error(exc.code)
        self.audit.append("token_exchange_failed", **base, code=exc.code, reason=str(exc))
        return ToolResult({"error": exc.code, "reason": str(exc)}, is_error=True)

    # ------------------------------------------------------------------ budgets, SLOs

    def record_model_cost(self, run_id: str, usd: float) -> None:
        """Hook for the LLM path: model spend counts toward the per-run cost cap."""
        self.state.run(run_id).add("cost_usd", usd)

    def record_violation(self, now: float) -> None:
        key = (self.agent_id,)
        slos = self.policy.slos
        window = slos.demotion_window_hours * 3600
        self.state.violations.add(key, now, window)
        if not self.auto_demote or self.state.violations.count(key, window, now) <= slos.max_policy_violations:
            return
        current = effective_level(self.policy, self.state)
        if current is AutonomyLevel.L0:
            return
        lower = list(AutonomyLevel)[current.rank - 1]
        if not self.state.demote_from(self.agent_id, self.policy.agent.autonomy_level, current, lower,
                                      by="gateway", reason="policy-violation SLO breached"):
            return  # another replica demoted first
        self.state.violations.reset(key)  # fresh window at the new level
        self.audit.append("autonomy_demoted", agent=self.agent_id, from_level=current.value, to_level=lower.value,
                          reason="policy-violation SLO breached")
