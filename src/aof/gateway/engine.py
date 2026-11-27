"""Policy engine: one decision per tool call. No I/O beyond the gateway state.

Slots that must not be oversold across replicas (rate-limit windows, write limits) are
taken atomically here, at the moment of the decision. A taken write slot is reported in
`Verdict.details["write_slot"]` so the core does not count that write again.

Checks, in order (first failure wins):
  1. kill switch              5. per-run budgets (steps, cost, delegation depth)
  2. tool in policy           6. rate limit
  3. effective decision       7. limits (within_limits writes escalate to approval)
     (demotion applied)       8. approval or allow (+ sampled review)
  4. user holds the scopes
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..enums import AutonomyLevel, READ_ONLY_LEVELS
from .compiled import CompiledPolicy, Decision, ToolRule
from .identity import Principal
from .state import GatewayState, RunState


class Action(str, Enum):
    ALLOW = "allow"
    APPROVAL = "approval_required"
    DENY = "deny"


@dataclass
class Verdict:
    action: Action
    code: str
    reason: str
    rule: ToolRule | None = None
    violation: bool = False  # counts toward the policy-violation SLO
    sampled: bool = False  # selected for human review after the fact
    hint: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


def effective_level(policy: CompiledPolicy, state: GatewayState) -> AutonomyLevel:
    demoted = state.demoted_level(policy.agent.id)
    level = policy.agent.autonomy_level
    return min(level, demoted) if demoted is not None else level


def effective_decision(rule: ToolRule, level: AutonomyLevel) -> tuple[Decision, str]:
    """Apply the current (possibly demoted) level on top of the compiled decision."""
    if rule.decision == "deny":
        return "deny", rule.reason or "denied by policy"
    if rule.access == "read":
        return rule.decision, rule.reason
    if level in READ_ONLY_LEVELS:
        return "deny", f"autonomy level {level.value} is read-only"
    if level is AutonomyLevel.L2 and rule.decision == "allow_within_limits":
        return "require_approval", "at L2 a human approves every write"
    return rule.decision, rule.reason


class PolicyEngine:
    def __init__(self, policy: CompiledPolicy, state: GatewayState, rng: random.Random | None = None):
        self.policy = policy
        self.state = state
        self.rng = rng or random.Random()

    @property
    def agent_id(self) -> str:
        return self.policy.agent.id

    def evaluate(self, principal: Principal, tool: str, args: dict[str, Any], run: RunState,
                 now: float, delegation_depth: int = 0, step: int | None = None) -> Verdict:
        """`step` is this call's number in the run, already counted by the caller (atomic
        across replicas); without it the engine assumes the next one."""
        p, b = self.policy, self.policy.budgets

        killed = self.state.killed(self.agent_id)
        if killed:
            return Verdict(Action.DENY, "KILL_SWITCH", f"agent disabled by {killed['by']}: {killed['reason']}")

        rule = p.rule(tool)
        if rule is None:
            return Verdict(Action.DENY, "UNKNOWN_TOOL", f"{tool} is not in this agent's policy (default deny)",
                           violation=True)

        decision, why = effective_decision(rule, effective_level(p, self.state))
        if decision == "deny":
            return Verdict(Action.DENY, "DENIED_BY_POLICY", why, rule, violation=rule.risk_tier.value == "T4")

        missing = sorted(set(rule.scopes) - principal.scopes)
        if missing:
            return Verdict(Action.DENY, "MISSING_SCOPE", f"user {principal.user_id} lacks {', '.join(missing)}",
                           rule, violation=True, hint="the user must hold these scopes; the agent cannot borrow them")

        step = run.steps + 1 if step is None else step
        if step > b.max_steps_per_run:
            return Verdict(Action.DENY, "STEP_BUDGET", f"run used {b.max_steps_per_run}/{b.max_steps_per_run} steps",
                           rule, hint="stop and summarise progress for the user")
        if run.cost_usd >= b.max_cost_usd_per_run:
            return Verdict(Action.DENY, "COST_BUDGET",
                           f"run cost ${run.cost_usd:.2f} reached the ${b.max_cost_usd_per_run:.2f} cap", rule)
        if delegation_depth > b.max_delegation_depth:
            return Verdict(Action.DENY, "DELEGATION_DEPTH",
                           f"delegation depth {delegation_depth} exceeds {b.max_delegation_depth}", rule)

        key = (self.agent_id, principal.user_id, tool)
        if rule.rate_limit:
            ok, used = self.state.calls.acquire(key, rule.rate_limit.window_seconds, rule.rate_limit.calls, now)
            if not ok:
                return Verdict(Action.DENY, "RATE_LIMITED",
                               f"{used} calls in the last {rule.rate_limit.per}; limit {rule.rate_limit.calls}",
                               rule, hint=f"retry after the current {rule.rate_limit.per}")

        if decision == "allow_within_limits":
            breach = self._limit_breach(rule, args, key, now)
            if breach:
                return Verdict(Action.APPROVAL, "LIMIT_EXCEEDED", f"{breach}: needs human approval", rule)
            return Verdict(Action.ALLOW, "WITHIN_LIMITS", "auto-executed within limits", rule,
                           details={"write_slot": (rule.limits or {}).get("max_per_hour") is not None})

        if decision == "require_approval":
            return Verdict(Action.APPROVAL, "APPROVAL_REQUIRED", why or "human approval required", rule)

        sampled = rule.sample_rate is not None and self.rng.random() < rule.sample_rate
        return Verdict(Action.ALLOW, "ALLOWED", why or "allowed", rule, sampled=sampled)

    def _limit_breach(self, rule: ToolRule, args: dict[str, Any], key: tuple, now: float) -> str | None:
        limits = rule.limits or {}
        max_amount = limits.get("max_amount")
        amount = args.get("amount")
        if max_amount is not None:
            if not isinstance(amount, (int, float)):
                return "amount missing or not numeric"
            if amount > max_amount:
                # The amount may come from a vault reference the agent never saw: don't echo it.
                return f"amount exceeds limit {max_amount}"
        max_per_hour = limits.get("max_per_hour")
        if max_per_hour is not None:
            ok, _ = self.state.writes.acquire(key, 3600, max_per_hour, now)  # last check: takes the slot
            if not ok:
                return f"{max_per_hour} writes in the last hour"
        return None
