# Runbook: Refunds Assistant

- **Owner:** payments-support
- **On-call rota:** payments-support-oncall
- **Agent identity:** `agent:refunds-assistant`

## Kill switch

Stops every call from this agent at the gateway within one minute. It does not need a deploy.

1. Disable the agent in the gateway: `TODO: gateway command, e.g. agentctl disable agent:refunds-assistant`.
2. Confirm in traces that no new spans arrive for `agent:refunds-assistant`.
3. Post in the incident channel and page payments-support-oncall.
4. To restore, re-enable it at the *current approved* autonomy level only. Re-promotion goes through the gates.

## Autonomy demotion

The gateway lowers the level by one if an SLO stays breached for the demotion window.
Investigate with the traces before you ask the review board to restore the level.

## Common failures

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Tool calls denied | Tool missing from the compiled policy | Run `aof validate`, then recompile the policy |
| Stale answers | Data product broke its freshness SLA | Check the data contract owner's pipeline |
| Cost spike | Loops or retries | Check step budgets in the traces; use the kill switch if needed |
