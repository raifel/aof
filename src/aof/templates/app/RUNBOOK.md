# Runbook: {{app_title}}

- **Owner:** {{owner}}
- **On-call rota:** {{on_call}}
- **Agent identity:** `agent:{{app_name}}`

## Kill switch

Stops every call from this agent at the gateway within one minute. It does not need a deploy.

1. Disable the agent in the gateway: `TODO: gateway command, e.g. agentctl disable agent:{{app_name}}`.
2. Confirm in traces that no new spans arrive for `agent:{{app_name}}`.
3. Post in the incident channel and page {{on_call}}.
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
