# Runbook: Ledger Analyst

- **Owner:** finance-systems
- **On-call rota:** finance-systems-oncall
- **Agent identity:** `agent:ledger-analyst`

## Kill switch

Stops every call from this agent at the gateway within one minute. It does not need a deploy.

1. Disable the agent in the gateway: `aof gateway admin disable agent:ledger-analyst`.
2. Confirm in traces that no new spans arrive for `agent:ledger-analyst`.
3. Post in the incident channel and page finance-systems-oncall.
4. To restore, re-enable it at the *current approved* autonomy level only. Re-promotion goes through the gates.

## Autonomy demotion

The gateway lowers the level by one if an SLO stays breached for the demotion window.
Investigate with the traces before you ask the review board to restore the level.

## Common failures

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `QUERY_NEEDS_CLARIFICATION` | The question names no company | Expected: the agent asks the user |
| `SQL_FILTER_NOT_ALLOWED` | A query filtered on a hidden column (amounts) | Expected: the guard stops value bisection |
| `DATA_EGRESS_BLOCKED` | A vaulted figure appeared in a model request | Check the audit record's `egress` field and the agent's prompt; possible leak path |
| Empty results for a company | The row filter: the user's tenant claim doesn't include it | Check the IdP claim, not the query |
| Stale figures | A data product broke its freshness SLA | Check the data contract owner's pipeline |
