# Roadmap

Where the kit stands and what each remaining step needs. Updated 2026-11-26.

**Done:** the contract kit and CLI, the seven gates, and the gateway (MCP, LLM and A2A
paths, on-behalf-of token exchange, JWT identity and admin API, multi-replica state).
Also `aof eval`, `aof gateway pilot-report` and the opt-in live tests. All of it is
tested against fakes only (fakeredis, a fake IdP, a scripted model); none of it has
run against real services yet.

**Example app:** `examples/refunds-assistant` passes gates 1 to 6 and fails promote
(review board sign-off). Its `results.json` and `pilot.json` are hand-written sample
numbers, not measured ones.

## 1. Check against real services (next)

| # | Step | Needs from you | Cost | Status |
|---|------|----------------|------|--------|
| 1.1 | Redis live tests: store contract, cross-client race | `AOF_LIVE_REDIS_URL` (Redis 6.0+; a spare DB number is fine) | free | waiting on URL |
| 1.2 | IdP live tests: verify a real token, reject a tampered one | `AOF_LIVE_ISSUER`, `AOF_LIVE_AUDIENCE`, `AOF_LIVE_TOKEN` (a current access token), optionally `AOF_LIVE_ROLES_CLAIM` | free | waiting on IdP details |
| 1.3 | Token exchange at the IdP (RFC 8693) | an IdP client allowed to exchange tokens: `AOF_LIVE_TOKEN_ENDPOINT`, `AOF_LIVE_CLIENT_ID`, `AOF_LIVE_CLIENT_SECRET`, `AOF_LIVE_OBO_AUDIENCE` | free | needs IdP admin setup; optional if you don't use OBO yet |
| 1.4 | Claude through the gateway (plain and streamed, allowlist holds) | `ANTHROPIC_API_KEY`, your go-ahead | under a cent | waiting on key |
| 1.5 | First real eval: `aof eval examples/refunds-assistant --limit 5` | key, go-ahead | expected well under $1 (not measured yet) | waiting on 1.4 |
| 1.6 | Full eval, 70 cases, replacing the hand-written `results.json` | go-ahead after 1.5, using its measured cost per case | measured in 1.5 | waiting on 1.5 |

What 1.5 should tell us: whether a real model handles writes held for approval,
returns the final JSON verdict, and stays within step and cost budgets. Expect to
tune the reference agent's system prompt or the tool descriptions.

## 2. Decisions (yours or the platform team's)

| # | Decision | Blocks | Who |
|---|----------|--------|-----|
| 2.1 | Pin `telemetry.genai_semconv_version` in `platform.yaml` | clears the P030 warning; dashboards depend on stable span names | platform team |
| 2.2 | Calibrate `platform.yaml` thresholds (eval scores, pilot window and agreement, budgets, rate limits) | real gate decisions; needs measured numbers from 1.6 and the lighthouse wave | platform team |
| 2.3 | Orchestrator: agentgateway or extend your existing API gateway | step 3.3 | architecture |
| 2.4 | Pick the lighthouse apps | 2.2, real pilots | platform team and app owners |
| 2.5 | Review board membership and SLA | promote gate for T3 or L3+ in practice | governance |
| 2.6 | Pin the official MCP Registry `server.json` schema version | step 3.2 | platform team |

## 3. Remaining platform pieces (build)

| # | Piece | What it does | Needs first |
|---|-------|--------------|-------------|
| 3.1 | AgentOps dashboard (recommended next build) | Shows denials by code, pending approvals, spend per run and per agent, demotions and kill switches, eval and pilot results over time. Reads the audit logs and the state store. | nothing (2.1 helps for OTel views) |
| 3.2 | Internal MCP registry service | Publish and look up `server.json` and tool manifests; full validation against the official schema | 2.6 |
| 3.3 | Runtime / orchestrator | Hosts agents behind the gateway; the largest piece | 2.3 |

## 4. Hardening found by the threat model and ops docs

From [docs/threat-model.md](docs/threat-model.md), [docs/observability.md](docs/observability.md)
and [docs/deployment.md](docs/deployment.md). Ordered by risk.

| # | Feature | Why | Size |
|---|---------|-----|------|
| 4.1 | Stable `STATE_UNAVAILABLE` error, audited, when the state store is down | today the call fails closed but with an unhandled error, no code and no audit record; breaks the "every decision audited" rule | small |
| 4.2 | Gateway-issued run ids (or a signed run context) and trusted delegation depth | per-run budgets trust the caller's run id and depth; an agent can reset them | medium |
| 4.3 | Audit shipping to WORM storage, external anchoring of chain heads, file rotation | the hash chain can't detect a truncated tail or a fully rewritten file | medium |
| 4.4 | Deployment kit: container image, Helm chart, NetworkPolicy (agent reaches only the gateway), example OTel config | the reference layout exists only as a doc | medium |
| 4.5 | A2A spans; OTel metrics (denials by code, spend, approvals pending) | A2A calls are audited but not traced; metrics today are derived by hand | small |
| 4.6 | Alert rules for the signals in observability.md | nothing alerts yet | small, part of 3.1 |
| 4.7 | Redis hardening guide: ACL user per gateway, TLS; optionally signed kill-switch and approval records | anyone with Redis write access can clear the kill switch | small (guide) / medium (signing) |
| 4.8 | Sender-constrained tokens (DPoP or mTLS) and optional introspection for revocation | stolen bearer tokens work until expiry | large |
| 4.9 | mTLS between gateways and signed agent card verification | A2A relies on edge TLS and an unsigned card | medium |
| 4.10 | Optional guardrail hook for content (prompt-injection and output checks) | the gateway limits blast radius but doesn't inspect content | medium |

## 5. Known limits to revisit later

See "Not built yet" in the README for the full list. The ones most likely to matter first:

- A2A: no agent card signature verification, no mTLS between gateways.
- Identity: no opaque tokens (introspection), no revocation before `exp`, no DPoP.
- On-behalf-of: client secret only, no `actor_token`.
- LLM: Anthropic only; one call can overshoot the cost cap.
- Evals: cases run one at a time; the prose judge has no calibration set.

## Suggested order

1.1 and 1.2 (free), then 1.4 and 1.5 (small spend), then 2.1 (cheap to decide), then 4.1
and 4.2 (small, close real gaps), then 3.1 with 4.5 and 4.6, while 1.6 and 2.2 to 2.5 are
in progress.

## Design documents

- [docs/architecture.md](docs/architecture.md): components, request flows, state
- [docs/deployment.md](docs/deployment.md): deployment and network diagrams, network policy
- [docs/threat-model.md](docs/threat-model.md): STRIDE by trust boundary, OWASP ASI mapping, residual risks
- [docs/observability.md](docs/observability.md): audit events, integrity, traces, what to watch
