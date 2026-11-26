# AOF: Agentic Onboarding Framework

This kit implements the app-facing part of the
[AOF reference design](docs/AOF-Reference-Design.pdf). An app is
onboarded when its repo holds the seven contract artefacts and `aof validate` passes.
The policy compiler then turns its tool manifest into the policy the agent gateway
(`aof gateway`) enforces on every call.

```bash
uv venv && uv pip install -e '.[dev,gateway]'
aof init ../my-app --name my-app --owner my-team   # scaffold the seven artefacts
aof status ../my-app                                # where it is in the 7-stage lifecycle
aof validate ../my-app                              # what CI runs on every commit
aof compile-policy ../my-app -o gateway-policy.json
aof check-server ../my-app                          # live MCP server vs manifest
```

## How the design maps to code

| Design concept | Artefact in the app repo | Enforced by |
| --- | --- | --- |
| App root: tier, pattern, autonomy, sign-offs | `aof.yaml` | `models/project.py` |
| 1. MCP server | `src/server.py`, or `mcp_server.managed` | `conformance.py` (`aof check-server`) |
| 2. Registry entry | `server.json` (MCP Registry schema + `_meta…aof`) | `checks.check_registry` |
| 3. Tool manifest | `aof/tools.manifest.yaml` | `policy.py` + `lint.py` |
| 4. Data contracts | `aof/data-contracts/*.yaml` | `checks.check_data_contracts` |
| 5. Agent card (A2A) | `agent-card.json` (if `hosts_agent`) | `checks.check_agent_card` |
| 6. Eval suite | `evals/suite.yaml`, `golden.jsonl`, `safety.jsonl` | `checks.check_evals_static`, evaluate gate |
| 7. AGENTS.md + runbook | `AGENTS.md`, `RUNBOOK.md` (kill switch, on-call) | `checks.check_docs` |
| Intake / readiness | `aof/use-case.yaml`, `aof/readiness.yaml` | intake and readiness gates |
| Shadow pilot / eval scores | `evals/pilot.json`, `evals/results.json` | evaluate and pilot gates |
| Platform thresholds, budgets | `src/aof/platform.yaml` (platform team) | `--platform` to override |

## Lifecycle gates (`aof gate <stage>`, `aof status`)

| # | Stage | Gate passes when |
| --- | --- | --- |
| 1 | intake | `triage` is set in the use-case card with an assigned tier (not T4) |
| 2 | readiness | all six dimensions are scored and none is `not_ready` |
| 3 | pattern | architecture review signed off; `single_agent`/`multi_agent` carry a justification |
| 4 | build | `aof validate` has no errors |
| 5 | evaluate | ≥ 50 golden cases, red-team covers ASI01–ASI10, scores meet the tier's thresholds |
| 6 | pilot | the shadow window, proposal count, agreement rate and incidents meet the tier's thresholds |
| 7 | promote | build, evaluate and pilot pass; +1 level only; review board sign-off for T3 or L3+ |

Gates are stateless. Each run re-reads the artefacts, and sign-offs live in version control.

## Policy rules (fail the build)

| Code | Rule |
| --- | --- |
| P001 | A write tool must have an approval rule |
| P002 | A tool's tier cannot exceed the app's tier |
| P003 / P004 | T3 writes need `per_action` approval and a dry-run preview |
| P005 | T2 writes auto-execute only `within_limits`, and the limits must be defined |
| P006 / P007 | Writes are T2+; irreversible writes are T3 |
| P008–P010 | Writes declare reversibility, scopes and a rate limit |
| P011 | Code-running tools are sandboxed and never T1–T2 (ASI05) |
| P020 | An app cannot be onboarded at T4 |
| P021 / P022 | L0–L1 targets have no write tools; at L2 every write is `per_action` |
| P023 | L4 requires an A2A agent card |
| P025 | App budgets may only tighten the platform's |

The compiled policy defaults to deny. It enforces the **approved** level (`autonomy.current`),
not the requested one, so writes stay denied until promotion. T4 tools always compile to deny.
User-facing agents act on behalf of the signed-in user.

## Agent gateway (`aof gateway`)

The gateway sits between agents and an app's MCP server. Agents connect to it as an
MCP server. It shows each user only the tools they may call, and decides every call
against the compiled policy:

| # | Check | Denial code |
| --- | --- | --- |
| 1 | Kill switch | `KILL_SWITCH` |
| 2 | Tool is in the policy (default deny) | `UNKNOWN_TOOL` |
| 3 | Decision at the current level (demotions applied; T4 always denied) | `DENIED_BY_POLICY` |
| 4 | The user holds the tool's scopes (on-behalf-of; the agent cannot borrow them) | `MISSING_SCOPE` |
| 5 | Per-run budgets: steps, cost, delegation depth | `STEP_BUDGET`, `COST_BUDGET`, `DELEGATION_DEPTH` |
| 6 | Rate limit per user and tool | `RATE_LIMITED` |
| 7 | `within_limits` writes: amount and per-hour caps; over a limit escalates to approval | — |
| 8 | `require_approval`: dry-run preview, then one human approval per action | — |

**Approvals (ASI09).** The first call returns `approval_required` with an
`approval_id` and the dry-run preview. A human approves that single id. The agent
repeats the identical call with `aof_approval_id`. Each approval can be used once, expires
after an hour, and is bound to the user, tool and argument hash. If the tool sets an
`approver_role`, the approver must hold that role and cannot be the requesting user.
An explicit `dry_run=true` call runs without approval.

**Audit.** Every decision goes to a hash-chained JSONL log. It stores the argument
hash and keys, never the values. `aof gateway audit --verify` detects edits.

**Demotion.** When policy violations in the SLO window exceed `max_policy_violations`,
the gateway lowers the agent one autonomy level by itself. Operators can also demote by hand.

**Telemetry.** Each call emits an `execute_tool {tool}` span with OpenTelemetry GenAI
attributes plus `aof.decision`, `aof.code` and `aof.risk_tier`. Spans are no-ops until
the host configures an OTel SDK.

```bash
aof compile-policy examples/refunds-assistant -o policy.json

# stdio, acting for one user (local development)
aof gateway serve --policy policy.json --user alice --scopes orders:read,refunds:read \
  --cwd examples/refunds-assistant -- python src/server.py

# HTTP, development: unsigned tokens from a file (prints a DEV ONLY warning)
aof gateway serve --transport http --port 8765 --policy policy.json --tokens tokens.json \
  --cwd examples/refunds-assistant -- python src/server.py

# HTTP, production: JWTs signed by the IdP in platform.yaml identity.issuer
aof gateway serve --transport http --policy policy.json \
  --public-url https://gw.example.com/mcp --upstream-url https://refunds.internal/mcp

# operate it, production: the /admin API with an operator token from the IdP
export AOF_OPERATOR_TOKEN=...
aof gateway approvals --gateway-url https://gw.example.com
aof gateway approve apr_1234 --gateway-url https://gw.example.com
aof gateway kill agent:refunds-assistant --reason "cost spike" --gateway-url https://gw.example.com

# operate it, development: edit --state-dir directly; --by/--roles are not verified
aof gateway approve apr_1234 --by bob --roles support-lead
aof gateway demote agent:refunds-assistant --to L1 --by ops --reason "incident 42"
aof gateway audit --verify
```

### Running several replicas

By default state lives in `--state-dir/state.json`, with rate and budget counters in
process memory, which is fine for one gateway. To run more than one, point every replica
at the same Redis:

```bash
aof gateway serve --transport http --policy policy.json --state-url rediss://redis:6380/0 \
  --replica-id gw-1 --upstream-url https://refunds.internal/mcp      # or AOF_STATE_URL / AOF_REPLICA_ID
```

Kill switches, demotions, approvals, A2A task owners, per-run counters (steps, model
calls, delegations, cost) and every sliding window (rate limits, write limits, policy
violations) then live in Redis. The checks that guard a limit are atomic, so replicas
cannot oversell the last slot:

- **Rate and write limits:** a slot is taken with an atomic count-and-add when the
  decision is made.
- **Run budgets:** steps, model calls and delegations are reserved by an atomic
  increment, rolled back if over the limit.
- **Approvals:** an approval moves pending → approved → consumed through atomic
  read-modify-writes, so it executes once even if two replicas race on it.
- **Auto-demotion:** a demotion applies only if the agent is still at the level the
  replica saw, so two replicas breaching the SLO together demote once.

Cost can't be reserved because a call's price is known only afterwards, so concurrent
calls in one run can each pass the cost check and overshoot together.

Each replica writes its own hash-chained audit log, `audit-<replica>.jsonl` (default: the
host name), and stamps `replica` on every record. `aof gateway audit --verify` checks
every chain in `--state-dir`. Ship the files to your log store from each host.
Operator commands accept `--state-url` too, but in production use `--gateway-url`.

### Identity

In HTTP mode every route (`/mcp`, `/v1/messages`, `/a2a`, `/admin`) needs a bearer
token. In production these are JWT access tokens from the IdP set in `platform.yaml`
(`identity.issuer`). A token is accepted only when all of these hold:

- its signature verifies against a key from the IdP's JWKS. The keys are found through
  OIDC or RFC 8414 discovery, and the metadata must name the same issuer.
- it uses an allow-listed asymmetric algorithm. `none` and HS* are refused, both at
  startup and by policy (`AOF-P062`).
- `iss` matches, `aud` names this gateway (`--audience`, default `--public-url`), and
  `exp`/`nbf` are valid within `leeway_seconds`.
- it has a `sub`.

Keys are refetched when a token names an unknown `kid` (key rotation), at most once every
30 seconds. Claims map to the principal:
- scopes from `scope` or `scp`;
- roles from `identity.roles_claim` (a dotted path, e.g. `realm_access.roles`);
- tenant from `identity.tenant_claim`;
- the calling client or agent from `client_id` or `azp`.

The gateway won't start in HTTP mode without an issuer unless `--tokens` is given, and
then it prints that it is running DEV ONLY.

Operators use `/admin` (or the CLI with `--gateway-url`). The decider is the token's
subject, so it is never claimed:
- approving or rejecting needs the tool's approver role from the token;
- the kill switch, demote, restore and revive need `identity.operator_role`;
- nobody can decide their own request.

Every admin action, including refusals, is audited with `verified: true`. Local-mode CLI
actions are audited with `verified: false`.

Callers can set `_meta["aof/run_id"]` (budgets are counted per run; the default is the
MCP session) and `_meta["aof/delegation_depth"]` for A2A hops.

### On-behalf-of credentials (token exchange)

For a user-facing app the gateway never forwards the user's token and never calls the
app as a shared service account. After policy allows a call, it exchanges the user's
bearer token at the IdP (OAuth 2.0 Token Exchange, RFC 8693) for a new token that is
bound to the app's audience, carries only that tool's manifest scopes, and is used for at
most `identity.scope_ttl_seconds`. Each call then opens its own connection to the app with
that token, so connections are never shared between users.

```bash
export AOF_GATEWAY_CLIENT_SECRET=...      # the gateway's own OAuth client at the IdP
aof gateway serve --transport http --policy policy.json --tokens tokens.json \
  --upstream-url https://refunds.internal/mcp \
  --token-endpoint https://idp.example.com/oauth2/token   # or platform.yaml identity.token_endpoint
```

- The audience is `mcp_server.audience` in `aof.yaml`, defaulting to the upstream URL,
  which is also sent as the RFC 8707 `resource`.
- If the IdP grants scopes that weren't asked for (`OBO_SCOPE_WIDENED`), or withholds ones
  the user may not delegate (`OBO_SCOPE_DENIED`), the call is refused. A missing user
  token (`NO_SUBJECT_TOKEN`) or a failed exchange is also a refusal, never a fallback to
  the gateway's own connection.
- Denied calls never reach the IdP. Exchanged tokens are cached per user token, audience
  and scopes until 30 seconds before they expire. The audit log records audience, scopes
  and lifetime, never a token.
- A2A peers without a `credential_env` get an exchanged token for their endpoint (or
  `audience`) with the peer's `scopes`.
- On-behalf-of needs the HTTP gateway and a URL upstream. Under stdio, or with no token
  endpoint configured, the gateway prints that exchange is OFF and uses its own
  connection. `--no-obo` makes that explicit.

### Model calls (`POST /v1/messages`)

When the app's `aof.yaml` has an `llm:` block, the HTTP gateway also serves the
Anthropic Messages API at `/v1/messages`. Agents point the official SDK at the gateway
and use their gateway token as the API key; the gateway calls Claude with its own
credential (`ANTHROPIC_API_KEY` or an `ant` profile in the gateway's environment), so
agents never hold a provider key.

```python
client = anthropic.AsyncAnthropic(base_url="http://127.0.0.1:8765", api_key=GATEWAY_TOKEN,
                                  default_headers={"x-aof-run-id": run_id})
```

Each call is checked, in order: kill switch, model allowlist (`aof:default` picks the
agent's first model), `max_tokens` cap, beta allowlist, fallbacks that stay inside the
allowlist, no API-side MCP connector, client tools must be tools this agent may call at
its current level, server tools must be allow-listed, then per-run model-call, cost and
delegation budgets and a per-user rate limit. Denials come back as Anthropic-shaped
errors with `[AOF:<CODE>]` in the message, so the SDK raises its usual typed exception.
Streaming is passed through. Cost is computed from `usage` x the prices in
`platform.yaml` (unknown models are charged at the highest listed price) and is added to
the same per-run budget as tool calls. The audit log records token counts and cost, never
prompt or response content. `--no-llm` turns the endpoint off.

### Agent-to-agent calls (A2A)

With an `a2a:` block in `aof.yaml` and autonomy **L4**, the HTTP gateway carries A2A
JSON-RPC traffic both ways (A2A 1.0 method names; 0.3 names are accepted too):

```yaml
a2a:
  peers:                       # outbound: agents this app may delegate to
    - name: billing
      card_url: https://billing.example/.well-known/agent-card.json
      skills: [invoice_lookup] # the peer's card must keep advertising these
      credential_env: BILLING_A2A_TOKEN
  allowed_callers: [agent:orchestrator]   # inbound (needs hosts_agent)
  max_delegations_per_run: 5
```

- **Outbound:** the app's agent sends A2A requests to `POST /a2a/peers/<peer>`. The
  gateway loads and checks the peer's agent card, adds one to `x-aof-delegation-depth`,
  attaches the gateway's credential for that peer, and forwards the payload unchanged.
- **Inbound:** other agents read `/.well-known/agent-card.json` (the app's card with its
  endpoint rewritten to the gateway) and call `POST /a2a`. The calling agent is the
  token's `client_id`; the user is its subject. Start the gateway with
  `--a2a-upstream-url` pointing at the app's own A2A server.

Checks: kill switch, autonomy L4 at the *current* level (a demotion cuts A2A off), method
allowlist (push-notification webhooks are refused), peer or caller allowlist, delegation
depth, per-run delegation and cost budgets, task ownership (a caller can only read,
cancel or continue tasks it started, and `ListTasks` is filtered), and the peer card's
contracted skills. Denials are JSON-RPC errors with `data.error` set to the AOF code.
The audit log records method, peer or caller, and task ids, never message content.

## Running the evals (`aof eval`)

`aof eval` writes `evals/results.json` for the evaluate gate. It runs every golden and
safety case through the gateway against the app's real MCP server, so policy, budgets,
approvals and spend are real, and it scores from what the gateway recorded, not from
what the agent claims.

```bash
export ANTHROPIC_API_KEY=...
aof eval examples/refunds-assistant --limit 5   # asks first: this is billed
aof eval examples/refunds-assistant --yes       # all 70 cases
aof gate evaluate examples/refunds-assistant
```

- **Agent.** By default a reference Claude tool loop through the gateway's LLM proxy,
  using the app's `llm.models`. It answers with a JSON verdict
  (`status`, `result`, `summary`). Plug in your own with `--agent module:attr`
  (implements `aof.evalrun.Agent`), or change the prompt with `--system-prompt`.
- **Level.** Cases run at the target autonomy level (`--level` to change). At L2 an
  approval request ends that write and the case is judged on the proposal; with
  `--approvals approve` the runner approves each one so the agent can finish.
- **Scores.** `task_success` compares `result` with `expected` (numbers within 1%,
  strings case-insensitive, only the keys in `expected`). Prose expectations are graded
  by a Claude judge that sees the gateway's record; its spend is reported separately
  (`judge_cost_usd`); `--no-judge` leaves them ungraded and failed. `tool_call_accuracy`
  is the overlap of `expected_tools` with the tools called. `safety_pass_rate` checks
  `refuse`, `block`, `no_write` and `ask_approval` against refusals, gateway denials,
  approvals and executed writes. Cost and steps come from the gateway's run state.
- **Output.** `results.json` (with the level, models and error count) and a per-case
  `report.jsonl` next to it.

The pilot gate reads `evals/pilot.json`. During a supervised L2 pilot every proposed
write goes to a human, so the gateway's audit logs already hold the answer:

```bash
aof gateway pilot-report agent:refunds-assistant --since 2026-11-03 -o evals/pilot.json
```

It counts proposals, the share a human approved (`agreement_rate`) and incidents (kill
switch or demotion) across every replica's audit log.

Live smoke tests against real Redis, a real IdP and the Claude API are in `tests/live`.
They never run with plain `pytest`; see `tests/live/README.md`.

## Layout

```
src/aof/
  models/        pydantic schemas for every artefact (`aof schema` exports JSON Schema)
  policy.py      policy rules + gateway policy compiler
  lint.py        tool-design lint (agent-computer interface rules)
  checks.py      cross-artefact contract checks
  gates.py       the seven lifecycle gates
  conformance.py live MCP server vs manifest (needs the `mcp` extra, SDK v2)
  platform.yaml  platform-owned thresholds and budgets
  templates/app  `aof init` scaffold: a read-only L0/T1 lighthouse app
  evalrun.py     `aof eval`: cases through the gateway, scored from its record
  gateway/
    engine.py      per-call decision (pure)       approvals.py  one approval per action
    core.py        Gateway.call_tool orchestration audit.py      hash-chained audit log
    state.py       kill switch, demotions, counters telemetry.py OTel GenAI spans
    mcp_proxy.py   MCP front + upstream client     cli.py        `aof gateway ...`
examples/refunds-assistant   T3 app at L1, pilot passed for L2, blocked on review board
```

## Not built yet

- **A2A path limits.** JSON-RPC binding only (no HTTP+JSON or gRPC). No mTLS between
  gateways (terminate it in front) and no agent card signature verification yet. A2A
  can't say which skill a message is for, so skills are checked on the peer's card,
  not per message.
- **LLM path limits.** Anthropic only. Budgets are checked before a call, so one call can
  overshoot the cost cap. Long-context and regional price premiums are not modelled;
  check `platform.yaml` prices against the pricing page. No `count_tokens` or batches
  endpoints.
- **On-behalf-of limits.** The gateway authenticates to the IdP with a client secret only
  (no `private_key_jwt` or mTLS), sends no RFC 8693 `actor_token`, and doesn't bind tokens
  with DPoP. Each upstream call opens a new MCP connection, which costs one extra round
  trip.
- **Identity limits.** JWT access tokens only: no opaque tokens (RFC 7662
  introspection), no revocation check before `exp`, and no sender-constrained tokens
  (DPoP or mTLS). `/admin` has no UI of its own; build approval screens on top of it.
- **Shared-state limits.** Redis only (`RedisStore`); a database backend would implement
  the same `Store` protocol. The gateway calls Redis synchronously, inline, one round
  trip per check. On-behalf-of tokens and peer agent cards are cached per replica, by
  design: bearer tokens are not copied into shared storage. Audit chains are per replica,
  not one global chain.
- **Eval limits.** Cases run one at a time. The reference agent is a plain tool loop, not
  your production agent: plug yours in with `--agent` for scores that mean something.
  The prose judge is one Claude call per case with no calibration set. Pilot agreement
  is approved/decided at L2; shadow mode with no human in the loop isn't scored.
- **Other platform pieces.** The runtime/orchestrator, the internal MCP registry service
  and the AgentOps dashboards.

Open decisions carried over from the design:

- `platform.yaml` thresholds are placeholders. Calibrate them on the lighthouse wave.
- Pin `telemetry.genai_semconv_version`. Validation warns (P030) until it is pinned.
- `server.json` checks cover only the fields AOF depends on. Pin the official MCP Registry
  schema version in the registry service and validate fully there.
- Orchestrator default, agentgateway vs extending the API gateway, the lighthouse apps,
  and the review board's membership and SLA are still open.
