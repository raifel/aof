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

# HTTP with bearer tokens (dev token file; use your IdP's TokenVerifier in production)
aof gateway serve --transport http --port 8765 --policy policy.json --tokens tokens.json \
  --cwd examples/refunds-assistant -- python src/server.py

# operate it (works against a running gateway: state is shared through --state-dir)
aof gateway approvals
aof gateway approve apr_1234 --by bob --roles support-lead
aof gateway kill agent:refunds-assistant --by ops --reason "cost spike"
aof gateway demote agent:refunds-assistant --to L1 --by ops --reason "incident 42"
aof gateway audit --verify
```

Callers can set `_meta["aof/run_id"]` (budgets are counted per run; the default is the
MCP session) and `_meta["aof/delegation_depth"]` for A2A hops.

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
  not per message. Task ownership lives in process memory, so it is lost on restart and
  not shared between replicas.
- **LLM path limits.** Anthropic only. Budgets are checked before a call, so one call can
  overshoot the cost cap. Long-context and regional price premiums are not modelled;
  check `platform.yaml` prices against the pricing page. No `count_tokens` or batches
  endpoints. The model-call rate limit is per process.
- **On-behalf-of token exchange to the upstream app.** The gateway checks the user's
  scopes, but it calls the app over its own connection.
- **Production identity.** `StaticTokenVerifier` is for development only. Plug in a JWT
  verifier for your IdP. Operator commands take `--by`/`--roles` on trust; put them
  behind SSO.
- **Multi-replica state.** State is a locked JSON file for one host. Swap `DurableStore`
  for Redis or a database. Rate and budget counters are per process.
- **Other platform pieces.** The runtime/orchestrator, the internal MCP registry service,
  the eval runner and the AgentOps dashboards.

Open decisions carried over from the design:

- `platform.yaml` thresholds are placeholders. Calibrate them on the lighthouse wave.
- Pin `telemetry.genai_semconv_version`. Validation warns (P030) until it is pinned.
- `server.json` checks cover only the fields AOF depends on. Pin the official MCP Registry
  schema version in the registry service and validate fully there.
- Orchestrator default, agentgateway vs extending the API gateway, the lighthouse apps,
  and the review board's membership and SLA are still open.
