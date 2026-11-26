# Architecture

How the AOF kit and gateway fit together. Deployment and network layout are in
[deployment.md](deployment.md), threats in [threat-model.md](threat-model.md), and
telemetry and audit in [observability.md](observability.md).

## Two halves

AOF has a **build-time** half and a **run-time** half, joined by one file: the compiled
gateway policy.

- **Build time (the contract kit, `aof`).** An app team keeps seven artefacts in its repo.
  CI runs `aof validate` and the lifecycle gates on them. `aof compile-policy` turns the
  artefacts plus the platform's `platform.yaml` into `gateway-policy.json`.
- **Run time (the gateway, `aof gateway serve`).** Every tool call, model call and
  agent-to-agent call the agent makes goes through the gateway, which enforces that
  policy, asks humans for approval when the policy says so, and audits every decision.

```mermaid
flowchart LR
  subgraph repo["App repo (owned by the app team)"]
    A1["aof.yaml<br/>project, tier, autonomy"]
    A2["tools.manifest.yaml"]
    A3["server.json<br/>(MCP Registry)"]
    A4["agent-card.json<br/>(A2A)"]
    A5["readiness.yaml"]
    A6["evals/<br/>suite, golden, safety"]
    A7["runbook.md"]
  end
  P["platform.yaml<br/>(owned by the platform team)"]
  subgraph ci["CI"]
    V["aof validate<br/>schemas, lint, policy rules"]
    G["aof gate STAGE<br/>7 lifecycle gates"]
    E["aof eval<br/>golden + safety cases"]
    C["aof compile-policy"]
  end
  POL[("gateway-policy.json")]
  GW["aof gateway serve"]
  repo --> V --> G
  P --> V
  repo --> C
  P --> C
  C --> POL --> GW
  E -- "results.json" --> G
  GW -- "audit logs" --> PR["aof gateway pilot-report"] -- "pilot.json" --> G
```

The seven gates are intake, readiness, pattern, build, evaluate, pilot and promote.
Promotion moves an agent one autonomy level at a time:

| Level | Meaning | Gateway behaviour |
|-------|---------|-------------------|
| L0 | assist: read-only answers and drafts | read tools only |
| L1 | workflow: predefined steps, read-only | read tools only |
| L2 | supervised agent | every write needs a human approval |
| L3 | bounded autonomy | low-risk writes inside the tool's limits run; others need approval |
| L4 | delegated multi-agent | as L3, plus agent-to-agent delegation (A2A) |

T4 tools (irreversible, high-impact) are compiled as `deny` at every level.

## Gateway components

```mermaid
flowchart TB
  subgraph clients["Callers"]
    AG["Agent runtime<br/>(the app's agent)"]
    PEER["Peer agent<br/>(via its own gateway)"]
    OPS["Operators and approvers"]
  end

  subgraph gw["aof gateway (one replica)"]
    direction TB
    subgraph front["HTTP front: Starlette app, mcp_proxy.http_app"]
      R1["/mcp<br/>MCP streamable HTTP"]
      R2["/v1/messages<br/>Claude Messages API"]
      R3["/a2a, /a2a/peers/{peer}<br/>A2A JSON-RPC"]
      R4["/admin/*<br/>approvals, kill, demote"]
      R5["/.well-known/agent-card.json"]
    end
    ID["identity<br/>JwtVerifier (prod)<br/>StaticTokenVerifier (dev)"]
    CORE["core.Gateway<br/>orchestrates one call"]
    ENG["engine.evaluate<br/>pure decision, no I/O"]
    LLM["llm.LlmProxy"]
    A2A["a2a_proxy.A2aProxy"]
    ADM["admin.py"]
    APR["approvals.ApprovalService"]
    OBO["obo.TokenExchanger<br/>RFC 8693"]
    ST["state: GatewayState<br/>RunState, counters, windows"]
    AUD["audit.AuditLog<br/>hash-chained JSONL"]
    TEL["telemetry<br/>OTel GenAI spans"]
  end

  subgraph ext["Dependencies"]
    APP["App MCP server<br/>(stdio or HTTP)"]
    ANT["Claude API"]
    IDP["Identity provider<br/>JWKS, token endpoint"]
    REDIS[("Redis<br/>shared state")]
    PEERGW["Peer's gateway"]
    OTEL["OTel Collector"]
    LOGS[("Audit log files")]
  end

  AG --> R1 & R2 & R3
  PEER --> R3
  OPS --> R4
  R1 & R2 & R3 & R4 --> ID
  ID -. "JWKS" .-> IDP
  R1 --> CORE
  R2 --> LLM --> CORE
  R3 --> A2A --> CORE
  R4 --> ADM
  CORE --> ENG
  CORE --> APR
  CORE --> OBO -. "token exchange" .-> IDP
  CORE --> ST --> REDIS
  CORE --> AUD --> LOGS
  CORE --> TEL -.-> OTEL
  ADM --> APR & ST & AUD
  CORE -- "tools/call" --> APP
  LLM -- "messages.create" --> ANT
  A2A -- "JSON-RPC" --> PEERGW
```

| Module | Responsibility | Rule it keeps |
|--------|----------------|---------------|
| `engine.py` | one decision per call: allow, deny, needs approval, dry run | no I/O, no transport code |
| `core.py` | runs a tool call: step budget, evaluate, approval, dry-run preview, token exchange, upstream call, audit, span | every decision is audited |
| `mcp_proxy.py` | MCP front (stdio or streamable HTTP) and the upstream MCP client | MCP specifics only here |
| `llm.py` | `/v1/messages`: model allowlist, token caps, budgets, rate limit, cost from usage | official `anthropic` SDK only |
| `a2a_proxy.py` | outbound and inbound A2A: peers, callers, depth, delegation budget, task ownership | forwards JSON-RPC unchanged |
| `approvals.py` | one approval per action, bound to tool, args, user and agent; single use | no self-approval |
| `obo.py` | exchange the user's token for one scoped to the upstream | exchange only after allow; fail closed; never log tokens |
| `jwt_verifier.py` | verify JWT access tokens against the IdP's JWKS | asymmetric algorithms only |
| `admin.py` | operator and approver API | decider comes from the verified token |
| `state.py` | `Store` protocol: memory, file, Redis | limit checks are atomic in the store |
| `audit.py` | append-only hash chain per replica | arguments hashed, not stored |
| `telemetry.py` | OTel GenAI spans | API only; the host configures the exporter |

## Request flows

### Tool call that needs approval (L2)

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant G as Gateway
  participant S as State store
  participant U as App MCP server
  participant H as Approver
  A->>G: tools/call create_refund_request(args), Bearer user token
  G->>G: verify JWT (iss, aud, exp, sig)
  G->>S: kill switch? demotion? reserve step (atomic)
  G->>G: engine.evaluate: scope, level, limits
  G->>U: same call with dry_run=true (preview)
  U-->>G: would_create {...}
  G->>S: store approval (args hash, user, agent, tool)
  G-->>A: approval_required {approval_id, preview}
  Note over G: audit approval_requested
  H->>G: POST /admin/approvals/{id}/approve, Bearer approver token
  G->>S: pending → approved (atomic, approver ≠ requester)
  Note over G: audit approval_decided
  A->>G: tools/call again with aof_approval_id
  G->>S: consume approval exactly once (args must match)
  G->>G: token exchange for the upstream audience (if configured)
  G->>U: tools/call create_refund_request(args)
  U-->>G: created
  G-->>A: result
  Note over G: audit tool_executed (approved_by, on_behalf_of)
```

### Model call

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant G as Gateway LLM proxy
  participant S as State store
  participant C as Claude API
  A->>G: POST /v1/messages {model, max_tokens, tools, messages}
  G->>G: verify JWT, model on allowlist, max_tokens within cap, no forbidden betas or server tools
  G->>S: reserve model call in run budget, acquire rate-limit slot (atomic)
  G->>S: cost so far < run cost cap?
  G->>C: messages.create (gateway's API key)
  C-->>G: message + usage
  G->>S: add cost (usage × platform.yaml prices)
  G-->>A: message (unchanged)
  Note over G: audit llm_call with tokens and cost, span aof.gateway.chat
```

### Agent-to-agent delegation (L4)

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent A
  participant GA as Gateway A
  participant GB as Gateway B
  participant B as Agent B
  A->>GA: POST /a2a/peers/billing SendMessage
  GA->>GA: L4? peer allowed? method allowed? depth+1 ≤ max? delegation budget?
  GA->>GB: GET agent card (cached), contracted skills present?
  GA->>GB: POST /a2a SendMessage (peer credential or exchanged token, depth header)
  GB->>GB: verify caller token, caller allowed? depth ≤ max? budgets
  GB->>B: forward unchanged
  B-->>GB: Task {id}
  GB->>GB: record task owner (caller, user)
  GB-->>GA: Task
  GA->>GA: record task owner (peer, user)
  GA-->>A: Task
  Note over GA,GB: each side audits a2a_call, follow-ups (GetTask, CancelTask) must come from the owner
```

## State

All shared state goes through one `Store` protocol, so a single replica can use memory or
a file and several replicas share Redis.

| Namespace | Contents | Written by | Atomic operation |
|-----------|----------|------------|------------------|
| kill switch | per agent: who, why, when | admin, CLI | `put` / `delete` |
| demotions | per agent: level, who, why | admin, CLI, auto-demotion | `demote_from` (only from the level the replica saw) |
| approvals | request, decision, consumption | core, admin | `update` with state transition |
| run state | steps, model calls, delegations, cost per run | core, llm, a2a | `reserve` / `incr` |
| windows | rate limits, write counts, violations | engine, llm | `window_acquire` |
| a2a tasks | task → owner | a2a | `put_if_absent` |

What is **not** shared, by design: bearer tokens (exchanged tokens are cached per replica,
keyed by a hash of the user token), peer agent cards (cached per replica) and audit
chains (one per replica).
