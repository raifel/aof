# AOF: Agentic Onboarding Framework, contract kit

This kit implements the app-facing part of the
[AOF reference design](https://claude.ai/artifact/PtqoNQdMNX3iw3oA8RF2Ta). An app is
onboarded when its repo holds the seven contract artefacts and `aof validate` passes.
The policy compiler then turns its tool manifest into the policy the shared agent
gateway enforces on every call.

```bash
uv venv && uv pip install -e '.[dev,mcp]'
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
examples/refunds-assistant   T3 app at L1, pilot passed for L2, blocked on review board
```

## Not built yet

This is the contract kit only. The shared platform it targets is out of scope for now:
the runtime/orchestrator, the gateway that loads `gateway-policy.json`, the internal MCP
registry service, the eval runner and AgentOps dashboards.

Open decisions carried over from the design:

- `platform.yaml` thresholds are placeholders. Calibrate them on the lighthouse wave.
- Pin `telemetry.genai_semconv_version`. Validation warns (P030) until it is pinned.
- `server.json` checks cover only the fields AOF depends on. Pin the official MCP Registry
  schema version in the registry service and validate fully there.
- Orchestrator default, agentgateway vs extending the API gateway, the lighthouse apps,
  and the review board's membership and SLA are still open.
