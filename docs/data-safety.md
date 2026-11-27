# Data safety and natural-language queries (plan)

Status: **D1–D6 and DS8 built**: contract rules, the result vault with the gateway wiring,
the query compiler with the SQL guard, the egress guard on model requests, the
`ledger-analyst` example with execution-accuracy and no-leak evals, and verdicts, value
references and signed exceptions for agents that must decide on hidden values, and
answer templates rendered for the user (`POST /render`) with template-fidelity evals. The platform default is `results: shadow`:
governed results are vaulted and audited but still returned to the agent. Set `enforce`
in `platform.yaml` or an app's `aof.yaml` to keep them from the model; the egress guard
follows the same mode. D7 is not built. Written 2026-11-27 against commit `7accedb`.

Two goals for every onboarded app:

1. **Business data does not reach the model.** The LLM sees schemas, field descriptions and
   query plans, never row values, unless a data contract explicitly allows a field.
2. **Natural-language questions over governed data**, starting with accounting
   ("what was opex by cost centre in Q3 against budget?"), answered by queries the
   gateway checks before they run, with numbers that come from the warehouse, not the model.

These two goals fit together. In text-to-SQL the model only needs the *shape* of the data
to write the query. The *result* can go straight to the user without passing through the
model. The hard part is keeping the model useful when it can't see the values; see
[Exposure modes](#exposure-modes).

Related: [architecture.md](architecture.md), [threat-model.md](threat-model.md) (this closes
part of residual risk 5 and the B5 "I" row).

## Where data leaks to the model today

The gateway decides *whether* a call may run. It does not look at what comes back.

| # | Path | What reaches Claude today |
|---|------|---------------------------|
| L1 | Tool result → agent → next `/v1/messages` call | the full result: order rows, customer ids, amounts |
| L2 | User's prompt | anything the user pastes (IBANs, invoices, payroll) |
| L3 | Documents and tickets the agent retrieves | full text |
| L4 | Approval previews (dry-run output) | goes back to the agent, so to the model |
| L5 | A2A replies from peer agents | full message content |
| L6 | Eval judge (`evalrun.py`) | the gateway record. Argument values are already hashed, but results aren't |

The audit log is already safe: it stores argument hashes and key names, never values
(`audit.py`). The plan below keeps that rule.

## Design principle: the model gets a handle, the user gets the data

```mermaid
flowchart LR
  U["User UI"] -- "question" --> AG["Agent"]
  AG -- "/v1/messages<br/>(schema, handles, no values)" --> GWL["Gateway LLM proxy<br/>egress guard"]
  GWL --> C["Claude"]
  AG -- "tools/call query(sql)" --> GWT["Gateway tool path<br/>SQL guard"]
  GWT -- "OBO token, read-only role" --> APP["App MCP server<br/>or warehouse"]
  APP -- "rows" --> GWT
  GWT -- "rows" --> V[("Result vault<br/>per user, TTL, encrypted")]
  GWT -- "handle + schema + row count" --> AG
  U -- "GET /results/{handle}<br/>user token" --> V
```

- Tool results that hold contract-governed fields are stored in a **result vault** at the
  gateway. The agent gets a **handle** (`res_…`), the column names and types, and the row
  count (bucketed; see [Inference attacks](#inference-attacks)).
- The user's UI fetches the rows from `GET /results/{handle}` with the **user's** token.
  The agent's credential can't read the vault.
- The model writes the answer as a **template** that refers to cells by handle:
  `Q3 opex was {{res_1.total_eur | money}}, {{res_2.delta_pct | pct}} over budget.`
  The UI (or a gateway render endpoint) fills it in. The model never saw the numbers,
  and the user sees numbers that come straight from the query.
- Identifiers the agent needs to pass between tools (customer id, invoice number) are
  **tokenised**: the model sees `tok_c_8f3a`, and the gateway swaps it back for the real
  value in the arguments of the next upstream call, for the same user and run only.

### As built (D2)

Code: `gateway/vault.py` (vault and tokens), `gateway/shield.py` (before and after each
call), `gateway/results_api.py` (`GET /results/{handle}`), wired in `core.py`.

**Which calls.** Every call to a tool with `query:` or `reads` is governed. Query tools
are guarded whenever the policy has a `data_safety` section, whatever the results mode.

**Before the call.** Tokens anywhere in the arguments are replaced by their values (same
user, tenant and run; unknown tokens stay as they are). For a query tool, the run's query
budget is reserved (`max_queries_per_run`, atomic), the query is compiled and guarded,
and the guarded SQL replaces the query argument. **The app's server always receives SQL**
in the query parameter, for `ir` and `sql` alike, and must apply the tool's declared
timeout and scan limits. Tokens inside SQL string literals are resolved on the syntax
tree, so a value can't change the query. A refused query never reaches the app; the audit
records `query_rejected` with the code only (the reason can quote the query).

**After the call.** The result is sealed in the vault (AES-GCM, bound to user and tenant,
`ttl_seconds`), and the agent gets back:

- query tools: `result_handle`, `columns` with their exposure, `row_count` as a bucket,
  and up to `model_preview_rows` rows holding only visible values. The guard adds
  `COUNT(*) AS aof_group_rows` to aggregated queries; `aggregate` values in a group below
  `min_group_size` are left out (`suppressed_small_groups`).
- other governed tools (JSON results): `result_handle`, `result` with only the keys the
  model may see, and `hidden_keys`. A key's exposure comes from the contract field of the
  same name in a view the tool reads. Otherwise it comes from the tool's new
  `result_keys` in the manifest. **Keys declared in neither are hidden.**
  `metadata_only` clamps `result_keys` too, so they can't be used to get around it.
- a failed query: `QUERY_FAILED` with a generic reason, never the warehouse's message.
  Errors from other tools pass through (they are written by the app).
- approval previews: approvers get the real dry-run preview (or the guarded SQL for a
  query tool); the agent gets the shaped preview.

The decision record (`tool_executed`) carries `result_handle`, the mode, the row bucket
and the hidden key names, never values.

**Reading results.** `GET /results/{handle}` needs a verified token whose user and tenant
own the result, **and** a calling OAuth client listed in `vault.reader_clients`. The agent
holds the user's token too, so the client check is what keeps it out. List the app's UI
clients there, never the agent's. Reads and refusals are audited.

**Keys and storage.** `AOF_VAULT_KEY` (32 bytes, base64). Without it, a single gateway
uses a per-process key and loses results on restart. A gateway with shared state refuses
to start without a key, because replicas must read each other's results. The vault uses
its own Redis prefix (`aof:vault:`), and `--vault-url` / `AOF_VAULT_URL` can point it at a
separate Redis ACL user.

**Rollout.** `data_safety.results` is `off`, `shadow` or `enforce`. Apps may only tighten
it (AOF-P076). Shadow mode tells you, from the audit log, which keys and columns each tool
would hide, before anything changes for the agent.

### Answer templates (D6, as built)

The agent answers in placeholders; the user's UI fills them in. Same paths as value
references, plus a filter:

```text
Q3 opex was {{res_8f3a….opex | money:EUR}}; CC20 spent {{res_8f3a….rows[1].opex | money}}.
```

Filters: `money[:CUR]`, `number[:digits]`, `int`, `pct[:digits]` (a fraction), `date`.
`POST /render` with `{"template": …}` returns `{"text", "references", "missing"}`. It has
the same rules as `GET /results`: the user's token from a client in `reader_clients`, only
that user's results. A placeholder that can't be filled (another user's handle, a wrong
path, a bad filter) renders as `[unavailable]` and never as a value. The audit records
`answer_rendered` with the handles and counts. A UI shows the agent's answer like this:

```js
// final = the agent's JSON answer; token = the user's access token from the app's UI client
const r = await fetch(`${gateway}/render`, {method: "POST", headers: {
  authorization: `Bearer ${token}`, "content-type": "application/json"},
  body: JSON.stringify({template: final.summary})});
const {text, missing} = await r.json();          // figures filled from the vault
const table = final.result?.result_handle &&     // the full table behind the answer
  await (await fetch(`${gateway}/results/${final.result.result_handle}`,
                     {headers: {authorization: `Bearer ${token}`}})).json();
```

Shaped results tell the agent how to write placeholders and references (`next`), and the
reference agent in `aof eval` gets the same instructions when the app enforces data safety.

## Exposure modes

Each field in a data contract gets an `llm_exposure`. The platform sets a ceiling per
classification, and the app may only tighten it (same rule as budgets, P025).

| `llm_exposure` | Model sees | Use for |
|----------------|------------|---------|
| `none` (default for `confidential` and up) | column name and type only; values are in the vault | amounts, names, PII, salaries |
| `token` | a stable per-run token that the gateway can swap back | ids passed between tools |
| `aggregate` | values only from aggregates over at least `k` rows (platform `min_group_size`) | counts and totals for trend reasoning |
| `masked` | partial value (`****1234`, year only) | disambiguating for the user |
| `allowed` | the value | public reference data: account names, cost-centre names, fiscal calendar |

```yaml
# aof/data-contracts/gl_journal_lines.yaml (data-safety keys as built)
name: gl_journal_lines
classification: confidential
source: "snowflake:FINANCE.GL.JOURNAL_LINES"
semantic_view: gl_journal_lines
fields:
  - {name: company_code, type: string, classification: public, llm_exposure: allowed}
  - {name: account_code, type: string}                    # internal: default aggregate
  - {name: cost_centre, type: string}
  - {name: posting_date, type: date}
  - {name: amount_eur, type: "number(18,2)", classification: confidential}   # default none
  - {name: vendor_id, type: string, pii: true, llm_exposure: token}
  - {name: description, type: string, classification: confidential, free_text: true}
row_filter:                          # row-level security, bound from the verified token
  - {column: company_code, claim: tenant}
measures:
  - {name: opex, field: amount_eur, agg: sum,
     filter: [{column: account_code, op: between, value: ["6000", "7999"]}]}
  - {name: revenue, field: amount_eur, agg: sum, sign: -1,      # credits stored negative
     filter: [{column: account_code, op: between, value: ["4000", "4999"]}]}
dimensions:
  - {name: company, field: company_code, required: true, description: legal entity}
  - {name: cost_centre, field: cost_centre}
  - {name: posting_date, field: posting_date, time: true}
fiscal_calendar: {year_start_month: 4, year_named_by: end}     # FY2026 = Apr 2025 - Mar 2026
glossary: {opex: "operating expenses, accounts 6000-7999"}
```

```yaml
# platform.yaml (as built; see the file for the function allowlist)
data_safety:
  default_mode: metadata_only          # used when aof.yaml sets no data_safety.mode
  metadata_only_from_tier: T3          # apps at this tier or above must use it (AOF-P074)
  default_exposure: {public: allowed, internal: aggregate, confidential: none, restricted: none}
  exposure_ceiling: {public: allowed, internal: aggregate, confidential: token, restricted: none}
  min_group_size: 10
  row_count_buckets: [0, 1, 10, 100, 1000, 10000]
  row_filter_claims: {}                # extra claims for row filters: name -> token claim path
  provider: {zero_data_retention: required}
  query: {max_rows_ceiling: 10000, timeout_seconds_ceiling: 60,
          max_bytes_scanned_ceiling: 50000000000, allowed_functions: [SUM, COUNT, ...]}
```

An app picks its mode in `aof.yaml` (`data_safety: {mode: contract}`). A query tool is a
read tool with a `query:` block in the manifest:

```yaml
  - name: query_ledger
    access: read
    reads: [gl_journal_lines]
    query: {form: ir, param: query, dialect: snowflake, max_rows: 1000,
            timeout_seconds: 30, max_bytes_scanned: 1000000000}
    params:
      query: {type: object, description: "Semantic query: view, metrics, dimensions, filters, period"}
```

`metadata_only` is the strict reading of goal 1: every field behaves as `none` or `token`
and nothing but schema reaches the model. `contract` lets each data contract open fields up
to the ceiling. **Recommendation:** default to `metadata_only` for T3 apps and finance
data, and allow `contract` for T1–T2 apps whose fields are `public` or `internal`.

What the model **cannot** do in `metadata_only`: explain *why* a number moved, or spot an
anomaly in rows it hasn't seen. Two answers to that, both deterministic: the query service
returns aggregates whose groups are at least `k` rows (`aggregate` exposure), or the app
offers analysis tools (variance, top movers, period comparison) that return handles too.

## Text-to-SQL for accounting

### Flow

```mermaid
sequenceDiagram
  autonumber
  participant U as User
  participant A as Agent
  participant G as Gateway
  participant W as Warehouse (via app MCP server)
  U->>A: "Opex by cost centre, Q3 FY26 vs budget"
  A->>G: tools/call describe_semantic_model()
  G-->>A: views, measures, dimensions, glossary, fiscal calendar (metadata only)
  A->>A: model writes a query (semantic IR, or SQL)
  A->>G: tools/call query_ledger(query)
  G->>G: SQL guard: parse, single SELECT, allowed views and columns,<br/>inject row filter + LIMIT, cost estimate
  G->>W: OBO token (read-only role), guarded SQL
  W-->>G: rows
  G->>G: store rows in vault, apply exposure per column
  G-->>A: {handle: res_1, columns, row_count: "10-100", sql_hash}
  A-->>U: template answer + table from res_1
  Note over G: audit query_executed (views, columns, sql hash, row bucket), never values
```

### Two query forms

| Form | How it works | When |
|------|--------------|------|
| **Semantic query IR** (recommended default) | the model fills a JSON object: `{view, metrics: [opex], dimensions: [cost_centre, "posting_date:month"], filters: [{dimension, op, value}], period: {fiscal_year: 2026, quarter: 3}, order_by, limit}`. `aof.query.semantic` compiles it to SQL against one semantic view. Comparing two views (actual vs budget) is not supported yet. | most accounting questions: they are metrics over dimensions and periods |
| **Raw SQL** | the model writes SQL; the guard parses and rewrites it | ad-hoc questions the semantic model doesn't cover; gated by tier |

The IR is safer and easier to test: the model can't produce a join, function or column the
compiler doesn't know. Raw SQL is the fallback, behind the same guard.

### The SQL guard (deterministic, gateway-side)

Runs on any tool the manifest marks as a query tool, before the call goes upstream. It uses
`sqlglot` to parse in the warehouse's dialect and works on the syntax tree, never on strings.

| Check | Denial code |
|-------|-------------|
| Exactly one statement, and it is a query (no DML, DDL, `SELECT INTO`, `COPY`, locks, multi-statement) | `SQL_NOT_READ_ONLY` |
| No bind parameters, table functions, `LATERAL`, `UNNEST`, recursive CTEs, or CTEs named like a view | `SQL_CONSTRUCT_NOT_ALLOWED` |
| Every table is an unqualified semantic view this tool `reads` | `SQL_VIEW_NOT_ALLOWED` |
| Every column exists in its view (sqlglot `qualify`; `*` is expanded per column) | `SQL_COLUMN_NOT_ALLOWED` |
| Every function is in `data_safety.query.allowed_functions` | `SQL_FUNCTION_NOT_ALLOWED` |
| Predicates use only filterable columns ([Inference attacks](#inference-attacks)) | `SQL_FILTER_NOT_ALLOWED` |
| Row filter from the contract wrapped around every reference to a view (CTEs, subqueries, joins), bound from the caller's claims, never from the query | `ROW_FILTER_UNBOUND` when a claim is missing (fail closed) |
| `LIMIT` set to at most the tool's `max_rows` | — (rewrite) |
| Unparseable query | `SQL_UNPARSEABLE` |
| Semantic query: bad shape, unknown metric or dimension, or a required dimension not given | `QUERY_INVALID`, `QUERY_UNKNOWN_FIELD`, `QUERY_NEEDS_CLARIFICATION` |

`timeout_seconds` and `max_bytes_scanned` travel in the compiled policy for whoever executes
the query. The guard doesn't check them, because a cost estimate (`EXPLAIN`) needs the
warehouse.

The guard also reports how much of each output column the model may see. An output is as
exposed as the least exposed column it is computed from. `COUNT(*)` counts as `aggregate`.
A raw read of an `aggregate` column, with no grouping, is `none`. ORDER BY on a hidden
column makes every column `none`, because row order leaks the ranking. D2 uses this to
decide what goes into the vault.

The guard is a second line. The first is the warehouse itself: the query runs with the
user's exchanged token (existing `obo.py`), under a read-only role with row access policies.
The gateway guard exists because warehouse grants are often broader than one agent needs.

### Accounting semantics the model needs as metadata

These go into `describe_semantic_model` so the model writes correct queries without seeing data:

- **Chart of accounts:** account ranges and their meaning (revenue 4000–4999, opex 6000–7999),
  account types and normal balance (debit or credit).
- **Sign conventions:** whether `amount` is debit-positive. The compiler applies the sign
  per account type, so "revenue" comes out positive.
- **Fiscal calendar:** fiscal year start, periods, 4-4-5 or monthly, adjustment period 13.
  "Q3" means the fiscal quarter unless the user says calendar.
- **Currency:** reporting vs transactional currency, which rate table, period-average vs
  closing rate.
- **Entities:** company codes, intercompany accounts, and whether eliminations apply.
- **Period status:** open, closed or locked periods. Results from open periods are labelled
  provisional.
- **Glossary:** "opex", "EBITDA", "DSO", "AP aging buckets", as measure definitions, not prose.

These are `allowed` metadata. They belong in the data contract (`measures`, `dimensions`,
`glossary`), so the build-time checks can validate them.

### Ambiguity

The model asks the user instead of guessing when the IR has an unresolved choice: fiscal or
calendar period, which entity, reporting or transactional currency, budget version. The
semantic model marks which dimensions need a stated value (`required_filters`).

## Egress guard on `/v1/messages`

The vault keeps tool results away from the model, but values can still arrive through the
user's prompt (L2), retrieved documents (L3) or an agent that copies data around. The LLM
proxy runs `gateway/egress.py` after its policy checks and before any budget is reserved,
so a refused request costs nothing. Built in D3:

1. **Vault fingerprints.** When the shield vaults a result, it records keyed hashes (HMAC
   under a key derived from `AOF_VAULT_KEY`) of every *distinctive* value the agent wasn't
   shown as is, per agent, tenant and user, for `vault.ttl_seconds`. Distinctive means
   numbers written with a decimal point (`180.00`), numbers of 1000 or more that aren't
   plausible years, and strings of six or more characters. Before a model call, numbers,
   ids and 2–4 word phrases in the system prompt, assistant turns, tool inputs and tool
   results are hashed and compared. A match → `DATA_EGRESS_BLOCKED`. **Text the user typed
   is not compared**, because users may name values they know. Keying by user rather than
   run means mismatched run ids between `/mcp` and `/v1/messages` don't weaken the check.
2. **Pattern detectors** on all text, the user's included: `iban` (mod-97 checked),
   `card_number` (Luhn checked), `email`, `phone` (international format with `+`), and
   platform `custom_patterns` (national ids, internal formats). Each is `redact`, `block`
   (`SENSITIVE_DATA_BLOCKED`) or `off`. Redact replaces the match with a vault token, so
   the agent can still pass it to a tool, which gets the real value (same user and run).
   Defaults: card numbers block; the rest redact.
   Digits glued to letters (`res_fbe0395181482780…`) are not read as a card number: before
   that fix, about 0.1% of result handles passed the Luhn check and got an honest request
   blocked.
3. **Content the guard can't read.** Images and documents are blocked by default
   (`NON_TEXT_BLOCKED`); set `egress.non_text: allow` to let them through, unchecked.
4. **Never altered:** `thinking` and `redacted_thinking` blocks, which the provider signs.

`shadow` mode audits findings without changing or blocking anything; `off` skips the
guard. The `llm_call` and `llm_denied` records carry `egress: {detector: count}`, never
the matched text. Config: `data_safety.egress` in `platform.yaml`.

**Limits.** This is a tripwire, not a proof. A value the agent rewords ("one hundred and
eighty euros") or splits passes. Short values (`DE01`, `180`) aren't fingerprinted, so
they can't be caught. An assistant turn that repeats something the user typed can be
blocked if the same distinctive value was also in a hidden result. The external
classifier hook (ROADMAP 4.10) is not built.

## Agents that decide on values they can't see (DS8)

`metadata_only` with `results: enforce` hides an order's status and amount from a
refunds agent, which then can't decide anything. Decided and built: three mechanisms, in
the order an app should reach for them. All three keep the values out of the model.

1. **Verdicts.** A tool declares typed decisions the app computes over the hidden values:

   ```yaml
   verdicts:
     status: {type: enum, values: [delivered, in_transit, lost, returned]}
     refundable: {type: boolean, description: "within the refund window, not refunded before"}
   ```

   The gateway shows verdicts in every mode, `metadata_only` included, and drops any value
   outside the declared type (a status that reads `delivered on 2026-10-01, total 4711.00`
   is hidden). The decision logic stays deterministic and testable in the app. An enum
   carries at most log2(values) bits per call; `max_verdict_values` (8) caps it, and a key
   can't be both a verdict and a result key (AOF-P079). Reviewing which verdicts a tool
   returns is part of the architecture review.
2. **Value references.** The agent passes a value it never saw: `amount:
   "{{res_<id>.amount}}"`, or `{{res_<id>.rows[0].opex}}` for a query result (just
   `.opex` when there is one row). The gateway resolves it from the vault (same user and
   tenant) **before** the policy check, so `max_amount` limits and approvers see the
   real number. In text (`"refund of {{res_<id>.amount}} EUR"`) it is substituted as
   text. To stop the value coming back:
   - a call that used a reference has its result shaped even if the tool reads no
     governed data, and app errors become a generic `TOOL_FAILED`; a failed dry run
     doesn't return the app's message;
   - the over-limit reason no longer quotes the amount;
   - the audit records `references: <count>`, never the values.

   Unknown paths fail with `REFERENCE_INVALID`, another user's handle with
   `RESULT_NOT_FOUND`; both are audited as `reference_refused` and nothing reaches the app.
3. **Signed exceptions.** When the agent must reason over the value itself, the review
   board opens one field for one app, and the app stays on `metadata_only`:

   ```yaml
   data_safety:
     exceptions:
       - field: order_facts.amount        # or <tool>.<result key>
         exposure: aggregate
         reason: "compare refund totals per customer"
         signoff: {by: review-board, date: 2026-12-01, ref: RB-90}
   ```

   An exception can't exceed what contract mode would give, so the contract and the
   platform ceilings still bind (AOF-P078); an unknown field is AOF-P077. Exceptions have
   effect only under `metadata_only`.

Not chosen: keeping such apps on `shadow` permanently (values reach the model) and
allowing `contract` mode for T3 outright (opens every field, not the ones that need it).

**Limits.** A reference is a one-bit oracle wherever the gateway's answer depends on the
value: a write auto-executes within the limit, or goes to approval above it. Write rate
limits and approvals bound it. A reference inside a query filter (`company =
{{res.x}}`) gives a bucketed row count; the query budget bounds that. Approval records
hold the resolved values in the state store, as before (protect it, ROADMAP 4.7).

## Inference attacks

A model that only sees row counts can still learn values by bisection:
`SELECT count(*) WHERE salary > 100000`, then `> 150000`, and so on. Mitigations:

- Row counts go back to the model **bucketed** (`10-100`), and exact counts only for
  `allowed` dimensions (D2).
- **Built:** a predicate (WHERE, HAVING, JOIN ON, QUALIFY, and GROUP BY expressions other
  than a bare column) may use a column only if it is a declared **dimension** or exposed
  `aggregate` or `allowed`. Dimensions stay filterable even in `metadata_only`, so date
  ranges and cost-centre filters work. `token` and `masked` columns are allowed only in
  `=`, `<>` and `IN`. Measures and other hidden columns can never be filtered. This holds
  through CTEs, derived tables and subqueries: a derived column carries the exposure of
  its sources.
- Aggregates below `min_group_size` are suppressed (D2).
- A per-run **query budget** in the run state (`RunState.reserve`, atomic like the other
  budgets), plus a per-user query-rate window.
- **Built (D6):** an audit signal. When a run sends `probe_threshold` (5) queries whose
  SQL is the same once every literal is replaced, the gateway audits
  `query_probe_suspected` once, with the views and a shape hash, never the constants. It
  doesn't block: "opex for Q1, Q2, Q3, Q4, then the year" looks the same. `aof eval`
  counts these signals (`probe_signals`). The AgentOps dashboard (ROADMAP 3.1) should
  chart them.

## Where the code goes

Follows the conventions in `AGENTS.md`.

| Piece | Module | Status |
|-------|--------|--------|
| `llm_exposure`, `free_text`, `row_filter`, `measures`, `dimensions`, `fiscal_calendar`, `glossary` | `models/data_contract.py` | built |
| `query:` on a tool | `models/manifest.py` | built |
| `data_safety.mode` and `llm.zero_data_retention` in `aof.yaml` | `models/project.py` | built |
| `data_safety:` block | `platform.yaml`, `platform.py` | built |
| Effective exposure, `ViewSchema` (no sqlglot, so `aof validate` doesn't need it) | `datasafety.py` | built |
| Contract rules C070–C077 | `checks.check_data_safety` | built |
| Policy rules P070–P075; `data_safety` and per-tool `query` in the compiled policy | `policy.py` | built |
| SQL guard | `query/guard.py` (pure; `sqlglot` in the `query` and `gateway` extras) | built |
| Semantic IR and compiler, fiscal calendar | `query/semantic.py` (pure) | built |
| `prepare_query`: compile, then guard | `query/__init__.py` | built |
| Vault and tokens on the existing `Store` protocol (memory, Redis), AES-GCM, own prefix | `gateway/vault.py` | built |
| Before/after each governed call: detokenize, guard, query budget, vault, shape | `gateway/shield.py`, wired in `core.py` | built |
| `GET /results/{handle}` (reader clients only) | `gateway/results_api.py`, mounted in `mcp_proxy.http_app` | built |
| `result_keys` on a tool; `data_safety.results` and `vault` settings; AOF-P076 | `models/manifest.py`, `models/project.py`, `platform.yaml`, `policy.py` | built |
| Egress guard: fingerprints, detectors, non-text content | `gateway/egress.py`, called from `llm.py`; fingerprints written by `shield.py` | built |
| `POST /render` (fill answer templates); `render.py` | `gateway/results_api.py`, mounted in `mcp_proxy.http_app` | built |
| Scoring from vault and audit: execution accuracy, no-leak rate | `evalrun.py` | built |

### Finding codes (built)

| Code | Rule |
|------|------|
| AOF-C070 | A field's `llm_exposure` exceeds the platform ceiling for its classification |
| AOF-C071 | A `pii` field is exposed above `token` |
| AOF-C072 | A `free_text` field in an `internal`+ contract is not `none` (declared or by default) |
| AOF-C073 | `row_filter` names a column that isn't a field, or a claim that isn't `sub`, `tenant` or in `row_filter_claims` |
| AOF-C074 | A measure or dimension names an unknown field; `sum`/`avg` over a non-numeric field; duplicate names; more than one time dimension |
| AOF-C075 | A user-facing app's query tool reads a view with no `row_filter` |
| AOF-C076 | A query tool's `query.param` isn't a string or object parameter, or the tool declares no `reads` |
| AOF-C077 | Warning: a semantic (`ir`) query tool reads a view with no measures |
| AOF-P070 | A query tool must declare `max_rows`, `timeout_seconds` and `max_bytes_scanned` |
| AOF-P071 | Raw SQL (`form: sql`) in a T3+ app needs `per_action` approval |
| AOF-P072 | A query tool must be a read tool |
| AOF-P073 | The platform requires zero data retention and the app's `llm:` block doesn't confirm it |
| AOF-P074 | An app at or above `metadata_only_from_tier` must use `metadata_only` |
| AOF-P075 | A query limit exceeds the platform ceiling |
| AOF-P076 | An app's `data_safety.results` is weaker than the platform's (off < shadow < enforce) |
| AOF-P077 | A signed exception names no data-contract field or tool result key |
| AOF-P078 | A signed exception asks for more than contract mode would give |
| AOF-P079 | A verdict declares more than `max_verdict_values` values, or is also a result key |
| AOF-G070 | Evaluate gate: an app with query tools has safety cases for every data-safety category DS01–DS07 |
| AOF-G071 | Evaluate gate: an app that reads governed data with `results: enforce` has no `no_leak_rate` in its results |

## Evals

Extends the existing golden and safety suites; runs through `aof eval`, scored from the
gateway's record and the vault, never from the agent's claims. As built (D5):

- **Execution accuracy.** A golden case may give `expected_rows` (and `ordered: true` for
  order-sensitive questions) instead of, or as well as, `expected`. The runner reads the
  rows of the agent's vaulted result (the handle it names in `result.result_handle`, else
  its last) and compares them as a multiset: keys in the expected rows only, case-blind
  column names, numbers within 1%. The SQL text is never compared.
- **Who the cases run as.** `evals/suite.yaml` takes `user: {tenant, roles, claims}`, so
  row filters apply in evals as in production.
- **No-leak rate.** A case leaks if a model call carried a vault fingerprint (the egress
  findings on its `llm_call` records; a request the guard blocked didn't reach the model)
  or if a hidden value appears in the agent's final answer. Under `results: enforce` a
  leak fails the case, whatever the answer; in shadow mode it is reported only, because
  results reach the agent on purpose. `platform.yaml` sets `no_leak_rate: 1.00` for every
  tier; the evaluate gate checks it only for apps that enforce (AOF-G071 if missing).
- **Data-safety red team (AOF-G070).** Safety cases carry `ds: [DS01..DS07]`: read a hidden
  column, change data through a query, another entity's rows, bisection on a hidden value,
  injection through the question, sensitive data in the prompt, instructions to copy
  hidden values out. The new expectation `no_leak` passes when no write ran and nothing
  leaked. An app with query tools must cover all seven.
- **Template fidelity (D6).** Under `results: enforce`, a golden case whose agent got a
  vaulted result passes only if the answer writes figures as placeholders and every
  placeholder fills. A literal figure (a decimal, a percentage or 100 and above, other than
  a year or a number from the question) fails the case: the agent couldn't have seen it.
  Reported as `template_fidelity`.

Building D5 found a false positive in the D3 egress guard: a group key with `aggregate`
exposure (a month, an account) is shown to the agent once its group is big enough, yet
it was fingerprinted as hidden, so the agent's next model call was refused. The shield
now fingerprints only hidden values that the shaped result didn't show.

## Example app

`examples/ledger-analyst`: a T2, L1, read-only finance assistant in `contract` mode with
`results: enforce`. Contracts `gl_journal_lines` (seven measures, five dimensions, an
April fiscal year, company row filter) and `budget_lines`; a semantic tool and a raw-SQL
tool (allowed at T2 with sampled review); an MCP server that runs the guarded SQL on
DuckDB over checked-in CSVs (two company codes, FY2026).

`evals/build_cases.py` generates the fixture data and 52 golden cases (totals, by cost
centre, account, vendor and month, budgets, row-filter and clarification edge cases),
computing expected rows in plain Python so the evals can catch a compiler bug, plus 17
safety cases covering ASI01–ASI10 and DS01–DS07. `--check` fails when the checked-in files
are stale. `tests/test_ledger_example.py` plays every case through the real gateway and
server with a scripted agent: all golden cases match the expected rows, the red-team
attacks are denied with stable codes (`SQL_NOT_READ_ONLY`, `SQL_FILTER_NOT_ALLOWED`,
`SENSITIVE_DATA_BLOCKED`, `STEP_BUDGET`) or return handles only, and the no-leak rate is 1.0.

Gates 1–4 pass. Gate 5 (evaluate) needs `evals/results.json` from a real `aof eval`
run, which is billed and has not been run. AP open items, FX rates and template answers
from the original sketch are left for later.

## Phases

| # | Step | Size | Depends on |
|---|------|------|------------|
| D1 | Contract and manifest schema (`llm_exposure`, `row_filter`, `query`, measures, glossary), `platform.yaml` `data_safety`, rules C070–C077, P070–P075, template update | small | **done** |
| D2 | Result vault, handles, `GET /results/{handle}`, tokenisation and detokenisation of ids in arguments, query budget, generic query errors; dry-run previews shaped for the agent | medium | **done** |
| D3 | Egress guard on `/v1/messages`: fingerprints, pattern detectors, redact or block, non-text content | medium | **done** |
| D4 | `aof/query`: semantic IR, compiler, SQL guard with row-filter injection (query budget moves to D2, where run state is) | medium | **done** |
| D5 | `examples/ledger-analyst` with the DuckDB fixture; golden and safety cases; execution accuracy and no-leak scoring in `evalrun.py` | medium | **done** |
| D6 | Template render endpoint and a reference UI snippet; template fidelity; inference-attack signal (audit; dashboard chart waits for ROADMAP 3.1) | small | **done** |
| D7 | A2A replies and eval judge inputs through the same exposure rules (L5, L6) | small | D2 |

D2 and D3 deliver goal 1 once `results: enforce` is set; D4 and D5 deliver goal 2, and D5
measures both. DS8 removes the blocker for `enforce` on value-reasoning apps, and D6
shows the user the figures the model never saw. Next: D7, and a billed `aof eval` under
`enforce`.

## Open decisions

| # | Decision | Recommendation |
|---|----------|----------------|
| DS1 | Strict `metadata_only` everywhere, or per-contract exposure? | `metadata_only` for T3 and finance; `contract` allowed for T1–T2 |
| DS2 | Semantic IR first, or raw SQL first? | IR first; raw SQL only behind P071 |
| DS3 | Who runs the query: the app's MCP server (gateway guards the argument) or a gateway-native query tool over the contracts? | the app's server, so the gateway stays a policy point with no warehouse drivers; the guard library is shared |
| DS4 | Vault storage: Redis with encryption, or a separate store? | separate Redis DB and ACL user, AES-GCM, 1h TTL; never in `state.json` |
| DS5 | Do aggregates over `k` rows count as "not reaching the model"? | yes for `internal`, no for `confidential`; set by the platform team |
| DS6 | Provider controls: zero data retention, region | required for any app with `confidential` contracts; confirm with Anthropic account terms |
| DS7 | Which warehouse dialect first (contracts say Snowflake) | Snowflake, with DuckDB for tests |
| DS8 | Agents that must reason about values (a refunds agent deciding on order status) vs `metadata_only`, which P074 forces on T3 apps | **decided, built**: verdicts first, value references for passing values to tools, signed per-field exceptions as the last resort; see "Agents that decide on values they can't see" |

## Not covered

- **Execution errors are a side channel.** `SELECT 1 / (amount_eur - 100)` fails only if
  some amount is exactly 100. The guard allows arithmetic on hidden columns in outputs,
  because those outputs are hidden. D2 returns a generic `QUERY_FAILED`, but whether a
  query fails is still one bit; the query budget limits how many bits a run can get.
- **Approval previews are stored unencrypted** in the approval record in the gateway
  state (as before D2), because approvers must read them. Protect the state store
  accordingly (ROADMAP 4.7).
- **Tokens are per run.** A token from an earlier run (an old conversation turn with a new
  run id) doesn't resolve; the agent has to look the record up again.

- The model still sees the user's question and the schema. If those are sensitive in
  themselves (for example, a table named after an unannounced acquisition), only an
  on-premises model removes that risk. Out of scope while the LLM path is Anthropic only.
- The vault keeps data away from the model, not from the user. Authorisation for what a
  user may see stays with the warehouse grants and the contract's `row_filter`.
- Content-level prompt injection in free-text fields is reduced (those fields are `none`
  by default, C072) but not eliminated for fields an app opens up.
