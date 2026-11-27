# AGENTS.md: Ledger Analyst

Instructions for coding agents working in this repo.

## What this repo is

An AOF-onboarded app for finance questions over the general ledger. The model writes a
semantic query (or SQL); the AOF gateway guards it, the MCP server in `src/server.py` runs
it, and the rows stay in the gateway's result vault. The model never sees an amount.

## Build and test

```bash
pip install 'aof[mcp,query]' duckdb pytest
aof validate .                       # contract checks: must pass before any merge
aof check-server .                   # server tools must match aof/tools.manifest.yaml
python evals/build_cases.py --check  # golden expected rows match the fixture ledger
```

## Rules

- Measures, dimensions and the fiscal calendar live in `aof/data-contracts/`. Add a metric
  there, then add golden cases for it in `evals/build_cases.py` and regenerate.
- Expected rows are computed in `build_cases.py` in plain Python, never by running the
  gateway's SQL: the evals must be able to catch a compiler bug.
- Don't loosen `llm_exposure` on `amount_eur`, `budget_eur` or `description`; that is a
  data-safety decision for the platform team (docs/data-safety.md, DS8).
- The server only executes what the gateway sends. Never add a tool that takes SQL from
  anywhere else.
