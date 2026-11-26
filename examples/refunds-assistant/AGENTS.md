# AGENTS.md: Refunds Assistant

Instructions for coding agents working in this repo.

## What this repo is

An AOF-onboarded app. It exposes its capabilities as an MCP server (`src/server.py`).
Its onboarding contract lives in `aof.yaml`, `aof/`, `server.json` and `evals/`.

## Build and test

```bash
pip install 'aof[mcp]' pytest
aof validate .            # contract checks: must pass before any merge
aof check-server .        # server tools must match aof/tools.manifest.yaml
aof status .              # where the app is in the seven-stage lifecycle
```

## Rules

- When you add or change a tool, update `aof/tools.manifest.yaml` in the same change.
  Keep the description identical to the server's docstring.
- Every write tool needs an approval rule, scopes, a rate limit, reversibility and a dry-run mode.
- Tools read only governed data products declared in `aof/data-contracts/`.
- Add golden cases to `evals/golden.jsonl` for every new behaviour, including an `edge_case`.
- Never put credentials in code, prompts, memory or tool results.
