# AGENTS.md: AOF contract kit

## Build and test

```bash
uv venv && uv pip install --python .venv/bin/python -e '.[dev,gateway]'
.venv/bin/pytest -q
.venv/bin/aof status examples/refunds-assistant
```

## Conventions

- Every check returns `Finding`s with a stable code (`AOF-<S|C|P|L|E|G><nnn>`). Never reuse a code for a different rule.
- Add a test for each new rule, usually by editing a copy of `examples/refunds-assistant` (see `tests/conftest.py`).
- AOF-owned schemas use `Strict` (unknown keys fail). Schemas that mirror external specs (MCP Registry, A2A) use `Open`.
- Platform numbers belong in `src/aof/platform.yaml`, never hard-coded in checks.
- The template in `src/aof/templates/app` must keep passing `aof validate` after `aof init` (tested).
- Gateway: keep `engine.py` free of I/O and transport code; MCP specifics belong in `mcp_proxy.py`, Claude API specifics in `llm.py` (official `anthropic` SDK only, behind the `LlmProvider` protocol).
- A2A specifics belong in `a2a_proxy.py`. It forwards JSON-RPC payloads unchanged; the a2a-sdk is a test dependency only (end-to-end tests in `tests/test_gateway_a2a.py`).
- Upstream credentials: token exchange lives in `obo.py`. Exchange only after the policy allows a call, fail closed (never fall back to the gateway's own connection when exchange was configured), and never log a token.
- Identity: `jwt_verifier.py` is the production `TokenVerifier`; `StaticTokenVerifier` is dev only. Never accept symmetric (HS*) or `none` algorithms. Operator actions in production go through `admin.py`, with the decider taken from the verified token, never from a request field.
- State: everything shared goes through the `Store` protocol in `state.py` (memory, file, Redis). A check that guards a limit must be atomic in the store (`window_acquire`, `RunState.reserve`, `Store.update`), never a read followed by a later write. Race tests in `tests/test_gateway_replicas.py` run against fakeredis.
- Model prices live in `platform.yaml` under `llm.pricing_usd_per_mtok`. Tests never call the real API: use `FakeProvider` or the in-process fake Messages API in `tests/test_gateway_llm.py`.
- Every gateway decision must be written to the audit log, and a denial must return a stable `error` code the model can act on.
