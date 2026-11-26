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
- Gateway: keep `engine.py` free of I/O and transport code; MCP specifics belong in `mcp_proxy.py`.
- Every gateway decision must be written to the audit log, and a denial must return a stable `error` code the model can act on.
