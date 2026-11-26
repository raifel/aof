# Live smoke tests

These talk to real services, so they never run as part of `pytest`. Run them on demand:

```bash
AOF_LIVE=1 .venv/bin/pytest -m live tests/live -v -s
```

Each test skips unless its variables are set, so you can run any subset.

| Test | Variables | Cost |
| --- | --- | --- |
| Redis store contract and race | `AOF_LIVE_REDIS_URL` (e.g. `redis://localhost:6379/15`; Redis 6.0+) | free; keys use a random prefix and are deleted afterwards |
| IdP token verification | `AOF_LIVE_ISSUER`, `AOF_LIVE_AUDIENCE`, `AOF_LIVE_TOKEN` (a current access token), optional `AOF_LIVE_ROLES_CLAIM` | free |
| Token exchange (RFC 8693) | `AOF_LIVE_TOKEN_ENDPOINT`, `AOF_LIVE_CLIENT_ID`, `AOF_LIVE_CLIENT_SECRET`, `AOF_LIVE_TOKEN`, `AOF_LIVE_OBO_AUDIENCE`, optional `AOF_LIVE_OBO_SCOPES` | free |
| Claude through the gateway | `ANTHROPIC_API_KEY`, optional `AOF_LIVE_MODEL` (default `claude-haiku-5-5`) | 2 tiny calls, a fraction of a cent |
| Eval smoke (2 cases) | `ANTHROPIC_API_KEY` and `AOF_LIVE_EVAL=1` | a few cents with `claude-opus-5-5` |

Keep secrets in your shell or a local `.env` you don't commit. The tests print what they
verified (subject, scopes, cost), never tokens.
