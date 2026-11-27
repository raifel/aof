"""`aof gateway ...`: run the gateway and operate it.

Operator commands (approvals, approve, kill, demote, ...) run in one of two modes:
  --gateway-url URL   production: call the gateway's /admin API with an operator token
                      (env AOF_OPERATOR_TOKEN); the identity comes from the verified token.
  local (default)     development: edit --state-dir directly; --by/--roles are claimed,
                      not verified.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path
from typing import Any

from ..enums import AutonomyLevel
from .approvals import ApprovalError, ApprovalService
from .audit import AuditLog, verify
from .compiled import load_policy
from .core import Gateway
from .identity import Principal
from .state import GatewayState, open_store

DEFAULT_STATE_DIR = ".aof-gateway"


def _csv(s: str | None) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _audit_path(args) -> Path:
    replica = getattr(args, "replica_id", None)
    return Path(args.state_dir) / (f"audit-{replica}.jsonl" if replica else "audit.jsonl")


def _state(args) -> tuple[GatewayState, AuditLog, ApprovalService]:
    store = open_store(getattr(args, "state_url", None), args.state_dir)
    state = GatewayState(store)
    return state, AuditLog(_audit_path(args), replica=getattr(args, "replica_id", None)), ApprovalService(store)


def _ts(t: float | None) -> str:
    return dt.datetime.fromtimestamp(t).isoformat(timespec="seconds") if t else "-"


def _obo_broker(args, policy):
    """The on-behalf-of broker, None when the gateway uses its own connection, or 2 on a
    configuration error."""
    ident = policy.identity
    endpoint = args.token_endpoint or ident.token_endpoint
    if ident.mode != "on_behalf_of" or args.no_obo:
        return None
    reason = None
    if not endpoint:
        reason = "no token endpoint (platform.yaml identity.token_endpoint or --token-endpoint)"
    elif args.transport != "http":
        reason = "stdio has no user token to exchange"
    elif not args.upstream_url:
        reason = "the app server is a stdio command; give --upstream-url"
    if reason:
        print(f"on-behalf-of exchange is OFF: {reason}. The gateway calls the app with its own "
              "connection; do not run user-facing apps like this in production.", file=sys.stderr)
        return None
    if not endpoint.startswith("https://") and not args.allow_insecure_idp:
        print("--token-endpoint must be https (user tokens are sent to it)", file=sys.stderr)
        return 2
    from .obo import OboBroker, TokenExchanger

    exchanger = TokenExchanger(endpoint, args.client_id or policy.agent.id,
                               os.environ.get(args.client_secret_env), max_ttl=ident.scope_ttl_seconds)
    print(f"on-behalf-of: exchanging user tokens at {endpoint} for audience "
          f"{ident.audience or args.upstream_url}", file=sys.stderr)
    return OboBroker(exchanger, audience=ident.audience or args.upstream_url, resource=args.upstream_url)


def _verifier(args, policy, public_url: str):
    """(token verifier, issuer URL), or (None, None) after printing why."""
    ident = policy.identity
    if args.tokens:
        print("DEV ONLY: tokens come from a static file and are not signed. Use the IdP "
              "(platform.yaml identity.issuer or --issuer-url) in production.", file=sys.stderr)
        from .identity import StaticTokenVerifier

        return StaticTokenVerifier(args.tokens), args.issuer_url or ident.issuer or "http://127.0.0.1:9000"
    issuer = args.issuer_url or ident.issuer
    if not issuer:
        print("http mode needs an IdP to verify tokens: set platform.yaml identity.issuer (or --issuer-url), "
              "or pass --tokens for local development", file=sys.stderr)
        return None, None
    from .jwt_verifier import IdentityConfigError, JwtVerifier

    if not issuer.startswith("https://") and not args.allow_insecure_idp:
        print("the issuer must be https", file=sys.stderr)
        return None, None
    audiences = args.audience or [public_url]
    try:
        verifier = JwtVerifier(issuer, audiences, jwks_uri=ident.jwks_uri, algorithms=ident.algorithms,
                               roles_claim=ident.roles_claim, tenant_claim=ident.tenant_claim,
                               leeway=ident.leeway_seconds)
    except IdentityConfigError as exc:
        print(str(exc), file=sys.stderr)
        return None, None
    print(f"identity: JWTs from {issuer} for audience {', '.join(audiences)}", file=sys.stderr)
    return verifier, issuer


def _vault(args, policy):
    """The result vault, or None (no data_safety in the policy), or 2 on a config error."""
    ds = policy.data_safety
    if not ds:
        return None
    from .state import DurableStore, RedisStore
    from .vault import KEY_ENV, ResultVault, VaultError, load_key

    url = args.vault_url or os.environ.get("AOF_VAULT_URL") or args.state_url
    try:
        key = load_key() if os.environ.get(KEY_ENV) or url else None
    except VaultError as exc:
        print(f"vault: {exc} (replicas must share the key to read each other's results)", file=sys.stderr)
        return 2
    store = RedisStore.from_url(url, prefix="aof:vault:") if url else DurableStore()
    v = ds.get("vault") or {}
    vault = ResultVault(store, key, ttl_seconds=int(v.get("ttl_seconds", 3600)),
                        max_bytes=int(v.get("max_bytes_per_result", 5_000_000)))
    where = f"shared at {url.split('@')[-1]}" if url else "in this process"
    note = "" if key else f"; per-process key, results are lost on restart (set {KEY_ENV})"
    print(f"data safety: results {ds.get('results')}, mode {ds.get('mode')}; vault {where}{note}", file=sys.stderr)
    return vault


def cmd_serve(args) -> int:
    try:
        from .mcp_proxy import McpUpstream, http_app, serve_stdio
    except ImportError:
        print("the gateway needs the MCP SDK: pip install 'aof[gateway]'", file=sys.stderr)
        return 2
    policy = load_policy(args.policy)
    if args.state_url and not args.replica_id:
        import socket

        args.replica_id = socket.gethostname()
    try:
        state, audit, approvals = _state(args)
    except (ValueError, ImportError) as exc:
        print(f"cannot open gateway state: {exc}", file=sys.stderr)
        return 2
    if args.state_url:
        print(f"state: shared at {args.state_url.split('@')[-1]} (replica {args.replica_id})", file=sys.stderr)
    else:
        print(f"state: {args.state_dir}/state.json, rate and budget counters in this process only. "
              "Use --state-url to run more than one replica.", file=sys.stderr)
    command = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    if not args.upstream_url and not command:
        print("give the app server: --upstream-url URL or -- <command>", file=sys.stderr)
        return 2
    obo = _obo_broker(args, policy)
    if obo == 2:
        return 2
    if args.upstream_url:
        upstream = McpUpstream(args.upstream_url, per_user=obo is not None)
    else:
        upstream = McpUpstream.stdio(command, cwd=args.cwd)
    vault = _vault(args, policy)
    if vault == 2:
        return 2
    gateway = Gateway(policy, upstream, state=state, audit=audit, approvals=approvals,
                      auto_demote=not args.no_auto_demote, obo=obo, vault=vault)
    audit.append("gateway_started", agent=policy.agent.id, transport=args.transport,
                 state="shared" if args.state_url else "local",
                 autonomy_level=policy.agent.autonomy_level.value,
                 upstream_credential="on_behalf_of" if obo else "gateway_connection")

    if args.transport == "stdio":
        if not args.user:
            print("stdio mode needs --user (and --scopes) for the person the agent acts for", file=sys.stderr)
            return 2
        principal = Principal.of(args.user, _csv(args.scopes), _csv(args.roles))
        asyncio.run(serve_stdio(gateway, upstream, principal))
        return 0

    public_url = args.public_url or f"http://{args.host}:{args.port}/mcp"
    verifier, issuer = _verifier(args, policy, public_url)
    if verifier is None:
        return 2
    import uvicorn

    llm_proxy = None
    if policy.llm is not None and not args.no_llm:
        try:
            from .llm import AnthropicProvider, LlmProxy

            llm_proxy = LlmProxy(gateway, AnthropicProvider())
        except ImportError:
            print("policy has an llm section but the anthropic SDK is missing: pip install 'aof[gateway]'",
                  file=sys.stderr)
            return 2
    a2a_proxy = None
    a2a = policy.a2a
    if (a2a.peers or a2a.allowed_callers) and not args.no_a2a:
        from .a2a_proxy import A2aProxy

        base_url = (args.public_url or f"http://{args.host}:{args.port}/mcp").rsplit("/mcp", 1)[0]
        a2a_proxy = A2aProxy(gateway, upstream_url=args.a2a_upstream_url, public_url=f"{base_url}/a2a")
        if not a2a.enabled:
            print(f"a2a configured but the agent is at {policy.agent.autonomy_level.value}: "
                  "every A2A call will be denied until it reaches L4", file=sys.stderr)
    app = http_app(gateway, upstream, verifier, issuer_url=issuer, public_url=public_url, host=args.host,
                   llm_proxy=llm_proxy, a2a_proxy=a2a_proxy, admin=not args.no_admin)
    if a2a_proxy:
        print(f"agent-to-agent: POST http://{args.host}:{args.port}/a2a/peers/<peer> "
              f"(peers: {', '.join(p.name for p in a2a.peers) or '-'}); inbound POST /a2a"
              + ("" if args.a2a_upstream_url else " disabled (no --a2a-upstream-url)"), file=sys.stderr)
    if llm_proxy:
        print(f"model calls: POST http://{args.host}:{args.port}/v1/messages "
              f"(models: {', '.join(policy.llm.models)})", file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def _admin_client(base_url: str):
    import httpx2

    return httpx2.AsyncClient(base_url=base_url, timeout=30.0)


def _remote(args, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
    token = os.environ.get(args.token_env)
    if not token:
        print(f"set {args.token_env} to an operator access token from the IdP", file=sys.stderr)
        return 2, None

    async def go():
        async with _admin_client(args.gateway_url) as client:
            res = await client.request(method, path, json=body, headers={"authorization": f"Bearer {token}"})
            try:
                return res.status_code, res.json()
            except ValueError:
                return res.status_code, {"error": f"HTTP_{res.status_code}", "reason": res.text[:200]}

    return asyncio.run(go())


def _remote_failed(status: int, data: Any) -> int | None:
    if status == 2 and data is None:
        return 2
    if status >= 400:
        print(f"{data.get('error')}: {data.get('reason')}", file=sys.stderr)
        return 1
    return None


def _local(args) -> bool:
    """Local mode needs --by; say that it is not verified."""
    if not getattr(args, "by", None):
        print("give --gateway-url (production) or --by (local development)", file=sys.stderr)
        return False
    print("local mode: --by/--roles are claimed, not verified. Use --gateway-url in production.",
          file=sys.stderr)
    return True


def _print_approvals(items: list[dict], args) -> None:
    if args.json:
        print(json.dumps(items, indent=2, default=str))
        return
    if not items:
        print(f"No {args.status} approvals.")
    for a in items:
        print(f"{a['id']}  {a['status']:9} {a['tool']}  user={a['user_id']}  agent={a['agent_id']}  "
              f"role={a['approver_role'] or '-'}  created={_ts(a['created_at'])}  expires={_ts(a['expires_at'])}")
        print(f"    args:    {json.dumps(a['args'], default=str)}")
        print(f"    preview: {json.dumps(a['preview'], default=str)}")


def cmd_approvals(args) -> int:
    if args.gateway_url:
        status, data = _remote(args, "GET", f"/admin/approvals?status={args.status}")
        failed = _remote_failed(status, data)
        if failed is not None:
            return failed
        _print_approvals(data, args)
        return 0
    _, _, approvals = _state(args)
    _print_approvals([dict(a.__dict__) for a in approvals.list(None if args.status == "all" else args.status)], args)
    return 0


def _decide(args, approve: bool) -> int:
    verb = "approve" if approve else "reject"
    if args.gateway_url:
        status, data = _remote(args, "POST", f"/admin/approvals/{args.approval_id}/{verb}", {"note": args.note})
        failed = _remote_failed(status, data)
        if failed is not None:
            return failed
        print(f"{data['id']} {data['status']} by {data['decided_by']}")
        return 0
    if not _local(args):
        return 2
    _, audit, approvals = _state(args)
    approver = Principal.of(args.by, roles=_csv(args.roles))
    try:
        a = (approvals.approve if approve else approvals.reject)(args.approval_id, approver, note=args.note)
    except ApprovalError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 1
    audit.append("approval_decided", approval_id=a.id, agent=a.agent_id, tool=a.tool, user=a.user_id,
                 decision=a.status, decided_by=args.by, verified=False)
    print(f"{a.id} {a.status} by {args.by}")
    return 0


def _operator(args, path: str, body: dict, local, done: str) -> int:
    if args.gateway_url:
        status, data = _remote(args, "POST", path, {"agent": args.agent, **body})
        failed = _remote_failed(status, data)
        if failed is not None:
            return failed
        print(done)
        return 0
    if not _local(args):
        return 2
    state, audit, _ = _state(args)
    return local(state, audit)


def cmd_kill(args) -> int:
    def local(state, audit):
        state.kill(args.agent, by=args.by, reason=args.reason)
        audit.append("kill_switch_on", agent=args.agent, by=args.by, reason=args.reason, verified=False)
        print(f"{args.agent} disabled. Every call is now denied.")
        return 0

    return _operator(args, "/admin/kill", {"reason": args.reason}, local,
                     f"{args.agent} disabled. Every call is now denied.")


def cmd_revive(args) -> int:
    def local(state, audit):
        if not state.revive(args.agent):
            print(f"{args.agent} was not disabled.")
            return 1
        audit.append("kill_switch_off", agent=args.agent, by=args.by, verified=False)
        print(f"{args.agent} re-enabled at its current approved level.")
        return 0

    return _operator(args, "/admin/revive", {}, local, f"{args.agent} re-enabled at its current approved level.")


def cmd_demote(args) -> int:
    level = AutonomyLevel(args.to)

    def local(state, audit):
        state.demote(args.agent, level, by=args.by, reason=args.reason)
        audit.append("autonomy_demoted", agent=args.agent, to_level=level.value, by=args.by, reason=args.reason,
                     verified=False)
        print(f"{args.agent} capped at {level.value}.")
        return 0

    return _operator(args, "/admin/demote", {"to": level.value, "reason": args.reason}, local,
                     f"{args.agent} capped at {level.value}.")


def cmd_restore(args) -> int:
    def local(state, audit):
        if not state.clear_demotion(args.agent):
            print(f"{args.agent} has no demotion.")
            return 1
        audit.append("autonomy_restored", agent=args.agent, by=args.by, verified=False)
        print(f"{args.agent} restored to its compiled level.")
        return 0

    return _operator(args, "/admin/restore", {}, local, f"{args.agent} restored to its compiled level.")


def cmd_audit(args) -> int:
    """Every chain in --state-dir: audit.jsonl and one audit-<replica>.jsonl per replica."""
    files = sorted(Path(args.state_dir).glob("audit*.jsonl"))
    chains = {f.name: AuditLog(f).read() for f in files}
    if args.verify:
        if not chains:
            print(f"no audit logs in {args.state_dir}")
            return 1
        failed = 0
        for name, records in chains.items():
            ok, bad = verify(records)
            failed += not ok
            print(f"{name}: chain OK ({len(records)} records)" if ok else f"{name}: chain BROKEN at seq {bad}")
        return 1 if failed else 0
    merged = sorted((r for records in chains.values() for r in records), key=lambda r: r.get("ts", 0))
    for r in merged[-args.tail:]:
        print(json.dumps(r, default=str))
    return 0


INCIDENT_EVENTS = ("kill_switch_on", "autonomy_demoted")


def cmd_pilot_report(args) -> int:
    """Pilot results from the audit logs of a supervised (L2) pilot: every write the agent
    proposed went to a human, so approved / decided is the agreement rate."""
    start = dt.date.fromisoformat(args.since)
    end = dt.date.fromisoformat(args.until) if args.until else dt.date.today()
    lo = dt.datetime.combine(start, dt.time.min).timestamp()
    hi = dt.datetime.combine(end, dt.time.max).timestamp()
    records = [r for f in sorted(Path(args.state_dir).glob("audit*.jsonl")) for r in AuditLog(f).read()
               if lo <= r.get("ts", 0) <= hi and r.get("agent") == args.agent]
    proposals = sum(1 for r in records if r["event"] == "approval_requested")
    decided = [r for r in records if r["event"] == "approval_decided"]
    approved = sum(1 for r in decided if r.get("decision") == "approved")
    incidents = sum(1 for r in records if r["event"] in INCIDENT_EVENTS)
    if not decided:
        print(f"no human decisions for {args.agent} between {start} and {end}: nothing to report",
              file=sys.stderr)
        return 1
    from ..outcomes import compute_measures

    report = {
        "window_start": start.isoformat(), "window_end": end.isoformat(), "proposals": proposals,
        "agreement_rate": round(approved / len(decided), 4), "incidents": incidents,
        "decided": len(decided), "approved": approved, "source": "aof gateway audit logs",
        "measures": compute_measures(records),  # what use-case outcome_metrics are checked against
    }
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text)
        print(f"Wrote {args.output}")
    else:
        print(text, end="")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    g = sub.add_parser("gateway", help="run and operate the agent gateway")
    gs = g.add_subparsers(dest="gateway_cmd", required=True)

    def with_state(p):
        p.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help="audit logs (and state, without --state-url)")
        p.add_argument("--state-url", default=os.environ.get("AOF_STATE_URL"),
                       help="shared state for several replicas, e.g. rediss://redis:6380/0 (env AOF_STATE_URL)")
        return p

    def operator(p):
        with_state(p)
        p.add_argument("--gateway-url", help="production: the gateway's base URL (uses its /admin API)")
        p.add_argument("--token-env", default="AOF_OPERATOR_TOKEN", help="env var with the operator's token")
        return p

    s = with_state(gs.add_parser("serve", help="serve an app's MCP server through the gateway"))
    s.add_argument("--policy", required=True, help="compiled gateway-policy.json")
    s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--upstream-url", help="app MCP server URL (streamable HTTP)")
    s.add_argument("--cwd", help="working directory for a stdio upstream")
    s.add_argument("--user", help="stdio: the user the agent acts for")
    s.add_argument("--scopes", help="stdio: comma-separated scopes of that user")
    s.add_argument("--roles", help="stdio: comma-separated roles")
    s.add_argument("--tokens", help="http: DEV token file for StaticTokenVerifier")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--issuer-url", help="http: the IdP issuer (default: platform.yaml identity.issuer)")
    s.add_argument("--audience", action="append", help="http: token audience(s) accepted (default: --public-url)")
    s.add_argument("--no-admin", action="store_true", help="http: do not serve the /admin operator API")
    s.add_argument("--vault-url", help="Redis URL for the result vault, ideally its own ACL user "
                                       "(default: AOF_VAULT_URL, then --state-url); needs AOF_VAULT_KEY")
    s.add_argument("--public-url", help="http: this gateway's public /mcp URL")
    s.add_argument("--no-auto-demote", action="store_true")
    s.add_argument("--replica-id", default=os.environ.get("AOF_REPLICA_ID"),
                   help="this replica's name: its audit chain is audit-<id>.jsonl (default with --state-url: "
                        "the host name)")
    s.add_argument("--no-llm", action="store_true", help="http: do not serve /v1/messages")
    s.add_argument("--no-a2a", action="store_true", help="http: do not serve the A2A routes")
    s.add_argument("--token-endpoint", help="http: IdP token endpoint for on-behalf-of exchange "
                   "(default: from the policy)")
    s.add_argument("--client-id", help="the gateway's OAuth client id at the IdP (default: the agent id)")
    s.add_argument("--client-secret-env", default="AOF_GATEWAY_CLIENT_SECRET",
                   help="env var holding the gateway's OAuth client secret")
    s.add_argument("--no-obo", action="store_true", help="call the app with the gateway's own connection")
    s.add_argument("--allow-insecure-idp", action="store_true", help=argparse.SUPPRESS)  # local IdP stubs
    s.add_argument("--a2a-upstream-url", help="http: the app's own A2A JSON-RPC endpoint (inbound calls)")
    s.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <app server command>")
    s.set_defaults(fn=cmd_serve)

    s = operator(gs.add_parser("approvals", help="list approval requests"))
    s.add_argument("--status", default="pending", choices=["pending", "approved", "rejected", "consumed", "all"])
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_approvals)

    for name, approve in (("approve", True), ("reject", False)):
        s = operator(gs.add_parser(name, help=f"{name} one approval request"))
        s.add_argument("approval_id")
        s.add_argument("--by", help="local mode: who decides (not verified)")
        s.add_argument("--roles", help="local mode: comma-separated roles of the approver (not verified)")
        s.add_argument("--note")
        s.set_defaults(fn=lambda a, _approve=approve: _decide(a, _approve))

    s = operator(gs.add_parser("kill", help="kill switch: deny every call from an agent"))
    s.add_argument("agent")
    s.add_argument("--by", help="local mode: who (not verified)")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_kill)

    s = operator(gs.add_parser("revive", help="turn the kill switch off"))
    s.add_argument("agent")
    s.add_argument("--by", help="local mode: who (not verified)")
    s.set_defaults(fn=cmd_revive)

    s = operator(gs.add_parser("demote", help="cap an agent's autonomy level"))
    s.add_argument("agent")
    s.add_argument("--to", required=True, choices=[lvl.value for lvl in AutonomyLevel])
    s.add_argument("--by", help="local mode: who (not verified)")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_demote)

    s = operator(gs.add_parser("restore", help="remove a demotion"))
    s.add_argument("agent")
    s.add_argument("--by", help="local mode: who (not verified)")
    s.set_defaults(fn=cmd_restore)

    s = with_state(gs.add_parser("pilot-report", help="write pilot results (agreement, incidents) from the audit logs"))
    s.add_argument("agent", help="agent id, e.g. agent:refunds-assistant")
    s.add_argument("--since", required=True, help="first day of the pilot window (YYYY-MM-DD)")
    s.add_argument("--until", help="last day (default: today)")
    s.add_argument("-o", "--output", help="e.g. evals/pilot.json (default: print)")
    s.set_defaults(fn=cmd_pilot_report)

    s = with_state(gs.add_parser("audit", help="show or verify the audit log"))
    s.add_argument("--verify", action="store_true")
    s.add_argument("--tail", type=int, default=20)
    s.set_defaults(fn=cmd_audit)
