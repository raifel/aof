"""`aof gateway ...`: run the gateway and operate it.

Operator commands (approve, kill, demote) assert the operator's identity with --by
and --roles. That is fine for local use; in production put them behind SSO (an
approval UI or an admin API) so the identity is verified, not claimed.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import sys
from pathlib import Path

from ..enums import AutonomyLevel
from .approvals import ApprovalError, ApprovalService
from .audit import AuditLog, verify
from .compiled import load_policy
from .core import Gateway
from .identity import Principal
from .state import DurableStore, GatewayState

DEFAULT_STATE_DIR = ".aof-gateway"


def _csv(s: str | None) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _paths(args) -> tuple[Path, Path]:
    d = Path(args.state_dir)
    return d / "state.json", d / "audit.jsonl"


def _state(args) -> tuple[GatewayState, AuditLog, ApprovalService]:
    state_path, audit_path = _paths(args)
    state = GatewayState(DurableStore(state_path))
    return state, AuditLog(audit_path), ApprovalService(state.store)


def _ts(t: float | None) -> str:
    return dt.datetime.fromtimestamp(t).isoformat(timespec="seconds") if t else "-"


def cmd_serve(args) -> int:
    try:
        from .mcp_proxy import McpUpstream, http_app, serve_stdio
    except ImportError:
        print("the gateway needs the MCP SDK: pip install 'aof[gateway]'", file=sys.stderr)
        return 2
    policy = load_policy(args.policy)
    state, audit, approvals = _state(args)
    command = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    if args.upstream_url:
        upstream = McpUpstream(args.upstream_url)
    elif command:
        upstream = McpUpstream.stdio(command, cwd=args.cwd)
    else:
        print("give the app server: --upstream-url URL or -- <command>", file=sys.stderr)
        return 2
    gateway = Gateway(policy, upstream, state=state, audit=audit, approvals=approvals,
                      auto_demote=not args.no_auto_demote)
    audit.append("gateway_started", agent=policy.agent.id, transport=args.transport,
                 autonomy_level=policy.agent.autonomy_level.value)

    if args.transport == "stdio":
        if not args.user:
            print("stdio mode needs --user (and --scopes) for the person the agent acts for", file=sys.stderr)
            return 2
        principal = Principal.of(args.user, _csv(args.scopes), _csv(args.roles))
        asyncio.run(serve_stdio(gateway, upstream, principal))
        return 0

    if not args.tokens:
        print("http mode needs --tokens (dev) or code that passes your IdP's TokenVerifier", file=sys.stderr)
        return 2
    import uvicorn

    from .identity import StaticTokenVerifier

    llm_proxy = None
    if policy.llm is not None and not args.no_llm:
        try:
            from .llm import AnthropicProvider, LlmProxy

            llm_proxy = LlmProxy(gateway, AnthropicProvider())
        except ImportError:
            print("policy has an llm section but the anthropic SDK is missing: pip install 'aof[gateway]'",
                  file=sys.stderr)
            return 2
    public_url = args.public_url or f"http://{args.host}:{args.port}/mcp"
    app = http_app(gateway, upstream, StaticTokenVerifier(args.tokens), issuer_url=args.issuer_url,
                   public_url=public_url, host=args.host, llm_proxy=llm_proxy)
    if llm_proxy:
        print(f"model calls: POST http://{args.host}:{args.port}/v1/messages "
              f"(models: {', '.join(policy.llm.models)})", file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_approvals(args) -> int:
    _, _, approvals = _state(args)
    items = approvals.list(None if args.status == "all" else args.status)
    if args.json:
        print(json.dumps([a.__dict__ for a in items], indent=2, default=str))
        return 0
    if not items:
        print(f"No {args.status} approvals.")
    for a in items:
        print(f"{a.id}  {a.status:9} {a.tool}  user={a.user_id}  agent={a.agent_id}  "
              f"role={a.approver_role or '-'}  created={_ts(a.created_at)}  expires={_ts(a.expires_at)}")
        print(f"    args:    {json.dumps(a.args, default=str)}")
        print(f"    preview: {json.dumps(a.preview, default=str)}")
    return 0


def _decide(args, approve: bool) -> int:
    _, audit, approvals = _state(args)
    approver = Principal.of(args.by, roles=_csv(args.roles))
    try:
        a = (approvals.approve if approve else approvals.reject)(args.approval_id, approver, note=args.note)
    except ApprovalError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 1
    audit.append("approval_decided", approval_id=a.id, agent=a.agent_id, tool=a.tool, user=a.user_id,
                 decision=a.status, decided_by=args.by)
    print(f"{a.id} {a.status} by {args.by}")
    return 0


def cmd_kill(args) -> int:
    state, audit, _ = _state(args)
    state.kill(args.agent, by=args.by, reason=args.reason)
    audit.append("kill_switch_on", agent=args.agent, by=args.by, reason=args.reason)
    print(f"{args.agent} disabled. Every call is now denied.")
    return 0


def cmd_revive(args) -> int:
    state, audit, _ = _state(args)
    if not state.revive(args.agent):
        print(f"{args.agent} was not disabled.")
        return 1
    audit.append("kill_switch_off", agent=args.agent, by=args.by)
    print(f"{args.agent} re-enabled at its current approved level.")
    return 0


def cmd_demote(args) -> int:
    state, audit, _ = _state(args)
    level = AutonomyLevel(args.to)
    state.demote(args.agent, level, by=args.by, reason=args.reason)
    audit.append("autonomy_demoted", agent=args.agent, to_level=level.value, by=args.by, reason=args.reason)
    print(f"{args.agent} capped at {level.value}.")
    return 0


def cmd_restore(args) -> int:
    state, audit, _ = _state(args)
    if not state.clear_demotion(args.agent):
        print(f"{args.agent} has no demotion.")
        return 1
    audit.append("autonomy_restored", agent=args.agent, by=args.by)
    print(f"{args.agent} restored to its compiled level.")
    return 0


def cmd_audit(args) -> int:
    _, audit, _ = _state(args)
    records = audit.read()
    if args.verify:
        ok, bad = verify(records)
        print(f"audit chain OK ({len(records)} records)" if ok else f"audit chain BROKEN at seq {bad}")
        return 0 if ok else 1
    for r in records[-args.tail:]:
        print(json.dumps(r, default=str))
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    g = sub.add_parser("gateway", help="run and operate the agent gateway")
    gs = g.add_subparsers(dest="gateway_cmd", required=True)

    def with_state(p):
        p.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help="durable state + audit log")
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
    s.add_argument("--issuer-url", default="http://127.0.0.1:9000", help="http: OAuth issuer")
    s.add_argument("--public-url", help="http: this gateway's public /mcp URL")
    s.add_argument("--no-auto-demote", action="store_true")
    s.add_argument("--no-llm", action="store_true", help="http: do not serve /v1/messages")
    s.add_argument("upstream", nargs=argparse.REMAINDER, help="-- <app server command>")
    s.set_defaults(fn=cmd_serve)

    s = with_state(gs.add_parser("approvals", help="list approval requests"))
    s.add_argument("--status", default="pending", choices=["pending", "approved", "rejected", "consumed", "all"])
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_approvals)

    for name, approve in (("approve", True), ("reject", False)):
        s = with_state(gs.add_parser(name, help=f"{name} one approval request"))
        s.add_argument("approval_id")
        s.add_argument("--by", required=True)
        s.add_argument("--roles", help="comma-separated roles of the approver")
        s.add_argument("--note")
        s.set_defaults(fn=lambda a, _approve=approve: _decide(a, _approve))

    s = with_state(gs.add_parser("kill", help="kill switch: deny every call from an agent"))
    s.add_argument("agent")
    s.add_argument("--by", required=True)
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_kill)

    s = with_state(gs.add_parser("revive", help="turn the kill switch off"))
    s.add_argument("agent")
    s.add_argument("--by", required=True)
    s.set_defaults(fn=cmd_revive)

    s = with_state(gs.add_parser("demote", help="cap an agent's autonomy level"))
    s.add_argument("agent")
    s.add_argument("--to", required=True, choices=[lvl.value for lvl in AutonomyLevel])
    s.add_argument("--by", required=True)
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_demote)

    s = with_state(gs.add_parser("restore", help="remove a demotion"))
    s.add_argument("agent")
    s.add_argument("--by", required=True)
    s.set_defaults(fn=cmd_restore)

    s = with_state(gs.add_parser("audit", help="show or verify the audit log"))
    s.add_argument("--verify", action="store_true")
    s.add_argument("--tail", type=int, default=20)
    s.set_defaults(fn=cmd_audit)
