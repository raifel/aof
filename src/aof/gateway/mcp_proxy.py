"""MCP virtualisation: one MCP endpoint in front of an app's MCP server.

Agents connect to the gateway as if it were the app's server. They see only the
tools their user may call, and every call goes through `Gateway.call_tool`.

Per-call context comes from the request `_meta`:
  aof/run_id            groups calls into one agent run (budgets); defaults to the session
  aof/delegation_depth  A2A hop count, set by the orchestrator

Credentials towards the app: with on-behalf-of exchange (see obo.py) every call opens
its own connection to the app's server carrying the exchanged, per-user, per-tool
token, so no connection is ever shared between users. Without it the gateway uses one
connection of its own. On-behalf-of needs a URL (streamable HTTP) upstream.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any, Callable

import mcp.types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel import Server

from .. import __version__
from .core import Gateway, ToolResult, UpstreamTool
from .identity import Principal, principal_from_access_token

PrincipalResolver = Callable[[Any], Principal]


def _payload(result: types.CallToolResult) -> Any:
    if result.structured_content is not None:
        return result.structured_content
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except json.JSONDecodeError:
            return texts[0]
    return texts


class McpUpstream:
    """The app's MCP server: a URL (streamable HTTP), a stdio command, or an in-process server.

    per_user=True (on-behalf-of): no shared connection is opened; each call connects with the
    token it is given. `http_client_factory(headers)` builds the HTTP client for that
    connection (override it for mTLS or tests).
    """

    def __init__(self, target: Any, *, per_user: bool = False, http_client_factory=None):
        if per_user and not isinstance(target, str):
            raise ValueError("on-behalf-of credentials need a URL (streamable HTTP) upstream")
        self._target = target
        self._client: Client | None = None
        self.per_user = per_user
        self._http_client_factory = http_client_factory

    @property
    def url(self) -> str | None:
        return self._target if isinstance(self._target, str) else None

    @classmethod
    def stdio(cls, command: list[str], cwd: str | None = None) -> "McpUpstream":
        return cls(StdioServerParameters(command=command[0], args=command[1:], cwd=cwd))

    async def __aenter__(self) -> "McpUpstream":
        if not self.per_user:
            self._client = Client(self._target)
            await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.__aexit__(*exc)
            self._client = None

    @contextlib.asynccontextmanager
    async def _session(self, token: str | None):
        if token is None:
            if self._client is None:
                raise RuntimeError("no user token for a per-user upstream")
            yield self._client
            return
        if self.url is None:
            raise RuntimeError("on-behalf-of tokens need a URL upstream")
        import httpx2
        from mcp.client.streamable_http import streamable_http_client

        headers = {"authorization": f"Bearer {token}"}
        factory = self._http_client_factory or (lambda h: httpx2.AsyncClient(headers=h, timeout=30.0))
        async with factory(headers) as http, Client(streamable_http_client(self.url, http_client=http)) as client:
            yield client

    async def list_tools(self, token: str | None = None) -> list[UpstreamTool]:
        async with self._session(token) as client:
            res = await client.list_tools()
        return [UpstreamTool(t.name, t.description or "", t.input_schema, t.annotations) for t in res.tools]

    async def call_tool(self, name: str, args: dict[str, Any], token: str | None = None) -> ToolResult:
        async with self._session(token) as client:
            res = await client.call_tool(name, args)
        return ToolResult(_payload(res), bool(res.is_error))


def _to_mcp(result: ToolResult) -> types.CallToolResult:
    content = result.content
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(content, default=str))],
        structured_content=content if isinstance(content, dict) else None,
        is_error=result.is_error,
    )


def _meta(params: Any, ctx: Any) -> dict[str, Any]:
    return dict(getattr(params, "meta", None) or getattr(ctx, "meta", None) or {})


def build_server(gateway: Gateway, resolve_principal: PrincipalResolver) -> Server:
    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        tools = await gateway.visible_tools(resolve_principal(ctx))
        return types.ListToolsResult(tools=[
            types.Tool(name=t.name, description=t.description, input_schema=t.input_schema,
                       annotations=t.annotations)
            for t in tools
        ])

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        meta = _meta(params, ctx)
        run_id = str(meta.get("aof/run_id") or f"session-{id(ctx.session):x}")
        depth = int(meta.get("aof/delegation_depth", 0) or 0)
        result = await gateway.call_tool(resolve_principal(ctx), params.name, params.arguments or {},
                                         run_id=run_id, delegation_depth=depth,
                                         call_id=str(ctx.request_id) if ctx.request_id is not None else None)
        return _to_mcp(result)

    return Server(
        "aof-gateway",
        version=__version__,
        instructions=f"AOF agent gateway for {gateway.agent_id}. Every call is authorised and audited.",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def fixed_principal(principal: Principal) -> PrincipalResolver:
    """stdio / local development: one user for the whole process."""
    return lambda ctx: principal


def token_principal(ctx: Any) -> Principal:
    """HTTP: the user from the verified bearer token (set by the SDK's auth middleware)."""
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None:
        raise PermissionError("no authenticated user on this request")
    return principal_from_access_token(token)


async def serve_stdio(gateway: Gateway, upstream: McpUpstream, principal: Principal) -> None:
    from mcp.server.stdio import stdio_server

    server = build_server(gateway, fixed_principal(principal))
    async with upstream, stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def http_app(gateway: Gateway, upstream: McpUpstream, token_verifier, *, issuer_url: str,
             public_url: str, host: str = "127.0.0.1", llm_proxy=None, a2a_proxy=None):
    """A Starlette app: /mcp for tools, /v1/messages for model calls (with an LlmProxy) and
    /a2a for agent-to-agent calls (with an A2aProxy). The upstream lives for the app's lifetime."""
    from mcp.server.auth.settings import AuthSettings

    routes = []
    if llm_proxy is not None:
        from .llm import llm_route

        routes.append(llm_route(llm_proxy, token_verifier))
    if a2a_proxy is not None:
        from .a2a_proxy import a2a_routes

        routes.extend(a2a_routes(a2a_proxy, token_verifier))
    server = build_server(gateway, token_principal)
    app = server.streamable_http_app(
        host=host,
        token_verifier=token_verifier,
        auth=AuthSettings(issuer_url=issuer_url, resource_server_url=public_url),
        custom_starlette_routes=routes,
    )
    inner = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(a):
        async with upstream, inner(a):
            yield

    app.router.lifespan_context = lifespan
    return app
