"""A2A path: agent-to-agent traffic passes the gateway in both directions.

Outbound (this app's agent delegates to a peer):
    POST /a2a/peers/<peer>      A2A JSON-RPC, forwarded to the peer's endpoint
Inbound (another agent calls this app's agent):
    GET  /.well-known/agent-card.json   the app's card, endpoints rewritten to the gateway
    POST /a2a                           A2A JSON-RPC, forwarded to the app's A2A server

Both directions speak A2A 1.0 JSON-RPC (SendMessage, GetTask, ...) and accept the 0.3
method names (message/send, tasks/get, ...). The gateway passes payloads through
unchanged; it reads only the method, task ids and the agent card.

Checks, in order (first failure wins):
  kill switch . A2A enabled at the current autonomy level (L4) . method allowed (no
  push-notification webhooks) . peer or caller allow-listed . delegation depth .
  per-run delegation and cost budgets (new work only) . task ownership (a caller sees
  only tasks it started) . peer card still advertises the contracted skills

Hop count: the gateway adds one to x-aof-delegation-depth on every outbound
delegation and refuses a request whose depth exceeds the policy's maximum.

Not built: mTLS between gateways (terminate it in front of the gateway), agent card
signature verification (a2a-sdk has a verifier; wire it to your trust roots), the
HTTP+JSON and gRPC bindings, and shared task-ownership state for several replicas.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Protocol

from ..enums import AutonomyLevel
from ..models.external import AgentCard
from .compiled import A2aPeerRule
from .core import Gateway
from .engine import effective_level
from .identity import Principal

DEPTH_HEADER = "x-aof-delegation-depth"
RUN_HEADER = "x-aof-run-id"
USER_HEADER = "x-aof-on-behalf-of"
VERSION_HEADER = "A2A-Version"

# A2A 1.0 names, with the 0.3 names mapped onto them.
_V03 = {
    "message/send": "SendMessage",
    "message/stream": "SendStreamingMessage",
    "tasks/get": "GetTask",
    "tasks/list": "ListTasks",
    "tasks/cancel": "CancelTask",
    "tasks/resubscribe": "SubscribeToTask",
    "agent/getAuthenticatedExtendedCard": "GetExtendedAgentCard",
}
NEW_WORK = {"SendMessage", "SendStreamingMessage"}
TASK_SCOPED = {"GetTask", "CancelTask", "SubscribeToTask"}
STREAMING = {"SendStreamingMessage", "SubscribeToTask"}
ALLOWED = NEW_WORK | TASK_SCOPED | {"ListTasks", "GetExtendedAgentCard"}

# JSON-RPC error codes. A2A reserves -32001..-32099 for its own errors, so AOF
# denials use one server-defined code and carry the stable AOF code in data.error.
RPC_DENIED = -32050
RPC_INVALID = -32600
RPC_METHOD = -32601
RPC_UPSTREAM = -32603


def canonical_method(method: str) -> str:
    return _V03.get(method, method)


def rpc_error(rpc_id: Any, code: str, message: str, rpc_code: int = RPC_DENIED) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id,
            "error": {"code": rpc_code, "message": f"[AOF:{code}] {message}", "data": {"error": code}}}


class A2aDenied(Exception):
    def __init__(self, code: str, message: str, *, violation: bool = False, rpc_code: int = RPC_DENIED):
        super().__init__(message)
        self.code, self.violation, self.rpc_code = code, violation, rpc_code


# --------------------------------------------------------------------------- transport


@dataclass
class A2aReply:
    status: int
    body: dict[str, Any] | None = None
    events: AsyncIterator[dict[str, Any]] | None = None  # parsed SSE `data` payloads


class A2aTransport(Protocol):
    async def get_json(self, url: str) -> dict[str, Any]: ...

    async def post(self, url: str, body: dict[str, Any], headers: dict[str, str], stream: bool) -> A2aReply: ...


class HttpTransport:
    """JSON-RPC over HTTP with httpx2. Pass `client` to add mTLS or test transports."""

    def __init__(self, client: Any = None, timeout: float = 60.0):
        import httpx2

        self.client = client or httpx2.AsyncClient(timeout=timeout)

    async def get_json(self, url: str) -> dict[str, Any]:
        res = await self.client.get(url, headers={"accept": "application/json"})
        res.raise_for_status()
        return res.json()

    async def post(self, url: str, body: dict[str, Any], headers: dict[str, str], stream: bool) -> A2aReply:
        hdrs = {"content-type": "application/json", **headers}
        if not stream:
            res = await self.client.post(url, json=body, headers=hdrs)
            try:
                return A2aReply(res.status_code, res.json())
            except ValueError:
                return A2aReply(res.status_code, None)
        hdrs["accept"] = "text/event-stream"
        req = self.client.build_request("POST", url, json=body, headers=hdrs)
        res = await self.client.send(req, stream=True)
        if res.status_code != 200 or "text/event-stream" not in res.headers.get("content-type", ""):
            raw = await res.aread()
            await res.aclose()
            try:
                return A2aReply(res.status_code, json.loads(raw))
            except ValueError:
                return A2aReply(res.status_code, None)
        return A2aReply(200, events=_sse_events(res))


async def _sse_events(res) -> AsyncIterator[dict[str, Any]]:
    try:
        data: list[str] = []
        async for line in res.aiter_lines():
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif not line.strip() and data:
                yield json.loads("\n".join(data))
                data = []
        if data:
            yield json.loads("\n".join(data))
    finally:
        await res.aclose()


# --------------------------------------------------------------------------- helpers


def _task_ids(result: Any) -> set[str]:
    """Task ids in a JSON-RPC result or stream event (A2A 1.0 and 0.3 shapes)."""
    if not isinstance(result, dict):
        return set()
    ids: set[str] = set()
    task = result.get("task")
    if isinstance(task, dict) and task.get("id"):
        ids.add(task["id"])
    for key in ("statusUpdate", "artifactUpdate", "message"):
        part = result.get(key)
        if isinstance(part, dict) and part.get("taskId"):
            ids.add(part["taskId"])
    if result.get("kind") == "task" and result.get("id"):  # 0.3
        ids.add(result["id"])
    if result.get("taskId"):  # 0.3 events and messages
        ids.add(result["taskId"])
    return ids


def _requested_task(method: str, params: dict[str, Any]) -> str | None:
    if method in TASK_SCOPED:
        return params.get("id")
    if method in NEW_WORK:
        message = params.get("message") or {}
        return message.get("taskId")
    return None


@dataclass
class _CardEntry:
    card: AgentCard
    fetched_at: float


@dataclass
class Call:
    """One JSON-RPC request through the gateway, after authentication."""

    principal: Principal
    body: dict[str, Any]
    run_id: str
    depth: int = 0
    caller: str | None = None  # inbound: the calling agent's id
    a2a_version: str | None = None
    rpc_id: Any = field(init=False, default=None)
    method: str = field(init=False, default="")
    params: dict[str, Any] = field(init=False, default_factory=dict)


# --------------------------------------------------------------------------- proxy


class A2aProxy:
    def __init__(self, gateway: Gateway, transport: A2aTransport | None = None, *,
                 upstream_url: str | None = None, public_url: str | None = None,
                 card_ttl: float = 300.0, env: dict[str, str] | None = None):
        self.gw = gateway
        self.transport = transport or HttpTransport()
        self.upstream_url = upstream_url  # inbound: the app's own A2A JSON-RPC endpoint
        self.public_url = public_url  # inbound: this gateway's /a2a URL, written into the card
        self.card_ttl = card_ttl
        self.env = os.environ if env is None else env
        self._cards: dict[str, _CardEntry] = {}
        self._owners: dict[tuple[str, str], str] = {}  # (scope, task id) -> owner key

    @property
    def rule(self):
        return self.gw.policy.a2a

    # ------------------------------------------------------------------ common checks

    def _parse(self, call: Call) -> None:
        body = call.body
        if body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
            raise A2aDenied("INVALID_REQUEST", "expected a JSON-RPC 2.0 request", rpc_code=RPC_INVALID)
        call.rpc_id = body.get("id")
        call.method = canonical_method(body["method"])
        params = body.get("params") or {}
        if not isinstance(params, dict):
            raise A2aDenied("INVALID_REQUEST", "params must be an object", rpc_code=RPC_INVALID)
        call.params = params

    def _check_common(self, call: Call, *, inbound: bool) -> None:
        gw = self.gw
        killed = gw.state.killed(gw.agent_id)
        if killed:
            raise A2aDenied("KILL_SWITCH", f"agent disabled by {killed['by']}: {killed['reason']}")
        level = effective_level(gw.policy, gw.state)
        if not self.rule.enabled or level < AutonomyLevel.L4:
            raise A2aDenied("A2A_NOT_ENABLED", f"agent-to-agent traffic needs autonomy L4; agent is at {level.value}")
        if inbound and not self.rule.inbound:
            raise A2aDenied("A2A_NOT_ENABLED", "this app does not host an agent (hosts_agent is false)")
        self._parse(call)
        if call.method not in ALLOWED:
            if "PushNotification" in call.method or "pushNotification" in call.body["method"]:
                raise A2aDenied("PUSH_NOT_ALLOWED",
                                "push-notification webhooks are not allowed through the gateway; poll or stream")
            raise A2aDenied("METHOD_NOT_ALLOWED", f"method {call.body['method']} is not allowed",
                            rpc_code=RPC_METHOD)

    def _check_budgets(self, call: Call, run, depth: int) -> None:
        b, rule = self.gw.policy.budgets, self.rule
        max_depth = min(b.max_delegation_depth, rule.max_delegation_depth)
        if depth > max_depth:
            raise A2aDenied("DELEGATION_DEPTH", f"delegation depth {depth} exceeds {max_depth}")
        if call.method in NEW_WORK and _requested_task(call.method, call.params) is None:
            if run.delegations >= rule.max_delegations_per_run:
                raise A2aDenied("DELEGATION_BUDGET",
                                f"run used {run.delegations}/{rule.max_delegations_per_run} delegations")
            if run.cost_usd >= b.max_cost_usd_per_run:
                raise A2aDenied("COST_BUDGET",
                                f"run cost ${run.cost_usd:.4f} reached the ${b.max_cost_usd_per_run:.2f} cap")

    def _check_owner(self, scope: str, owner: str, call: Call) -> None:
        task_id = _requested_task(call.method, call.params)
        if task_id is None:
            return
        if self._owners.get((scope, task_id)) != owner:
            raise A2aDenied("TASK_NOT_OWNED", f"task {task_id} was not started by this caller", violation=True)

    def _claim(self, scope: str, owner: str, ids: set[str]) -> list[str]:
        for t in ids:
            self._owners.setdefault((scope, t), owner)
        return sorted(ids)

    def _filter_list(self, scope: str, owner: str, body: dict[str, Any]) -> dict[str, Any]:
        result = body.get("result")
        if isinstance(result, dict) and isinstance(result.get("tasks"), list):
            kept = [t for t in result["tasks"] if self._owners.get((scope, t.get("id"))) == owner]
            body = {**body, "result": {**result, "tasks": kept, "totalSize": len(kept)}}
        return body

    # ------------------------------------------------------------------ peer cards

    async def peer_card(self, peer: A2aPeerRule) -> AgentCard:
        now = self.gw.clock()
        entry = self._cards.get(peer.name)
        if entry and now - entry.fetched_at < self.card_ttl:
            return entry.card
        try:
            card = AgentCard.model_validate(await self.transport.get_json(peer.card_url))
        except Exception as exc:  # noqa: BLE001 - any fetch or schema failure means no verified card
            raise A2aDenied("PEER_CARD_INVALID", f"could not load {peer.name}'s agent card: {exc}") from exc
        missing = sorted(set(peer.skills) - card.skill_ids())
        if missing:
            raise A2aDenied("PEER_SKILL_MISSING",
                            f"{peer.name}'s card no longer advertises contracted skills: {', '.join(missing)}")
        endpoint = card.endpoint()
        if not endpoint or not endpoint.startswith("https://"):
            raise A2aDenied("PEER_CARD_INVALID", f"{peer.name}'s card has no https JSONRPC endpoint")
        self._cards[peer.name] = _CardEntry(card, now)
        return card

    # ------------------------------------------------------------------ outbound

    async def delegate(self, peer_name: str, call: Call) -> A2aReply:
        """This app's agent calls a peer agent."""
        gw = self.gw
        now = gw.clock()
        run = gw.state.run(call.run_id, now)
        base = {"agent": gw.agent_id, "user": call.principal.user_id, "run_id": call.run_id,
                "direction": "outbound", "peer": peer_name}
        scope, owner = f"peer:{peer_name}", f"user:{call.principal.user_id}"
        try:
            self._check_common(call, inbound=False)
            peer = self.rule.peer(peer_name)
            if peer is None:
                raise A2aDenied("PEER_NOT_ALLOWED", f"{peer_name} is not an allowed peer", violation=True)
            depth = call.depth + 1
            self._check_budgets(call, run, depth)
            self._check_owner(scope, owner, call)
            card = await self.peer_card(peer)
        except A2aDenied as d:
            return self._deny(call, base, d, now)

        headers = {DEPTH_HEADER: str(depth), RUN_HEADER: f"{gw.agent_id}:{call.run_id}",
                   USER_HEADER: call.principal.user_id}
        if call.a2a_version:
            headers[VERSION_HEADER] = call.a2a_version
        if peer.credential_env:
            token = self.env.get(peer.credential_env)
            if not token:
                return self._deny(call, base, A2aDenied("PEER_CREDENTIAL_MISSING",
                                                        f"{peer.credential_env} is not set on the gateway"), now)
            headers["authorization"] = f"Bearer {token}"
        if call.method in NEW_WORK and _requested_task(call.method, call.params) is None:
            run.delegations += 1
        return await self._forward(card.endpoint(), call, headers, base, scope, owner)

    # ------------------------------------------------------------------ inbound

    async def receive(self, call: Call) -> A2aReply:
        """Another agent calls this app's agent."""
        gw = self.gw
        now = gw.clock()
        caller = call.caller or "unknown"
        run_id = f"{caller}:{call.run_id}"
        run = gw.state.run(run_id, now)
        base = {"agent": gw.agent_id, "user": call.principal.user_id, "run_id": run_id,
                "direction": "inbound", "caller": caller}
        scope, owner = "inbound", f"{caller}|{call.principal.user_id}"
        try:
            self._check_common(call, inbound=True)
            if caller not in self.rule.allowed_callers:
                raise A2aDenied("CALLER_NOT_ALLOWED", f"{caller} may not call {gw.agent_id}")
            if self.upstream_url is None:
                raise A2aDenied("A2A_NOT_ENABLED", "the gateway has no upstream A2A endpoint for this app")
            self._check_budgets(call, run, call.depth)
            self._check_owner(scope, owner, call)
        except A2aDenied as d:
            return self._deny(call, base, d, now)
        headers = {DEPTH_HEADER: str(call.depth), RUN_HEADER: run_id, USER_HEADER: call.principal.user_id,
                   "x-aof-caller": caller}
        if call.a2a_version:
            headers[VERSION_HEADER] = call.a2a_version
        if call.method in NEW_WORK and _requested_task(call.method, call.params) is None:
            run.delegations += 1
        return await self._forward(self.upstream_url, call, headers, base, scope, owner)

    async def own_card(self) -> dict[str, Any]:
        """The app's agent card as served by the gateway: endpoints point at the gateway."""
        if self.upstream_url is None:
            raise A2aDenied("A2A_NOT_ENABLED", "no upstream A2A endpoint")
        from urllib.parse import urljoin

        card = await self.transport.get_json(urljoin(self.upstream_url, "/.well-known/agent-card.json"))
        if self.public_url:
            if card.get("url"):
                card["url"] = self.public_url
            for iface in card.get("supportedInterfaces") or []:
                iface["url"] = self.public_url
        return card

    # ------------------------------------------------------------------ shared

    def _deny(self, call: Call, base: dict[str, Any], d: A2aDenied, now: float) -> A2aReply:
        self.gw.audit.append("a2a_denied", **base, method=call.method or call.body.get("method"),
                             code=d.code, reason=str(d))
        if d.violation:
            self.gw.record_violation(now)
        return A2aReply(200, rpc_error(call.rpc_id, d.code, str(d), d.rpc_code))

    async def _forward(self, url: str, call: Call, headers: dict[str, str], base: dict[str, Any],
                       scope: str, owner: str) -> A2aReply:
        stream = call.method in STREAMING
        started = time.monotonic()
        try:
            reply = await self.transport.post(url, call.body, headers, stream)
        except Exception as exc:  # noqa: BLE001 - network failure towards the other agent
            self.gw.audit.append("a2a_failed", **base, method=call.method, reason=type(exc).__name__)
            return A2aReply(200, rpc_error(call.rpc_id, "A2A_UNREACHABLE", "could not reach the other agent",
                                           RPC_UPSTREAM))
        if reply.events is not None:
            return A2aReply(200, events=self._relay(reply.events, call, base, scope, owner, started))
        body = reply.body if isinstance(reply.body, dict) else rpc_error(
            call.rpc_id, "A2A_BAD_RESPONSE", f"the other agent answered HTTP {reply.status}", RPC_UPSTREAM)
        tasks = self._claim(scope, owner, _task_ids(body.get("result")))
        if call.method == "ListTasks":
            body = self._filter_list(scope, owner, body)
        err = body.get("error")
        self.gw.audit.append("a2a_call", **base, method=call.method, task_ids=tasks,
                             rpc_error=(err or {}).get("code") if isinstance(err, dict) else None,
                             duration_ms=round((time.monotonic() - started) * 1000))
        return A2aReply(200, body)

    async def _relay(self, events, call, base, scope, owner, started) -> AsyncIterator[dict[str, Any]]:
        tasks: set[str] = set()
        count = 0
        try:
            async for event in events:
                count += 1
                tasks |= _task_ids(event.get("result") if isinstance(event, dict) else None)
                self._claim(scope, owner, tasks)
                yield event
        finally:
            self.gw.audit.append("a2a_call", **base, method=call.method, task_ids=sorted(tasks), events=count,
                                 duration_ms=round((time.monotonic() - started) * 1000))


# --------------------------------------------------------------------------- HTTP routes


def a2a_routes(proxy: A2aProxy, token_verifier) -> list:
    """Starlette routes. Callers authenticate with a gateway bearer token. Inbound, the
    token's client_id is the calling agent's id and its subject is the user it acts for."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    from .identity import principal_from_access_token

    async def _auth(request: Request):
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else None
        return await token_verifier.verify_token(token) if token else None

    async def _call(request: Request, access) -> Call | JSONResponse:
        try:
            body = await request.json()
            assert isinstance(body, dict)
        except Exception:  # noqa: BLE001
            return JSONResponse(rpc_error(None, "INVALID_JSON", "body must be a JSON-RPC object", -32700))
        principal = principal_from_access_token(access)
        try:
            depth = int(request.headers.get(DEPTH_HEADER, "0"))
        except ValueError:
            depth = 0
        return Call(principal, body, run_id=request.headers.get(RUN_HEADER) or f"user-{principal.user_id}",
                    depth=depth, caller=access.client_id, a2a_version=request.headers.get(VERSION_HEADER))

    def _respond(reply: A2aReply):
        if reply.events is None:
            return JSONResponse(reply.body, status_code=reply.status)

        async def sse():
            async for event in reply.events:
                yield f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode()

        return StreamingResponse(sse(), media_type="text/event-stream", headers={"cache-control": "no-cache"})

    def _unauthenticated():
        return JSONResponse(rpc_error(None, "UNAUTHENTICATED", "a valid gateway token is required"), 401,
                            headers={"www-authenticate": "Bearer"})

    async def outbound(request: Request):
        access = await _auth(request)
        if access is None:
            return _unauthenticated()
        call = await _call(request, access)
        if isinstance(call, JSONResponse):
            return call
        return _respond(await proxy.delegate(request.path_params["peer"], call))

    async def inbound(request: Request):
        access = await _auth(request)
        if access is None:
            return _unauthenticated()
        call = await _call(request, access)
        if isinstance(call, JSONResponse):
            return call
        return _respond(await proxy.receive(call))

    async def card(request: Request):
        try:
            return JSONResponse(await proxy.own_card())
        except A2aDenied as d:
            return JSONResponse({"error": d.code, "reason": str(d)}, 404)
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "A2A_UNREACHABLE", "reason": "could not load the agent card"}, 502)

    return [
        Route("/a2a/peers/{peer}", outbound, methods=["POST"]),
        Route("/a2a", inbound, methods=["POST"]),
        Route("/.well-known/agent-card.json", card, methods=["GET"]),
    ]
