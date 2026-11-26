"""LLM proxy path: model calls pass the gateway like tool calls do.

Agents call the gateway's `POST /v1/messages` (the Anthropic Messages API) with
their gateway token as the API key. The gateway checks the request against the
agent's compiled `llm` policy, forwards it with the gateway's own provider
credential (agents never hold it), charges the run for the tokens used and
writes the call to the audit log (token counts and cost, never content).

Checks, in order (first failure wins):
  kill switch . LLM enabled . model allowlist . max_tokens cap . beta allowlist .
  fallbacks stay inside the allowlist . no MCP connector . declared tools are in
  the policy . server tools allow-listed . model-call / cost / depth budgets .
  per-user rate limit

Budget checks run before the call, so one call can take a run past its cost cap.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Protocol

from .compiled import LlmRule
from .core import Gateway
from .engine import effective_decision, effective_level
from .identity import Principal
from .telemetry import llm_span

DEFAULT_MODEL_ALIAS = "aof:default"
_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    429: "rate_limit_error",
    502: "api_error",
}
_WINDOW_S = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def error_body(status: int, code: str, message: str) -> dict[str, Any]:
    """Anthropic-shaped error, so the agent's SDK raises its usual typed exception."""
    return {"type": "error", "error": {"type": _ERROR_TYPES.get(status, "api_error"),
                                       "message": f"[AOF:{code}] {message}"}}


class LlmDenied(Exception):
    def __init__(self, status: int, code: str, message: str, *, violation: bool = False,
                 headers: dict[str, str] | None = None):
        super().__init__(message)
        self.status, self.code, self.violation = status, code, violation
        self.headers = headers or {}


class ProviderError(Exception):
    def __init__(self, status: int, body: dict[str, Any]):
        super().__init__(f"provider error {status}")
        self.status, self.body = status, body


class LlmProvider(Protocol):
    async def create(self, params: dict[str, Any], betas: list[str]) -> dict[str, Any]: ...

    def stream(self, params: dict[str, Any], betas: list[str]) -> AsyncIterator[dict[str, Any]]: ...


class AnthropicProvider:
    """Calls the Claude API with the gateway's credential (resolved by the SDK from
    ANTHROPIC_API_KEY, an `ant auth login` profile, or workload identity federation)."""

    _CONTROL = {"extra_body", "extra_headers", "extra_query", "timeout", "stream", "betas"}

    def __init__(self, client: Any = None):
        import anthropic

        self._sdk = anthropic
        self.client = client or anthropic.AsyncAnthropic()

    def _call(self, params: dict[str, Any], betas: list[str], stream: bool):
        api = self.client.beta.messages if betas else self.client.messages
        known = set(inspect.signature(api.create).parameters) - self._CONTROL
        kwargs = {k: v for k, v in params.items() if k in known}
        extra = {k: v for k, v in params.items() if k not in known}
        if betas:
            kwargs["betas"] = betas
        if extra:
            kwargs["extra_body"] = extra  # fields newer than the installed SDK
        return api.create(**kwargs, stream=stream)

    def _translate(self, exc: Exception) -> ProviderError:
        sdk = self._sdk
        if isinstance(exc, sdk.APIStatusError):
            body = exc.body if isinstance(exc.body, dict) else error_body(exc.status_code, "PROVIDER_ERROR",
                                                                          exc.message)
            return ProviderError(exc.status_code, body)
        if isinstance(exc, sdk.APIConnectionError):
            return ProviderError(502, error_body(502, "PROVIDER_UNREACHABLE", "could not reach the model provider"))
        if isinstance(exc, ValueError):  # SDK guard: very long non-streaming request
            return ProviderError(400, error_body(400, "USE_STREAMING", str(exc)))
        raise exc

    async def create(self, params: dict[str, Any], betas: list[str]) -> dict[str, Any]:
        try:
            message = await self._call(params, betas, stream=False)
        except (self._sdk.APIStatusError, self._sdk.APIConnectionError, ValueError) as exc:
            raise self._translate(exc) from exc
        return message.to_dict()

    async def stream(self, params: dict[str, Any], betas: list[str]) -> AsyncIterator[dict[str, Any]]:
        try:
            events = await self._call(params, betas, stream=True)
        except (self._sdk.APIStatusError, self._sdk.APIConnectionError, ValueError) as exc:
            raise self._translate(exc) from exc
        try:
            async for event in events:
                yield event.to_dict()
        except (self._sdk.APIStatusError, self._sdk.APIConnectionError) as exc:
            raise self._translate(exc) from exc
        finally:
            await events.close()


@dataclass
class LlmResponse:
    status: int
    body: dict[str, Any] | None = None
    events: AsyncIterator[bytes] | None = None  # SSE bytes when streaming
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class _Usage:
    model: str
    message_id: str | None = None
    stop_reason: str | None = None
    tokens: dict[str, Any] = field(default_factory=dict)

    def merge(self, usage: dict[str, Any] | None) -> None:
        for k, v in (usage or {}).items():
            if v is not None:
                self.tokens[k] = v


class LlmProxy:
    def __init__(self, gateway: Gateway, provider: LlmProvider):
        self.gw = gateway
        self.provider = provider

    @property
    def rule(self) -> LlmRule | None:
        return self.gw.policy.llm

    # ------------------------------------------------------------------ cost

    def cost_usd(self, model: str, usage: dict[str, Any]) -> tuple[float, bool]:
        """(cost, priced). Unknown models are charged at the highest listed price."""
        rule = self.rule
        price = rule.pricing_usd_per_mtok.get(model)
        priced = price is not None
        if price is None:
            prices = list(rule.pricing_usd_per_mtok.values())
            if not prices:
                return 0.0, False
            price = max(prices, key=lambda p: p.output)
        cache_read_price = price.cache_read if price.cache_read is not None else price.input * 0.1
        usd = (
            (usage.get("input_tokens") or 0) * price.input  # excludes cache reads and writes
            + (usage.get("cache_creation_input_tokens") or 0) * price.input * rule.cache_write_multiplier
            + (usage.get("cache_read_input_tokens") or 0) * cache_read_price
            + (usage.get("output_tokens") or 0) * price.output
        ) / 1_000_000
        if usage.get("speed") == "fast":
            usd *= rule.fast_mode_multiplier
        return usd, priced

    # ------------------------------------------------------------------ checks

    def _check(self, principal: Principal, params: dict[str, Any], betas: list[str], run, now: float,
               depth: int) -> str:
        gw, rule = self.gw, self.rule
        killed = gw.state.killed(gw.agent_id)
        if killed:
            raise LlmDenied(403, "KILL_SWITCH", f"agent disabled by {killed['by']}: {killed['reason']}")
        if rule is None:
            raise LlmDenied(403, "LLM_NOT_ENABLED", "this agent's policy has no llm section")

        model = params.get("model") or DEFAULT_MODEL_ALIAS
        if model == DEFAULT_MODEL_ALIAS:
            model = rule.default_model
        if model not in rule.models:
            raise LlmDenied(403, "MODEL_NOT_ALLOWED", f"{model} is not allowed; use one of {', '.join(rule.models)}",
                            violation=True)
        params["model"] = model

        max_tokens = params.get("max_tokens")
        if not isinstance(max_tokens, int) or max_tokens < 1:
            raise LlmDenied(400, "MAX_TOKENS_REQUIRED", "max_tokens must be a positive integer")
        if max_tokens > rule.max_tokens:
            raise LlmDenied(400, "MAX_TOKENS_CAP", f"max_tokens {max_tokens} exceeds this agent's cap {rule.max_tokens}")

        bad_betas = [b for b in betas if b not in rule.allowed_betas]
        if bad_betas:
            raise LlmDenied(403, "BETA_NOT_ALLOWED", f"betas not allowed: {', '.join(bad_betas)}")

        fallbacks = params.get("fallbacks")
        if fallbacks is not None:
            if not isinstance(fallbacks, list):
                raise LlmDenied(403, "FALLBACK_NOT_ALLOWED",
                                "automatic fallbacks can route to models outside the allowlist; name them")
            outside = [f.get("model") for f in fallbacks if f.get("model") not in rule.models]
            if outside:
                raise LlmDenied(403, "FALLBACK_NOT_ALLOWED", f"fallback models not allowed: {outside}")

        if params.get("mcp_servers"):
            raise LlmDenied(403, "MCP_CONNECTOR_NOT_ALLOWED",
                            "connect MCP servers through the gateway's /mcp endpoint, not the API connector",
                            violation=True)

        level = effective_level(gw.policy, gw.state)
        for tool in params.get("tools") or []:
            name = tool.get("name")
            if "input_schema" in tool or "type" not in tool:  # a client tool the agent will run
                tool_rule = gw.policy.rule(name)
                if tool_rule is None or effective_decision(tool_rule, level)[0] == "deny":
                    raise LlmDenied(403, "TOOL_NOT_ALLOWED",
                                    f"tool {name} is not callable by this agent at {level.value}", violation=True)
            elif name not in rule.allowed_server_tools:
                raise LlmDenied(403, "SERVER_TOOL_NOT_ALLOWED", f"server tool {name or tool.get('type')} is not allowed")

        b = gw.policy.budgets
        if run.cost_usd >= b.max_cost_usd_per_run:
            raise LlmDenied(403, "COST_BUDGET",
                            f"run cost ${run.cost_usd:.4f} reached the ${b.max_cost_usd_per_run:.2f} cap")
        if depth > b.max_delegation_depth:
            raise LlmDenied(403, "DELEGATION_DEPTH", f"delegation depth {depth} exceeds {b.max_delegation_depth}")

        # Last: take a model call and a rate-limit slot atomically (shared across replicas).
        if not run.reserve("model_calls", rule.max_model_calls_per_run):
            raise LlmDenied(403, "MODEL_CALL_BUDGET",
                            f"run used {rule.max_model_calls_per_run}/{rule.max_model_calls_per_run} model calls")
        if rule.rate_limit:
            window = _WINDOW_S[rule.rate_limit.per]
            ok, used = gw.state.calls.acquire(self._rate_key(principal), window, rule.rate_limit.calls, now)
            if not ok:
                run.add("model_calls", -1)  # give the reserved call back
                raise LlmDenied(429, "RATE_LIMITED", f"{used} model calls in the last {rule.rate_limit.per}",
                                headers={"retry-after": str(window)})
        return model

    def _rate_key(self, principal: Principal) -> tuple:
        return (self.gw.agent_id, principal.user_id, "__llm__")

    # ------------------------------------------------------------------ handling

    async def handle(self, principal: Principal, body: dict[str, Any], *, betas: list[str] | None = None,
                     run_id: str, delegation_depth: int = 0) -> LlmResponse:
        gw = self.gw
        betas = list(betas or [])
        params = dict(body)
        stream = bool(params.pop("stream", False))
        now = gw.clock()
        run = gw.state.run(run_id, now)
        base = {"agent": gw.agent_id, "user": principal.user_id, "run_id": run_id, "stream": stream}
        try:
            model = self._check(principal, params, betas, run, now, delegation_depth)
        except LlmDenied as d:
            gw.audit.append("llm_denied", **base, model=params.get("model"), code=d.code, reason=str(d))
            if d.violation:
                gw.record_violation(now)
            return LlmResponse(d.status, error_body(d.status, d.code, str(d)), headers=d.headers)

        if stream:
            return LlmResponse(200, events=self._stream(params, betas, model, run, base),
                               headers={"cache-control": "no-cache"})

        with llm_span(model, agent_id=gw.agent_id, run_id=run_id, user_id=principal.user_id, stream=False) as span:
            try:
                message = await self.provider.create(params, betas)
            except ProviderError as exc:
                span.set_error(f"PROVIDER_{exc.status}")
                gw.audit.append("llm_failed", **base, model=model, status=exc.status)
                return LlmResponse(exc.status, exc.body)
            usage = _Usage(message.get("model", model), message.get("id"), message.get("stop_reason"))
            usage.merge(message.get("usage"))
            self._charge(run, usage, base, span)
        return LlmResponse(200, message)

    async def _stream(self, params, betas, model, run, base) -> AsyncIterator[bytes]:
        usage = _Usage(model)
        with llm_span(model, agent_id=self.gw.agent_id, run_id=base["run_id"], user_id=base["user"],
                      stream=True) as span:
            try:
                async for event in self.provider.stream(params, betas):
                    kind = event.get("type")
                    if kind == "message_start":
                        msg = event.get("message") or {}
                        usage.model = msg.get("model", model)
                        usage.message_id = msg.get("id")
                        usage.merge(msg.get("usage"))
                    elif kind == "message_delta":
                        usage.merge(event.get("usage"))
                        usage.stop_reason = (event.get("delta") or {}).get("stop_reason") or usage.stop_reason
                    yield _sse(kind or "message", event)
            except ProviderError as exc:
                span.set_error(f"PROVIDER_{exc.status}")
                self.gw.audit.append("llm_failed", **base, model=model, status=exc.status)
                yield _sse("error", exc.body)
            finally:
                # Charge what was used even when the client disconnects mid-stream.
                if usage.tokens:
                    self._charge(run, usage, base, span)

    def _charge(self, run, usage: _Usage, base: dict[str, Any], span) -> None:
        usd, priced = self.cost_usd(usage.model, usage.tokens)
        run_cost = run.add("cost_usd", usd)
        span.set_attribute("gen_ai.response.model", usage.model)
        span.set_attribute("gen_ai.response.id", usage.message_id)
        span.set_attribute("aof.cost_usd", round(usd, 6))
        t = usage.tokens
        self.gw.audit.append(
            "llm_call", **base, model=usage.model, message_id=usage.message_id, stop_reason=usage.stop_reason,
            input_tokens=t.get("input_tokens"), output_tokens=t.get("output_tokens"),
            cache_read_input_tokens=t.get("cache_read_input_tokens"),
            cache_creation_input_tokens=t.get("cache_creation_input_tokens"),
            cost_usd=round(usd, 6), priced=priced, run_cost_usd=round(run_cost, 6),
        )


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode()


# ---------------------------------------------------------------------- HTTP route


def llm_route(proxy: LlmProxy, token_verifier):
    """Starlette route for POST /v1/messages. Accepts the gateway token as x-api-key
    (what the Anthropic SDK sends) or as an Authorization bearer token."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    from .identity import principal_from_access_token

    async def endpoint(request: Request):
        auth = request.headers.get("authorization", "")
        token = request.headers.get("x-api-key") or (auth[7:] if auth.lower().startswith("bearer ") else None)
        access = await token_verifier.verify_token(token) if token else None
        if access is None:
            return JSONResponse(error_body(401, "UNAUTHENTICATED", "a valid gateway token is required"), 401)
        principal = principal_from_access_token(access)
        try:
            body = await request.json()
            assert isinstance(body, dict)
        except Exception:  # noqa: BLE001 - any unparsable body is the caller's error
            return JSONResponse(error_body(400, "INVALID_JSON", "request body must be a JSON object"), 400)
        betas = [b.strip() for b in request.headers.get("anthropic-beta", "").split(",") if b.strip()]
        run_id = request.headers.get("x-aof-run-id") or f"user-{principal.user_id}"
        try:
            depth = int(request.headers.get("x-aof-delegation-depth", "0"))
        except ValueError:
            depth = 0
        res = await proxy.handle(principal, body, betas=betas, run_id=run_id, delegation_depth=depth)
        if res.events is not None:
            return StreamingResponse(res.events, media_type="text/event-stream", headers=res.headers)
        return JSONResponse(res.body, status_code=res.status, headers=res.headers)

    return Route("/v1/messages", endpoint, methods=["POST"])
