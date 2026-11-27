"""`GET /results/{handle}` and `POST /render`: the user's UI reads vaulted results and
fills the agent's answer templates (docs/data-safety.md).

The agent holds the user's token too, so a token alone is not enough: the calling OAuth
client (`client_id` / `azp`) must be listed in `data_safety.vault.reader_clients`, which
should name the app's UI and never the agent's client. The result must belong to the
token's user and tenant. Reads and refusals are audited; values never are.

`POST /render` takes `{"template": "..."}` and returns `{"text", "references", "missing"}`:
every `{{res_<id>.<path> | filter}}` filled from results of the token's user (see
`render.py`). A placeholder for another user's result, or one that names nothing,
renders as `[unavailable]`.
"""

from __future__ import annotations

from .core import Gateway
from .identity import principal_from_access_token
from .render import render
from .shield import _follow
from .vault import VaultError


def results_routes(gateway: Gateway, token_verifier) -> list:
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    readers = set(((gateway.policy.data_safety or {}).get("vault") or {}).get("reader_clients") or [])

    def fail(status: int, code: str, reason: str) -> JSONResponse:
        return JSONResponse({"error": code, "reason": reason}, status)

    async def caller(request: Request, event: str, **fields):
        """(principal, audit base) or a refusal response."""
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else None
        access = await token_verifier.verify_token(token) if token else None
        if access is None:
            return None, None, fail(401, "UNAUTHENTICATED", "a valid bearer token is required")
        who = principal_from_access_token(access)
        base = {"agent": gateway.agent_id, "user": who.user_id, "client": who.client_id, **fields, "verified": True}
        if who.client_id not in readers:
            gateway.audit.append(event, **base, code="RESULT_READER_NOT_ALLOWED")
            return None, None, fail(403, "RESULT_READER_NOT_ALLOWED",
                                    "this client may not read results; only the app's UI clients may")
        return who, base, None

    async def read(request: Request) -> JSONResponse:
        handle = request.path_params["handle"]
        who, base, refused = await caller(request, "result_read_refused", result_handle=handle)
        if refused is not None:
            return refused
        if gateway.vault is None:
            return fail(404, "RESULT_NOT_FOUND", "this gateway keeps no results")
        try:
            stored = gateway.vault.get(handle, who)
        except VaultError as exc:
            gateway.audit.append("result_read_refused", **base, code=exc.code)
            return fail(404, exc.code, str(exc))
        gateway.audit.append("result_read", **base, tool=stored.tool, run_id=stored.run_id)
        return JSONResponse({"result_handle": handle, "tool": stored.tool, "run_id": stored.run_id,
                             "expires_at": stored.expires_at, **stored.meta, "content": stored.content},
                            headers={"cache-control": "no-store"})

    async def render_answer(request: Request) -> JSONResponse:
        who, base, refused = await caller(request, "render_refused")
        if refused is not None:
            return refused
        try:
            body = await request.json()
        except ValueError:
            body = None
        template = body.get("template") if isinstance(body, dict) else None
        if not isinstance(template, str) or len(template) > 20_000:
            return fail(400, "TEMPLATE_INVALID", "send {\"template\": \"...\"} (at most 20000 characters)")
        cache: dict[str, object] = {}

        def lookup(handle: str, path: str):
            if gateway.vault is None:
                raise VaultError("RESULT_NOT_FOUND", "this gateway keeps no results")
            if handle not in cache:
                cache[handle] = gateway.vault.get(handle, who).content
            return _follow(cache[handle], path, handle)

        out = render(template, lookup)
        gateway.audit.append("answer_rendered", **base, result_handles=out.handles, references=out.references,
                             missing=len(out.missing))
        return JSONResponse({"text": out.text, "references": out.references, "missing": out.missing},
                            headers={"cache-control": "no-store"})

    return [Route("/results/{handle}", read, methods=["GET"]),
            Route("/render", render_answer, methods=["POST"])]
