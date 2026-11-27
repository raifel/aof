"""`GET /results/{handle}`: the user's UI reads a vaulted result (docs/data-safety.md).

The agent holds the user's token too, so a token alone is not enough: the calling OAuth
client (`client_id` / `azp`) must be listed in `data_safety.vault.reader_clients`, which
should name the app's UI and never the agent's client. The result must belong to the
token's user and tenant. Reads and refusals are audited; values never are.
"""

from __future__ import annotations

from .core import Gateway
from .identity import principal_from_access_token
from .vault import VaultError


def results_routes(gateway: Gateway, token_verifier) -> list:
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    readers = set(((gateway.policy.data_safety or {}).get("vault") or {}).get("reader_clients") or [])

    def fail(status: int, code: str, reason: str) -> JSONResponse:
        return JSONResponse({"error": code, "reason": reason}, status)

    async def read(request: Request) -> JSONResponse:
        handle = request.path_params["handle"]
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else None
        access = await token_verifier.verify_token(token) if token else None
        if access is None:
            return fail(401, "UNAUTHENTICATED", "a valid bearer token is required")
        who = principal_from_access_token(access)
        base = {"agent": gateway.agent_id, "user": who.user_id, "client": who.client_id,
                "result_handle": handle, "verified": True}
        if who.client_id not in readers:
            gateway.audit.append("result_read_refused", **base, code="RESULT_READER_NOT_ALLOWED")
            return fail(403, "RESULT_READER_NOT_ALLOWED",
                        "this client may not read results; only the app's UI clients may")
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

    return [Route("/results/{handle}", read, methods=["GET"])]
