"""GET /v1/system, /healthz, /readyz."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)

router = APIRouter()


class _Empty(BaseModel):
    pass


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> Response:
    r = request.app.state.readiness
    if r.ok:
        return Response(content='{"status":"ready"}', media_type="application/json")
    return Response(
        status_code=503,
        content='{"status":"not_ready"}',
        media_type="application/json",
    )


@router.post("/v1/system")
async def system_status(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    payload = state.status.system()
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
