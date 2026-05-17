"""/v1/debug/* — read-only introspection for any authenticated client."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from secure_llm_protocol.schemas import DebugStatus, DoctorReport
from secure_llm_server import __version__
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)
from secure_llm_server.scripts_doctor import run_checks

router = APIRouter(prefix="/v1/debug")


class _Empty(BaseModel):
    pass


class _LogQuery(BaseModel):
    limit: int = Field(default=200, ge=1, le=2000)
    level: str | None = None
    component: str | None = None
    since: float | None = None


class _ErrorQuery(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)


@router.post("/status")
async def status(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    payload: DebugStatus = state.status.debug_status()
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/doctor")
async def doctor(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    steps = run_checks(state.settings)
    overall: Literal["ok", "warn", "fail"]
    if any(s.status == "fail" for s in steps):
        overall = "fail"
    elif any(s.status == "warn" for s in steps):
        overall = "warn"
    else:
        overall = "ok"
    payload = DoctorReport(overall=overall, steps=steps)
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/version")
async def version(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    payload: dict[str, Any] = {
        "server_version": __version__,
        "protocol_version": "1.0",
    }
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/logs")
async def logs(request: Request) -> Response:
    state = request.app.state
    session, q = await decrypt_request(request, state.session_manager, _LogQuery)
    fp = None if "admin" in session.scopes else session.client_fingerprint
    entries = state.ring.tail(
        limit=q.limit,
        level=q.level,
        component=q.component,
        since=q.since,
        client_fingerprint=fp,
    )
    payload = {"entries": [e.model_dump() for e in entries]}
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/errors")
async def errors(request: Request) -> Response:
    state = request.app.state
    session, q = await decrypt_request(request, state.session_manager, _ErrorQuery)
    payload = {"errors": [e.summary() for e in state.errors.recent(q.limit)]}
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
