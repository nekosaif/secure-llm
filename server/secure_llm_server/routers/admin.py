"""/v1/admin/* — control-plane. Requires the 'admin' scope on the session.

Operations here mutate live server state: terminate sessions, preload/unload
models, change log levels, etc. Every successful call is recorded in the audit
log.
"""

from __future__ import annotations

import base64
import gc

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import (
    AdminClientInfo,
    AdminSessionInfo,
    ErrorEnvelope,
    ModelList,
)
from secure_llm_server.crypto.kdf import fingerprint
from secure_llm_server.logging import set_component_level
from secure_llm_server.middleware.audit import audit_event
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)

router = APIRouter(prefix="/v1/admin")


class _Empty(BaseModel):
    pass


class _ModelId(BaseModel):
    id: str


class _TerminateReq(BaseModel):
    session_id: str  # base64


class _RevokeReq(BaseModel):
    fingerprint: str


class _LogLevelReq(BaseModel):
    component: str
    level: str
    ttl_seconds: int | None = Field(default=None, ge=1, le=86400)


class _ShutdownReq(BaseModel):
    grace_seconds: int = Field(default=30, ge=0, le=600)


def _require_admin(session, request, method, path) -> Response | None:  # type: ignore[no-untyped-def]
    if "admin" in session.scopes:
        return None
    err = ErrorEnvelope(code=ErrorCode.ADMIN_REQUIRED, message="admin scope required")
    body = encrypt_response(session, err, method=method, path=path)
    audit_event("admin.denied", path=path, client_fp=session.client_fingerprint)
    return Response(status_code=403, content=body, media_type="application/octet-stream")


@router.post("/sessions/list")
async def list_sessions(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    sessions = [
        AdminSessionInfo(
            session_id=s.session_id_b64,
            client_fingerprint=s.client_fingerprint,
            scopes=sorted(s.scopes),
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            ttl_seconds=s.ttl_seconds,
        ).model_dump()
        for s in state.session_manager.all()
    ]
    body = encrypt_response(
        session, {"sessions": sessions}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/sessions/terminate")
async def terminate_session(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _TerminateReq)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    sid = base64.b64decode(req.session_id)
    removed = await state.session_manager.terminate(sid)
    audit_event("admin.session.terminate", session_id=req.session_id, removed=removed)
    body = encrypt_response(
        session, {"terminated": removed}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/clients/list")
async def list_clients(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    clients = [
        AdminClientInfo(
            name=c.name,
            fingerprint=fingerprint(c.x25519_pk),
            scopes=sorted(c.scopes),
            revoked=c.revoked,
            not_before=c.not_before,
            not_after=c.not_after,
        ).model_dump()
        for c in state.keystore.allowlist.values()
    ]
    body = encrypt_response(
        session, {"clients": clients}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/clients/reload")
async def reload_clients(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    n = state.keystore.reload_allowlist()
    audit_event("admin.clients.reload", count=n)
    body = encrypt_response(session, {"clients": n}, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/models/list")
async def admin_models_list(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    payload = ModelList(models=state.models.snapshot())
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/models/preload")
async def preload_model(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _ModelId)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    await state.models.preload(req.id)
    audit_event("admin.model.preload", id=req.id)
    body = encrypt_response(
        session, {"id": req.id, "state": "loaded"}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/models/unload")
async def unload_model(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _ModelId)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    removed = await state.models.force_unload(req.id)
    audit_event("admin.model.unload", id=req.id, was_loaded=removed)
    body = encrypt_response(
        session, {"id": req.id, "unloaded": removed}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/log-level")
async def set_log_level(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _LogLevelReq)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    set_component_level(req.component, req.level)
    audit_event("admin.log_level", component=req.component, level=req.level, ttl=req.ttl_seconds)
    if req.ttl_seconds is not None:
        import asyncio

        ttl: int = req.ttl_seconds

        async def _revert() -> None:
            await asyncio.sleep(ttl)
            set_component_level(req.component, state.settings.observability.log_level)
            audit_event("admin.log_level.revert", component=req.component)

        # Keep a strong reference so the task isn't GC'd mid-sleep.
        task = asyncio.create_task(_revert(), name=f"log-revert:{req.component}")
        request.app.state.setdefault("_log_revert_tasks", set()) if isinstance(
            getattr(request.app.state, "_log_revert_tasks", None), dict
        ) else None
        bag = getattr(request.app.state, "_log_revert_tasks", None)
        if bag is None:
            bag = set()
            request.app.state._log_revert_tasks = bag
        bag.add(task)
        task.add_done_callback(bag.discard)
    body = encrypt_response(session, {"ok": True}, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/gc")
async def admin_gc(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    collected = gc.collect()
    audit_event("admin.gc", collected=collected)
    body = encrypt_response(
        session, {"collected": collected}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/shutdown")
async def admin_shutdown(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _ShutdownReq)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    audit_event("admin.shutdown", grace=req.grace_seconds)
    # uvicorn handles SIGTERM as graceful shutdown.
    import os
    import signal

    def _send_term() -> None:
        os.kill(os.getpid(), signal.SIGTERM)

    import asyncio

    asyncio.get_event_loop().call_later(0.1, _send_term)
    body = encrypt_response(
        session, {"shutting_down": True}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")
