"""/v1/admin/* — control-plane. Requires the 'admin' scope on the session.

Operations here mutate live server state: terminate sessions, preload/unload
models, change log levels, etc. Every successful call is recorded in the audit
log.
"""

from __future__ import annotations

import asyncio
import base64
import gc

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import (
    AdminClientInfo,
    AdminSessionInfo,
    ErrorEnvelope,
    LoraApplyRequest,
    LoraDownloadRequest,
    LoraInfo,
    LoraList,
    ModelList,
)
from secure_llm_server.crypto.kdf import fingerprint
from secure_llm_server.logging import set_component_level
from secure_llm_server.middleware.audit import audit_event
from secure_llm_server.models.downloader import (
    DownloadError,
    download_and_seal_lora,
)
from secure_llm_server.models.manager import ManagerError
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
    if "admin" in session.scopes or "super_admin" in session.scopes:
        return None
    err = ErrorEnvelope(code=ErrorCode.ADMIN_REQUIRED, message="admin scope required")
    body = encrypt_response(session, err, method=method, path=path)
    audit_event(
        "admin.denied",
        path=path,
        client_fp=session.client_fingerprint,
        tenant=session.tenant,
    )
    return Response(status_code=403, content=body, media_type="application/octet-stream")


def _is_super(session) -> bool:  # type: ignore[no-untyped-def]
    return "super_admin" in session.scopes


def _require_super_admin(session, method, path) -> Response | None:  # type: ignore[no-untyped-def]
    if _is_super(session):
        return None
    err = ErrorEnvelope(
        code=ErrorCode.ADMIN_REQUIRED,
        message="super_admin scope required for cross-tenant operations",
    )
    body = encrypt_response(session, err, method=method, path=path)
    audit_event(
        "admin.super_required",
        path=path,
        client_fp=session.client_fingerprint,
        tenant=session.tenant,
    )
    return Response(status_code=403, content=body, media_type="application/octet-stream")


@router.post("/sessions/list")
async def list_sessions(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    super_view = _is_super(session)
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
        if super_view or s.tenant == session.tenant
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
    # Tenant-admins can only terminate sessions in their own tenant; super_admin
    # can terminate any.
    # Use lookup_async so cross-instance terminations work in a
    # federated deployment (the target may be pinned to another node).
    target = await state.session_manager.lookup_async(sid)
    if target is not None and not _is_super(session) and target.tenant != session.tenant:
        audit_event(
            "admin.session.terminate.cross_tenant_denied",
            session_id=req.session_id,
            tenant=session.tenant,
        )
        err = ErrorEnvelope(
            code=ErrorCode.ADMIN_REQUIRED,
            message="cross-tenant termination requires super_admin",
        )
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=403, content=body, media_type="application/octet-stream")
    # When terminating *our own* session, save the s2c direction before
    # SessionManager zeroes its keys so the goodbye envelope is still
    # decryptable by the caller.
    saved_direction = session.s2c if sid == session.session_id else None
    removed = await state.session_manager.terminate(sid)
    audit_event(
        "admin.session.terminate",
        session_id=req.session_id,
        removed=removed,
        tenant=session.tenant,
    )
    body = encrypt_response(
        session,
        {"terminated": removed},
        method=request.method,
        path=request.url.path,
        direction=saved_direction,
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/clients/list")
async def list_clients(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    super_view = _is_super(session)
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
        if super_view or c.tenant == session.tenant
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
    payload = ModelList(models=state.models.snapshot(tenant=session.tenant))
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/models/preload")
async def preload_model(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _ModelId)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    await state.models.preload(req.id, tenant=session.tenant)
    audit_event("admin.model.preload", id=req.id, tenant=session.tenant)
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
    removed = await state.models.force_unload(req.id, tenant=session.tenant)
    audit_event("admin.model.unload", id=req.id, was_loaded=removed, tenant=session.tenant)
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

    asyncio.get_event_loop().call_later(0.1, _send_term)
    body = encrypt_response(
        session, {"shutting_down": True}, method=request.method, path=request.url.path
    )
    return Response(content=body, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# LoRA adapters
# ---------------------------------------------------------------------------


class _LoraId(BaseModel):
    id: str


@router.post("/loras/list")
async def admin_loras_list(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    reg = state.lora_registry.for_tenant(session.tenant)
    payload = LoraList(
        loras=[
            LoraInfo(
                id=e.id,
                repo_id=e.repo_id,
                filename=e.filename,
                sha256=e.sha256_plaintext,
                bytes_on_disk=e.bytes_ciphertext,
                base_model_id=e.base_model_id,
            )
            for e in reg.all()
        ]
    )
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/loras/pull")
async def admin_loras_pull(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, LoraDownloadRequest)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    if not state.settings.models.allow_download:
        err = ErrorEnvelope(code=ErrorCode.BAD_REQUEST, message="downloads disabled")
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=403, content=body, media_type="application/octet-stream")
    tenant_lora_reg = state.lora_registry.for_tenant(session.tenant)
    try:
        entry = await asyncio.to_thread(
            download_and_seal_lora,
            repo_id=req.repo_id,
            filename=req.filename,
            expected_sha256=req.sha256,
            registry=tenant_lora_reg,
            at_rest=state.at_rest_key,
            allowed_repo_prefixes=state.settings.models.allowed_repo_prefixes,
            disk_quota_gb=state.settings.models.disk_quota_gb,
            base_model_id=req.base_model_id,
        )
    except DownloadError as e:
        audit_event(
            "admin.lora.pull.fail",
            code=e.code.value,
            repo=req.repo_id,
            tenant=session.tenant,
        )
        err = ErrorEnvelope(code=e.code, message=str(e))
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=400, content=body, media_type="application/octet-stream")
    audit_event(
        "admin.lora.pull.ok",
        id=entry.id,
        sha=entry.sha256_plaintext,
        tenant=session.tenant,
    )
    payload = LoraInfo(
        id=entry.id,
        repo_id=entry.repo_id,
        filename=entry.filename,
        sha256=entry.sha256_plaintext,
        bytes_on_disk=entry.bytes_ciphertext,
        base_model_id=entry.base_model_id,
    )
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/loras/rm")
async def admin_loras_rm(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _LoraId)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    removed = state.lora_registry.for_tenant(session.tenant).remove(req.id)
    audit_event("admin.lora.rm", id=req.id, removed=removed, tenant=session.tenant)
    body = encrypt_response(
        session,
        {"id": req.id, "removed": removed},
        method=request.method,
        path=request.url.path,
    )
    return Response(content=body, media_type="application/octet-stream")


@router.post("/loras/apply")
async def admin_loras_apply(request: Request) -> Response:
    """Eagerly load a base model with this LoRA set stacked, ready for inference."""
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, LoraApplyRequest)
    if deny := _require_admin(session, request, request.method, request.url.path):
        return deny
    spec = tuple((lr.id, lr.scale) for lr in req.loras)
    try:
        await state.models.ensure_loaded(
            req.base_model_id,
            n_ctx=req.n_ctx,
            mode="chat",
            loras=spec,
            tenant=session.tenant,
        )
    except ManagerError as e:
        err = ErrorEnvelope(code=e.code, message=str(e))
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=400, content=body, media_type="application/octet-stream")
    audit_event(
        "admin.lora.apply",
        base_model_id=req.base_model_id,
        loras=[{"id": lid, "scale": s} for lid, s in spec],
        tenant=session.tenant,
    )
    body = encrypt_response(
        session,
        {"base_model_id": req.base_model_id, "loras": [{"id": lid, "scale": s} for lid, s in spec]},
        method=request.method,
        path=request.url.path,
    )
    return Response(content=body, media_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Tenants  (super_admin only)
# ---------------------------------------------------------------------------


@router.post("/tenants/list")
async def admin_tenants_list(request: Request) -> Response:
    """List every tenant the server knows about, with rollup stats.

    Tenants are discovered from three sources, unioned:
      * the allowlist (every authorized client's ``tenant`` field)
      * the model storage tree (subdirs under ``data/models/tenants/``)
      * the live session table (any tenant with at least one open session)
    """
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    if deny := _require_super_admin(session, request.method, request.url.path):
        return deny

    from_allowlist: dict[str, dict[str, int]] = {}
    for c in state.keystore.allowlist.values():
        bucket = from_allowlist.setdefault(c.tenant, {"clients": 0, "revoked": 0})
        bucket["clients"] += 1
        if c.revoked:
            bucket["revoked"] += 1

    from_storage = set(state.registry.known_tenants())

    sessions_by_tenant: dict[str, int] = {}
    for s in state.session_manager.all():
        sessions_by_tenant[s.tenant] = sessions_by_tenant.get(s.tenant, 0) + 1

    tenants = sorted(set(from_allowlist.keys()) | from_storage | set(sessions_by_tenant.keys()))
    payload = {
        "tenants": [
            {
                "name": t,
                "clients": from_allowlist.get(t, {}).get("clients", 0),
                "revoked_clients": from_allowlist.get(t, {}).get("revoked", 0),
                "active_sessions": sessions_by_tenant.get(t, 0),
                "models": len(state.registry.for_tenant(t).all()),
            }
            for t in tenants
        ],
    }
    audit_event("admin.tenants.list", count=len(tenants))
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
