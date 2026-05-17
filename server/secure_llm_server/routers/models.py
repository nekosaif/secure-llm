"""Model list/download/remove, all encrypted-envelope."""

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import (
    ErrorEnvelope,
    ModelDownloadRequest,
    ModelList,
)
from secure_llm_server.middleware.audit import audit_event
from secure_llm_server.models.downloader import DownloadError, download_and_seal
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)

router = APIRouter(prefix="/v1")
_log = structlog.get_logger("secure_llm_server.routers.models")


class _Empty(BaseModel):
    pass


@router.post("/models/list")
async def list_models(request: Request) -> Response:
    state = request.app.state
    session, _ = await decrypt_request(request, state.session_manager, _Empty)
    payload = ModelList(models=state.models.snapshot())
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


@router.post("/models/download")
async def download_model(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, ModelDownloadRequest)
    if not state.settings.models.allow_download:
        err = ErrorEnvelope(code=ErrorCode.BAD_REQUEST, message="downloads disabled")
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=403, content=body, media_type="application/octet-stream")
    try:
        entry = await asyncio.to_thread(
            download_and_seal,
            repo_id=req.repo_id,
            filename=req.filename,
            expected_sha256=req.sha256,
            registry=state.registry,
            at_rest=state.at_rest_key,
            allowed_repo_prefixes=state.settings.models.allowed_repo_prefixes,
            disk_quota_gb=state.settings.models.disk_quota_gb,
        )
    except DownloadError as e:
        audit_event("model.download.fail", code=e.code.value, repo=req.repo_id)
        err = ErrorEnvelope(code=e.code, message=str(e))
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=400, content=body, media_type="application/octet-stream")
    audit_event("model.download.ok", id=entry.id, sha=entry.sha256_plaintext)
    payload = ModelList(models=state.models.snapshot())
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")


class _RemoveReq(BaseModel):
    id: str


@router.post("/models/remove")
async def remove_model(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, _RemoveReq)
    await state.models.force_unload(req.id)
    state.registry.remove(req.id)
    audit_event("model.remove", id=req.id)
    payload = ModelList(models=state.models.snapshot())
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
