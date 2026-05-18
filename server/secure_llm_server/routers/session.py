"""POST /v1/session (plaintext) and DELETE /v1/session/{id} (encrypted)."""

from __future__ import annotations

import base64

import structlog
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from secure_llm_protocol.schemas import ErrorEnvelope, HandshakeRequest
from secure_llm_server.crypto.handshake import HandshakeError, perform_handshake
from secure_llm_server.metrics import handshake_total
from secure_llm_server.middleware.audit import audit_event

router = APIRouter(prefix="/v1")
_log = structlog.get_logger("secure_llm_server.routers.session")


class _Empty(BaseModel):
    pass


@router.post("/session")
async def create_session(req: HandshakeRequest, request: Request) -> Response:
    state = request.app.state
    try:
        response, material = perform_handshake(
            req=req,
            server_identity=state.keystore.server,
            allowlist=state.keystore.allowlist,
            skew_seconds=state.settings.crypto.handshake_skew_seconds,
            ttl_seconds=state.settings.crypto.session_ttl_seconds,
            expected_host=req.server_host,
        )
    except HandshakeError as e:
        handshake_total.labels(e.code.value).inc()
        audit_event("handshake.reject", code=e.code.value)
        err = ErrorEnvelope(code=e.code, message=str(e))
        raise HTTPException(status_code=401, detail=err.model_dump()) from None
    sess = await state.session_manager.create(material)
    handshake_total.labels("ok").inc()
    audit_event("handshake.ok", client_fp=sess.client_fingerprint, tenant=sess.tenant)
    return Response(content=response.model_dump_json(), media_type="application/json")


@router.delete("/session/{session_id_b64:path}")
async def terminate_session(session_id_b64: str, request: Request) -> Response:
    # Accept either standard or URL-safe base64. The SDK sends URL-safe; we
    # accept both so curl users can paste whatever their tool produces.
    try:
        try:
            sid = base64.urlsafe_b64decode(session_id_b64)
        except Exception:
            sid = base64.b64decode(session_id_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400) from None
    removed = await request.app.state.session_manager.terminate(sid)
    audit_event("session.terminate", session_id=session_id_b64, removed=removed)
    return Response(status_code=204)
