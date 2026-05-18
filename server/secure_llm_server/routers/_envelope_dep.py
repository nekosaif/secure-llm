"""Helpers shared by every encrypted router.

The decryption + replay-check pattern is bulky. Centralizing it here keeps
individual route handlers focused on business logic.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, TypeVar

import structlog
from fastapi import HTTPException, Request
from pydantic import BaseModel, ValidationError

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import ErrorEnvelope
from secure_llm_server.crypto.envelope import (
    DirectionKeys,
    EnvelopeAuthError,
    open_envelope,
    seal,
)
from secure_llm_server.crypto.replay import ReplayDetected
from secure_llm_server.metrics import envelope_failures_total
from secure_llm_server.session.manager import Session, SessionManager

T = TypeVar("T", bound=BaseModel)

_log = structlog.get_logger("secure_llm_server.routers.envelope")
# Uniform latency floor on the auth-rejection paths to dampen timing oracles.
_AUTH_FAIL_FLOOR_S = 0.20


def _err(code: ErrorCode, message: str = "", *, http: int = 400) -> HTTPException:
    body = ErrorEnvelope(code=code, message=message).model_dump()
    return HTTPException(status_code=http, detail=body)


async def _slow(start: float) -> None:
    spent = time.monotonic() - start
    if spent < _AUTH_FAIL_FLOOR_S:
        await asyncio.sleep(_AUTH_FAIL_FLOOR_S - spent)


async def decrypt_request(
    request: Request,
    session_manager: SessionManager,
    schema: type[T],
) -> tuple[Session, T]:
    started = time.monotonic()
    raw = await request.body()
    if len(raw) < 41:  # min envelope size
        envelope_failures_total.labels("too_short").inc()
        await _slow(started)
        raise _err(ErrorCode.BAD_ENVELOPE, http=400)

    from secure_llm_protocol.wire import unpack_envelope

    try:
        env = unpack_envelope(raw)
    except Exception:
        envelope_failures_total.labels("malformed").inc()
        await _slow(started)
        raise _err(ErrorCode.BAD_ENVELOPE, http=400) from None

    # Federation note: lookup_async falls back to the backing store on
    # cache miss, so a session created on instance A can be served by
    # instance B after a failover.
    session = await session_manager.lookup_async(env.session_id)
    if session is None:
        envelope_failures_total.labels("unknown_session").inc()
        await _slow(started)
        raise _err(ErrorCode.UNKNOWN_SESSION, http=401)

    # Replay check is on counter alone — AEAD verifies the nonce binding.
    try:
        session.replay.check_and_advance(env.counter)
    except ReplayDetected:
        envelope_failures_total.labels("replay").inc()
        await _slow(started)
        raise _err(ErrorCode.REPLAY_DETECTED, http=400) from None

    try:
        _, plaintext = open_envelope(
            direction=session.c2s,
            expected_session_id=session.session_id,
            method=request.method,
            path=request.url.path,
            body=raw,
        )
    except EnvelopeAuthError:
        envelope_failures_total.labels("aead").inc()
        await _slow(started)
        raise _err(ErrorCode.DECRYPT_FAILED, http=400) from None

    try:
        parsed = schema.model_validate_json(plaintext)
    except ValidationError as e:
        envelope_failures_total.labels("schema").inc()
        raise _err(ErrorCode.BAD_REQUEST, message=str(e), http=400) from None

    session.touch()
    # Persist replay watermark + last_used_at so a federated peer
    # picking this session up after failover sees the right state.
    # No-op for the in-memory store.
    await session_manager.persist(session)
    request.state.client_fingerprint = session.client_fingerprint
    request.state.tenant = session.tenant
    structlog.contextvars.bind_contextvars(
        session_id=session.session_id_b64,
        client_fp=session.client_fingerprint,
        tenant=session.tenant,
    )
    return session, parsed


def encrypt_response(
    session: Session,
    payload: BaseModel | dict[str, Any],
    *,
    method: str,
    path: str,
    direction: DirectionKeys | None = None,
) -> bytes:
    """Seal ``payload`` for this session's s2c direction.

    ``direction`` overrides ``session.s2c`` — the admin terminate handler
    saves the live direction keys before calling ``SessionManager.terminate``
    (which zeroes them) so it can still send a final goodbye envelope the
    caller can decrypt.
    """
    if isinstance(payload, BaseModel):
        body = payload.model_dump_json().encode("utf-8")
    else:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    session.s2c_counter += 1
    return seal(
        direction=direction if direction is not None else session.s2c,
        counter=session.s2c_counter,
        session_id=session.session_id,
        method=method,
        path=path,
        plaintext=body,
    )
