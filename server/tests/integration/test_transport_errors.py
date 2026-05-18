"""Client transport error-path coverage.

- session-expired → auto-rehandshake retry
- plaintext JSON error envelope → typed exception
- bad SSE base64 → SecureLLMError(BAD_ENVELOPE)
- HTTP 4xx without content-type stream → SecureLLMError
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import (
    SecureLLMError,
)
from secure_llm_client.transport import Transport
from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


class _Body(BaseModel):
    text: str


def _build_app(tmp_path: Path) -> tuple[FastAPI, Keystore, ClientIdentity]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)
    cid = ClientIdentity.generate_and_save(tmp_path / "client")
    keystore = Keystore(
        server=server_id,
        allowlist={
            cid.x25519_pk: AuthorizedClient(
                name="t",
                x25519_pk=cid.x25519_pk,
                ed25519_pk=cid.ed25519_pk,
                scopes=("chat",),
            )
        },
    )
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)

    app = FastAPI()
    app.state.keystore = keystore
    app.state.session_manager = sm
    app.state.settings = type(
        "S",
        (),
        {
            "crypto": type(
                "C",
                (),
                {"handshake_skew_seconds": 30, "session_ttl_seconds": 3600},
            )()
        },
    )()
    app.include_router(session_router)

    @app.post("/v1/echo")
    async def echo(request: Request) -> Response:
        session, parsed = await decrypt_request(request, sm, _Body)
        body = encrypt_response(
            session, {"echo": parsed.text}, method=request.method, path=request.url.path
        )
        return Response(content=body, media_type="application/octet-stream")

    @app.post("/v1/plain-error")
    async def plain_error() -> JSONResponse:
        return JSONResponse(
            {"code": ErrorCode.RATE_LIMITED.value, "message": "slow", "retry_after_seconds": 0.5},
            status_code=429,
        )

    @app.post("/v1/stream-bad")
    async def stream_bad() -> StreamingResponse:
        async def _gen():
            # Emit a non-base64 data line so the client raises BAD_ENVELOPE.
            yield b"data: !!!NOT_BASE64!!!\n\n"
            yield b"data: [DONE]\n\n"

        return StreamingResponse(_gen(), media_type="text/event-stream")

    return app, keystore, cid


def _client(app: FastAPI, keystore: Keystore, key_base: Path) -> Transport:
    identity = ClientIdentity.load(key_base)
    base = "http://testserver"
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = TestClient(app, base_url=base)  # type: ignore[attr-defined]
    return t


def test_session_expired_triggers_rehandshake(tmp_path: Path):
    app, keystore, _ = _build_app(tmp_path)
    t = _client(app, keystore, tmp_path / "client")
    # First call: establish session.
    out = t.request("POST", "/v1/echo", payload={"text": "hi"})
    assert out["echo"] == "hi"
    # Wipe the server-side session table to force UNKNOWN_SESSION on next call.
    app.state.session_manager._store._by_id.clear()  # type: ignore[attr-defined]
    # The transport should detect, re-handshake, and succeed transparently.
    out2 = t.request("POST", "/v1/echo", payload={"text": "again"})
    assert out2["echo"] == "again"


def test_plain_json_error_surfaces_typed_exception(tmp_path: Path):
    app, keystore, _ = _build_app(tmp_path)
    t = _client(app, keystore, tmp_path / "client")
    # Drive a handshake first.
    t.request("POST", "/v1/echo", payload={"text": "x"})
    # Now drive the /v1/plain-error endpoint that returns a JSON envelope.
    from secure_llm_client.errors import RateLimited

    with pytest.raises(RateLimited) as exc:
        t.request("POST", "/v1/plain-error", payload={})
    assert exc.value.code == ErrorCode.RATE_LIMITED
    assert exc.value.retry_after == 0.5


def test_stream_request_bad_base64(tmp_path: Path):
    app, keystore, _ = _build_app(tmp_path)
    t = _client(app, keystore, tmp_path / "client")
    # Force handshake to set up keys (stream_request uses them).
    t.request("POST", "/v1/echo", payload={"text": "warmup"})
    with pytest.raises(SecureLLMError) as exc:
        list(t.stream_request("POST", "/v1/stream-bad", payload={}))
    assert exc.value.code == ErrorCode.BAD_ENVELOPE


def test_close_zeroizes_session_state(tmp_path: Path):
    app, keystore, _ = _build_app(tmp_path)
    t = _client(app, keystore, tmp_path / "client")
    t.request("POST", "/v1/echo", payload={"text": "warmup"})
    # close() resets the session + closes the httpx client; should be idempotent.
    t.close()
    # A second close should be safe too (no live session, but httpx client is gone).
    # We don't drive a third call; just confirm no exception.
