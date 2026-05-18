"""Envelope-decryption error paths in routers/_envelope_dep.

The successful path is exercised by every other integration test. This
file covers each rejection branch:

- too-short body                       → bad_envelope (400)
- malformed header                     → bad_envelope (400)
- unknown session id                   → unknown_session (401)
- replay (counter reused)              → replay_detected (400)
- AEAD failure (key/aad mismatch)      → decrypt_failed (400)
- pydantic schema validation failure   → bad_request (400)
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import BaseModel

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.transport import Transport
from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)
from secure_llm_server.routers.session import router as session_router


class _Body(BaseModel):
    text: str


def _build_app(tmp_path: Path) -> tuple[FastAPI, object, ClientIdentity]:
    from secure_llm_server.crypto.keystore import (
        AuthorizedClient,
        Keystore,
        init_server_identity,
    )
    from secure_llm_server.session.manager import SessionManager

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

    @app.post("/v1/echo")
    async def echo(request: Request) -> Response:
        session, parsed = await decrypt_request(request, sm, _Body)
        body = encrypt_response(
            session,
            {"echo": parsed.text},
            method=request.method,
            path=request.url.path,
        )
        return Response(content=body, media_type="application/octet-stream")

    app.include_router(session_router)
    return app, keystore, cid


def _client(app: FastAPI, keystore: object, key_base: Path) -> tuple[Transport, TestClient]:
    identity = ClientIdentity.load(key_base)
    base = "http://testserver"
    http = TestClient(app, base_url=base)
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,  # type: ignore[attr-defined]
        verify=False,
    )
    t._client = http  # type: ignore[attr-defined]
    return t, http


def test_too_short_body_rejected(tmp_path: Path):
    app, _ks, _cid = _build_app(tmp_path)
    http = TestClient(app, base_url="http://testserver")
    r = http.post(
        "/v1/echo",
        content=b"x",
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == ErrorCode.BAD_ENVELOPE.value


def test_malformed_envelope_rejected(tmp_path: Path):
    app, _ks, _cid = _build_app(tmp_path)
    http = TestClient(app, base_url="http://testserver")
    # Long enough to pass the length check, but wrong magic + tag.
    body = b"X" * 200
    r = http.post(
        "/v1/echo",
        content=body,
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == ErrorCode.BAD_ENVELOPE.value


def test_unknown_session_rejected(tmp_path: Path):
    app, keystore, _cid = _build_app(tmp_path)
    t, _http = _client(app, keystore, tmp_path / "client")
    # Drive a real envelope first, then forge one with a different session_id.
    t.request("POST", "/v1/echo", payload={"text": "hi"})

    # Forge an envelope with random session_id but valid framing.
    from secure_llm_protocol.wire import pack_envelope

    bogus = pack_envelope(
        secrets.token_bytes(16),  # unknown sid
        counter=1,
        nonce=secrets.token_bytes(12),
        ciphertext=b"\x00" * 32,  # 16 bytes ct + 16 tag (won't matter)
    )
    http = TestClient(app, base_url="http://testserver")
    r = http.post(
        "/v1/echo",
        content=bogus,
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == ErrorCode.UNKNOWN_SESSION.value


def test_replay_detected(tmp_path: Path):
    app, keystore, _cid = _build_app(tmp_path)
    t, http = _client(app, keystore, tmp_path / "client")
    # Drive one real request so the session is registered.
    out = t.request("POST", "/v1/echo", payload={"text": "first"})
    assert out["echo"] == "first"

    # Re-seal a request with a *counter we've already used* (counter=1).
    from secure_llm_server.crypto.envelope import seal

    state = t._session_state()  # type: ignore[attr-defined]
    body = seal(
        direction=state.outcome.c2s,
        counter=1,  # already advanced past this
        session_id=state.outcome.session_id,
        method="POST",
        path="/v1/echo",
        plaintext=b'{"text":"replay"}',
    )
    r = http.post(
        "/v1/echo",
        content=body,
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == ErrorCode.REPLAY_DETECTED.value


def test_aead_failure_decrypt_failed(tmp_path: Path):
    """Bit-flip a real envelope's ciphertext byte → AEAD verify fails."""
    app, keystore, _cid = _build_app(tmp_path)
    t, http = _client(app, keystore, tmp_path / "client")
    t.request("POST", "/v1/echo", payload={"text": "warmup"})

    from secure_llm_server.crypto.envelope import seal

    state = t._session_state()  # type: ignore[attr-defined]
    body = bytearray(
        seal(
            direction=state.outcome.c2s,
            counter=999,
            session_id=state.outcome.session_id,
            method="POST",
            path="/v1/echo",
            plaintext=b'{"text":"tampered"}',
        )
    )
    body[-1] ^= 0xFF  # break the AEAD tag
    r = http.post(
        "/v1/echo",
        content=bytes(body),
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == ErrorCode.DECRYPT_FAILED.value


def test_schema_validation_failure(tmp_path: Path):
    """Valid envelope, wrong inner JSON shape → bad_request (400)."""
    app, keystore, _cid = _build_app(tmp_path)
    t, http = _client(app, keystore, tmp_path / "client")
    t.request("POST", "/v1/echo", payload={"text": "warmup"})

    from secure_llm_server.crypto.envelope import seal

    state = t._session_state()  # type: ignore[attr-defined]
    body = seal(
        direction=state.outcome.c2s,
        counter=999,
        session_id=state.outcome.session_id,
        method="POST",
        path="/v1/echo",
        plaintext=b'{"wrong":"shape"}',  # missing required `text` field
    )
    r = http.post(
        "/v1/echo",
        content=body,
        headers={"content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == ErrorCode.BAD_REQUEST.value
