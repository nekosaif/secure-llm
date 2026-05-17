"""In-process server: handshake + a dummy encrypted echo round-trip via the session machinery.

We don't run llama.cpp here — too heavy and not the point. We exercise:
- handshake via the real router
- envelope wrap/unwrap via Transport
- a fake "echo" endpoint added in the test app

This catches almost every framing/AEAD/AAD/replay bug without requiring a model.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from pydantic import BaseModel

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers._envelope_dep import decrypt_request, encrypt_response
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


class _Echo(BaseModel):
    text: str


def _build_app(tmp_path: Path) -> tuple[FastAPI, Keystore, SessionManager, ClientIdentity]:
    keystore_dir = tmp_path / "keys"
    keystore_dir.mkdir()
    keystore_dir.chmod(0o700)
    server_id = init_server_identity(keystore_dir)

    # client
    client_id = ClientIdentity.generate_and_save(tmp_path / "client")

    keystore = Keystore(
        server=server_id,
        allowlist={
            client_id.x25519_pk: AuthorizedClient(
                name="t",
                x25519_pk=client_id.x25519_pk,
                ed25519_pk=client_id.ed25519_pk,
                scopes=("chat", "admin"),
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
                {
                    "handshake_skew_seconds": 30,
                    "session_ttl_seconds": 3600,
                },
            )(),
        },
    )()

    app.include_router(session_router)

    @app.post("/v1/echo")
    async def echo(request: Request) -> Response:
        session, req = await decrypt_request(request, sm, _Echo)
        body = encrypt_response(
            session,
            {"echo": req.text, "scopes": list(session.scopes)},
            method=request.method,
            path=request.url.path,
        )
        return Response(content=body, media_type="application/octet-stream")

    return app, keystore, sm, client_id


def test_handshake_echo_roundtrip(tmp_path: Path):
    app, keystore, _sm, _client_id = _build_app(tmp_path)
    base = "http://testserver"
    http = TestClient(app, base_url=base)
    from secure_llm_client.transport import Transport

    identity = ClientIdentity.load(tmp_path / "client")
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = http  # type: ignore[attr-defined]

    resp = t.request("POST", "/v1/echo", payload={"text": "hi"})
    assert resp["echo"] == "hi"
    assert sorted(resp["scopes"]) == ["admin", "chat"]


def test_unknown_client_rejected(tmp_path: Path):
    app, keystore, _sm, _id = _build_app(tmp_path)
    keystore.allowlist = {}
    from secure_llm_client.errors import HandshakeFailed
    from secure_llm_client.transport import Transport

    identity = ClientIdentity.load(tmp_path / "client")
    base = "http://testserver"
    http = TestClient(app, base_url=base)
    t = Transport(
        base_url=base, identity=identity, pinned_server_pk=keystore.server.x25519_pk, verify=False
    )
    t._client = http  # type: ignore[attr-defined]

    with pytest.raises(HandshakeFailed):
        t.request("POST", "/v1/echo", payload={"text": "x"})
