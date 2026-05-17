"""Shared helpers for in-process router integration tests.

Each test builds a minimal FastAPI app with the routers under test, a
real :class:`Keystore` + :class:`SessionManager`, and an
``_StubModels`` / ``_StubRegistry`` for whatever the test exercises.
This module factors out the handshake boilerplate so each test file
stays small and obvious.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.transport import Transport
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


def _settings_stub() -> Any:
    return type(
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
            "models": type(
                "M",
                (),
                {
                    "allow_download": True,
                    "allowed_repo_prefixes": [],
                    "disk_quota_gb": 50,
                },
            )(),
        },
    )()


def build_app(
    tmp_path: Path,
    *,
    extra_routers: list[Any],
    scopes: tuple[str, ...] = ("chat", "admin"),
    tenant: str = "default",
) -> tuple[FastAPI, Keystore, ClientIdentity]:
    """Spin up an in-process FastAPI app with the session router plus extras."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)
    client_id = ClientIdentity.generate_and_save(tmp_path / "client")
    keystore = Keystore(
        server=server_id,
        allowlist={
            client_id.x25519_pk: AuthorizedClient(
                name="t",
                x25519_pk=client_id.x25519_pk,
                ed25519_pk=client_id.ed25519_pk,
                scopes=scopes,
                tenant=tenant,
            )
        },
    )
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)
    app = FastAPI()
    app.state.keystore = keystore
    app.state.session_manager = sm
    app.state.settings = _settings_stub()
    app.include_router(session_router)
    for r in extra_routers:
        app.include_router(r)
    return app, keystore, client_id


def make_transport(app: FastAPI, keystore: Keystore, client_key_base: Path) -> Transport:
    """Wire a real :class:`Transport` against an in-process ASGI app."""
    identity = ClientIdentity.load(client_key_base)
    base = "http://testserver"
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = TestClient(app, base_url=base)  # type: ignore[attr-defined]
    return t
