"""Tenant-admin can NOT terminate a session belonging to another tenant."""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import AdminRequiredError
from secure_llm_client.transport import Transport
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers.admin import router as admin_router
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


def _build(tmp_path: Path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)

    identities = {}
    allowlist = {}
    for name, tenant, scopes in [
        ("alice", "a", ("chat", "admin")),
        ("bob", "b", ("chat", "admin")),
    ]:
        ident = ClientIdentity.generate_and_save(tmp_path / name)
        identities[name] = ident
        allowlist[ident.x25519_pk] = AuthorizedClient(
            name=name,
            x25519_pk=ident.x25519_pk,
            ed25519_pk=ident.ed25519_pk,
            scopes=scopes,
            tenant=tenant,
        )

    keystore = Keystore(server=server_id, allowlist=allowlist)
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
            )()
        },
    )()
    app.include_router(session_router)
    app.include_router(admin_router)
    return app, keystore, identities


def _client(app: FastAPI, keystore: Keystore, key_base: Path) -> Transport:
    base = "http://testserver"
    t = Transport(
        base_url=base,
        identity=ClientIdentity.load(key_base),
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = TestClient(app, base_url=base)  # type: ignore[attr-defined]
    return t


def test_cross_tenant_terminate_denied(tmp_path: Path):
    app, keystore, _ = _build(tmp_path)
    alice = _client(app, keystore, tmp_path / "alice")
    bob = _client(app, keystore, tmp_path / "bob")
    # Make sure both have live sessions.
    alice.request("POST", "/v1/admin/sessions/list", payload={})
    bob.request("POST", "/v1/admin/sessions/list", payload={})

    # Pull alice's session id from her own session_state — that's the one
    # bob will try to kill.
    a_state = alice._session_state()  # type: ignore[attr-defined]
    a_sid_b64 = base64.b64encode(a_state.outcome.session_id).decode("ascii")

    import pytest

    with pytest.raises(AdminRequiredError):
        bob.request("POST", "/v1/admin/sessions/terminate", payload={"session_id": a_sid_b64})
