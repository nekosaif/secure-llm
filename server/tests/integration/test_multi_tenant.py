"""Tenant isolation: clients in tenant A cannot see anything from tenant B.

Asserts:
- ``/v1/admin/sessions/list`` returns only the caller's own tenant.
- ``/v1/admin/clients/list``  returns only the caller's own tenant.
- A ``super_admin`` in tenant ``ops`` sees both.
- ``/v1/admin/tenants/list`` rejects tenant-admins; ``super_admin`` succeeds.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.transport import Transport
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers.admin import router as admin_router
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


def _build_app(tmp_path: Path) -> tuple[FastAPI, Keystore, dict[str, ClientIdentity]]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)

    identities: dict[str, ClientIdentity] = {}
    allowlist: dict[bytes, AuthorizedClient] = {}
    for name, tenant, scopes in [
        ("alice", "a", ("chat", "admin")),
        ("bob", "b", ("chat", "admin")),
        ("ops", "ops", ("chat", "admin", "super_admin")),
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

    # Minimal app-state stubs — we only exercise the admin sessions/clients/tenants
    # endpoints which don't need a real ModelManager.
    class _StubMTRegistry:
        def for_tenant(self, t: str) -> object:
            class _R:
                def all(self) -> list[object]:
                    return []

            return _R()

        def known_tenants(self) -> list[str]:
            return []

    app = FastAPI()
    app.state.keystore = keystore
    app.state.session_manager = sm
    app.state.registry = _StubMTRegistry()
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


def _new_client(app: FastAPI, keystore: Keystore, base: str, key_path: Path) -> Transport:
    identity = ClientIdentity.load(key_path)
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    http = TestClient(app, base_url=base)
    t._client = http  # type: ignore[attr-defined]
    return t


def test_tenant_admin_only_sees_own_tenant(tmp_path: Path):
    app, keystore, identities = _build_app(tmp_path)
    base = "http://testserver"
    alice = _new_client(app, keystore, base, tmp_path / "alice")
    bob = _new_client(app, keystore, base, tmp_path / "bob")
    # Force handshakes so two sessions across two tenants exist.
    alice.request("POST", "/v1/admin/sessions/list", payload={})
    bob.request("POST", "/v1/admin/sessions/list", payload={})

    alice_view = alice.request("POST", "/v1/admin/sessions/list", payload={})
    bob_view = bob.request("POST", "/v1/admin/sessions/list", payload={})

    # Each tenant-admin sees only their own tenant's sessions
    assert len(alice_view["sessions"]) == 1
    assert len(bob_view["sessions"]) == 1
    assert (
        alice_view["sessions"][0]["client_fingerprint"]
        != bob_view["sessions"][0]["client_fingerprint"]
    )

    # Clients listing follows the same scoping rule.
    alice_clients = alice.request("POST", "/v1/admin/clients/list", payload={})
    fps = {c["fingerprint"] for c in alice_clients["clients"]}
    from secure_llm_server.crypto.kdf import fingerprint as _fp

    assert _fp(identities["alice"].x25519_pk) in fps
    assert _fp(identities["bob"].x25519_pk) not in fps


def test_super_admin_sees_all_tenants(tmp_path: Path):
    app, keystore, _identities = _build_app(tmp_path)
    base = "http://testserver"
    alice = _new_client(app, keystore, base, tmp_path / "alice")
    bob = _new_client(app, keystore, base, tmp_path / "bob")
    ops = _new_client(app, keystore, base, tmp_path / "ops")
    alice.request("POST", "/v1/admin/sessions/list", payload={})
    bob.request("POST", "/v1/admin/sessions/list", payload={})

    ops_view = ops.request("POST", "/v1/admin/sessions/list", payload={})
    # super_admin sees alice, bob, and ops's own
    assert len(ops_view["sessions"]) >= 3


def test_tenants_list_requires_super_admin(tmp_path: Path):
    app, keystore, _ids = _build_app(tmp_path)
    base = "http://testserver"
    alice = _new_client(app, keystore, base, tmp_path / "alice")
    ops = _new_client(app, keystore, base, tmp_path / "ops")

    import pytest

    from secure_llm_client.errors import AdminRequiredError

    with pytest.raises(AdminRequiredError):
        alice.request("POST", "/v1/admin/tenants/list", payload={})

    out = ops.request("POST", "/v1/admin/tenants/list", payload={})
    tenant_names = {t["name"] for t in out["tenants"]}
    assert {"a", "b", "ops"} <= tenant_names
