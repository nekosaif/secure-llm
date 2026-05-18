"""Keystore: server identity init/load, allowlist loading, per-tenant scoping."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from secure_llm_server.crypto.keystore import (
    DEFAULT_TENANT,
    AuthorizedClient,
    Keystore,
    init_server_identity,
    load_allowlist,
    load_or_init_keystore,
    load_server_identity,
)


def test_init_then_load_roundtrip(tmp_path: Path):
    ident = init_server_identity(tmp_path)
    loaded = load_server_identity(tmp_path)
    assert loaded.x25519_pk == ident.x25519_pk
    assert loaded.ed25519_pk == ident.ed25519_pk


def test_init_server_identity_when_already_present_raises(tmp_path: Path):
    """init_server_identity uses O_EXCL — calling twice fails the second time."""
    init_server_identity(tmp_path)
    with pytest.raises(FileExistsError):
        init_server_identity(tmp_path)


def test_load_or_init_keystore_existing_keys_path(tmp_path: Path):
    """Second call exercises the 'load existing' branch rather than init."""
    first = load_or_init_keystore(tmp_path, None)
    second = load_or_init_keystore(tmp_path, None)
    assert first.server.x25519_pk == second.server.x25519_pk


def test_load_or_init_creates_if_missing(tmp_path: Path):
    keystore = load_or_init_keystore(tmp_path, None)
    assert isinstance(keystore, Keystore)
    assert keystore.allowlist == {}
    # Second call hits the load-existing branch.
    keystore2 = load_or_init_keystore(tmp_path, None)
    assert keystore2.server.x25519_pk == keystore.server.x25519_pk


def test_load_server_identity_refuses_loose_perms(tmp_path: Path):
    init_server_identity(tmp_path)
    # Loosen perms on the X25519 secret to trigger the perm guard.
    (tmp_path / "server.x25519.key").chmod(0o644)
    with pytest.raises(PermissionError, match="world/group-accessible"):
        load_server_identity(tmp_path)


def test_load_allowlist_root_only(tmp_path: Path):
    x_pk = bytes(PrivateKey.generate().public_key)
    e_pk = bytes(SigningKey.generate().verify_key)
    toml = tmp_path / "authorized_clients.toml"
    toml.write_text(
        f'[[clients]]\nname = "alice"\nx25519_pk = "{base64.b64encode(x_pk).decode()}"\n'
        f'ed25519_pk = "{base64.b64encode(e_pk).decode()}"\nscopes = ["chat"]\n',
        encoding="utf-8",
    )
    allow = load_allowlist(toml)
    assert next(iter(allow)) == x_pk
    assert allow[x_pk].tenant == DEFAULT_TENANT
    assert allow[x_pk].scopes == ("chat",)


def test_load_allowlist_per_tenant_overrides_tenant_field(tmp_path: Path):
    """The per-tenant *directory* name wins over any TOML `tenant` field."""
    x_pk = bytes(PrivateKey.generate().public_key)
    e_pk = bytes(SigningKey.generate().verify_key)
    root_toml = tmp_path / "authorized_clients.toml"
    root_toml.write_text("clients = []\n", encoding="utf-8")
    tenant_dir = tmp_path / "tenants" / "acme"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "authorized_clients.toml").write_text(
        # Note: the TOML claims tenant="evil" but the directory should override.
        f'[[clients]]\nname = "bob"\ntenant = "evil"\n'
        f'x25519_pk = "{base64.b64encode(x_pk).decode()}"\n'
        f'ed25519_pk = "{base64.b64encode(e_pk).decode()}"\nscopes = ["chat"]\n',
        encoding="utf-8",
    )
    allow = load_allowlist(root_toml)
    assert allow[x_pk].tenant == "acme"  # directory wins


def test_load_allowlist_bad_pk_length(tmp_path: Path):
    toml = tmp_path / "authorized_clients.toml"
    toml.write_text(
        '[[clients]]\nname = "x"\n'
        f'x25519_pk = "{base64.b64encode(b"short").decode()}"\n'
        f'ed25519_pk = "{base64.b64encode(b"short").decode()}"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="bad pk length"):
        load_allowlist(toml)


def test_load_allowlist_missing_returns_empty(tmp_path: Path):
    assert load_allowlist(tmp_path / "nope.toml") == {}


def test_keystore_reload_allowlist(tmp_path: Path):
    key_dir = tmp_path / "keys"
    allow_path = tmp_path / "authorized_clients.toml"
    allow_path.write_text("clients = []\n", encoding="utf-8")
    keystore = load_or_init_keystore(key_dir, allow_path)
    assert keystore.reload_allowlist() == 0
    # Append one entry and reload.
    x_pk = bytes(PrivateKey.generate().public_key)
    e_pk = bytes(SigningKey.generate().verify_key)
    allow_path.write_text(
        f'[[clients]]\nname = "z"\nx25519_pk = "{base64.b64encode(x_pk).decode()}"\n'
        f'ed25519_pk = "{base64.b64encode(e_pk).decode()}"\n',
        encoding="utf-8",
    )
    assert keystore.reload_allowlist() == 1
    assert keystore.allowlist[x_pk].name == "z"


def test_keystore_reload_without_path_is_noop(tmp_path: Path):
    keystore = load_or_init_keystore(tmp_path, None)
    assert keystore.reload_allowlist() == 0


def test_authorized_client_fingerprint_stable():
    pk = secrets.token_bytes(32)
    c = AuthorizedClient(name="x", x25519_pk=pk, ed25519_pk=secrets.token_bytes(32))
    assert c.fingerprint == c.fingerprint  # deterministic
