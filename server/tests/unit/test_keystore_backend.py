"""v1.3 KeystoreBackend Protocol + FileKeystoreBackend wrapper."""

from __future__ import annotations

import base64
from pathlib import Path

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from secure_llm_server.crypto.keystore import (
    DEFAULT_TENANT,
    FileKeystoreBackend,
    Keystore,
)


def test_file_backend_loads_identity_initializing_if_absent(tmp_path: Path):
    backend = FileKeystoreBackend(key_dir=tmp_path / "keys", allowlist_path=None)
    ident = backend.load_server_identity()
    assert len(ident.x25519_pk) == 32
    assert len(ident.ed25519_pk) == 32
    # Calling again loads the same identity (no init-on-existing race).
    ident2 = backend.load_server_identity()
    assert ident2.x25519_pk == ident.x25519_pk


def test_file_backend_empty_allowlist_when_path_none(tmp_path: Path):
    backend = FileKeystoreBackend(key_dir=tmp_path / "keys", allowlist_path=None)
    assert backend.load_allowlist() == {}


def test_file_backend_reads_allowlist_from_disk(tmp_path: Path):
    key_dir = tmp_path / "keys"
    allow_path = tmp_path / "authorized_clients.toml"
    x_pk = bytes(PrivateKey.generate().public_key)
    e_pk = bytes(SigningKey.generate().verify_key)
    allow_path.write_text(
        f'[[clients]]\nname = "a"\n'
        f'x25519_pk = "{base64.b64encode(x_pk).decode()}"\n'
        f'ed25519_pk = "{base64.b64encode(e_pk).decode()}"\nscopes = ["chat"]\n',
        encoding="utf-8",
    )
    backend = FileKeystoreBackend(key_dir=key_dir, allowlist_path=allow_path)
    allow = backend.load_allowlist()
    assert x_pk in allow
    assert allow[x_pk].tenant == DEFAULT_TENANT


def test_file_backend_to_keystore_returns_complete_keystore(tmp_path: Path):
    backend = FileKeystoreBackend(key_dir=tmp_path / "keys", allowlist_path=None)
    ks = backend.to_keystore()
    assert isinstance(ks, Keystore)
    assert ks.allowlist == {}
    assert ks.server.x25519_pk == backend.load_server_identity().x25519_pk
