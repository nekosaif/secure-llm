"""at_rest.AtRestKey + encrypt_file + decrypt_to_tmpfs round-trip."""

from __future__ import annotations

from pathlib import Path

import pyrage
import pytest

from secure_llm_server.crypto.at_rest import (
    AtRestKey,
    decrypt_to_tmpfs,
    encrypt_file,
)


def _make_identity(tmp_path: Path) -> Path:
    ident = pyrage.x25519.Identity.generate()
    p = tmp_path / "id.age"
    p.write_text(str(ident), encoding="ascii")
    p.chmod(0o600)
    return p


def test_atrestkey_round_trip(tmp_path: Path):
    ident_path = _make_identity(tmp_path)
    key = AtRestKey(ident_path)
    assert key.recipient is not None
    assert key.identity is not None

    src = tmp_path / "plain.bin"
    src.write_bytes(b"hello secret world")
    sealed = tmp_path / "out.age"
    encrypt_file(src, sealed, key)
    assert sealed.exists()
    # Decrypt into tmpfs and read it back.
    with decrypt_to_tmpfs(sealed, tmp_path / "tmpfs", key) as plain:
        data = plain.read_bytes()
    assert data == b"hello secret world"


def test_atrestkey_empty_identity_raises(tmp_path: Path):
    empty = tmp_path / "empty.age"
    empty.write_text("", encoding="ascii")
    with pytest.raises(RuntimeError, match="empty age identity"):
        AtRestKey(empty)


def test_decrypt_to_tmpfs_unlinks_file(tmp_path: Path):
    ident_path = _make_identity(tmp_path)
    key = AtRestKey(ident_path)
    src = tmp_path / "plain.bin"
    src.write_bytes(b"trace")
    sealed = tmp_path / "out.age"
    encrypt_file(src, sealed, key)
    tmpfs = tmp_path / "tmpfs"
    seen: Path
    with decrypt_to_tmpfs(sealed, tmpfs, key) as plain:
        seen = plain
        assert plain.exists()
    # After the context exits, the dentry is gone.
    assert not seen.exists()
