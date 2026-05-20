"""at_rest.AtRestKey + encrypt_file + decrypt_to_tmpfs round-trip."""

from __future__ import annotations

import os
from pathlib import Path

import pyrage
import pytest

from secure_llm_server.crypto import at_rest
from secure_llm_server.crypto.at_rest import (
    AtRestKey,
    _write_all,
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


# --- regression: short os.write returns must not silently truncate ---
#
# Linux's write(2) caps a single syscall at 0x7FFFF000 bytes (~2 GiB). For
# multi-GiB GGUFs this surfaced as a corrupted decrypted model where
# llama.cpp reported "tensor data not within file bounds". The fix
# loops os.write until every byte lands on disk; these tests pin that
# behavior so the regression can't sneak back in.


def test_write_all_loops_when_kernel_returns_partial(tmp_path: Path, monkeypatch):
    """Simulate the kernel returning at most 100 bytes per write(2). The
    helper must loop until every byte is written."""
    real_write = os.write
    counts: list[int] = []

    def short_write(fd: int, buf) -> int:
        view = memoryview(buf)
        n = min(100, len(view))
        counts.append(n)
        return real_write(fd, bytes(view[:n]))

    monkeypatch.setattr(at_rest.os, "write", short_write)

    target = tmp_path / "out.bin"
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(fd, b"X" * 1024)
    finally:
        os.close(fd)

    assert target.stat().st_size == 1024, "short os.write returns were not retried"
    assert target.read_bytes() == b"X" * 1024
    # At least 11 calls (1024 / 100 = 10.24 → 11 calls).
    assert len(counts) >= 11, f"expected ≥11 looped writes, got {len(counts)}"


def test_write_all_raises_when_kernel_returns_zero(tmp_path: Path, monkeypatch):
    """``os.write`` returning 0 means disk full / fd closed (POSIX EOF on
    a regular file). The helper must fail loudly instead of spinning."""

    def zero_write(_fd: int, _buf) -> int:
        return 0

    monkeypatch.setattr(at_rest.os, "write", zero_write)
    target = tmp_path / "out.bin"
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with pytest.raises(OSError, match="disk full or fd closed"):
            _write_all(fd, b"data")
    finally:
        os.close(fd)


def test_decrypt_to_tmpfs_handles_multi_chunk_writes(tmp_path: Path, monkeypatch):
    """End-to-end: encrypt a multi-MB blob, decrypt with short-write
    simulation in place, verify the full plaintext lands on disk.

    Catches the original 2-GiB truncation bug at any size — the
    monkey-patch forces multi-syscall writes for a CI-friendly blob."""
    ident_path = _make_identity(tmp_path)
    key = AtRestKey(ident_path)
    payload = b"A" * (2 * 1024 * 1024)  # 2 MiB
    src = tmp_path / "plain.bin"
    src.write_bytes(payload)
    sealed = tmp_path / "out.age"
    encrypt_file(src, sealed, key)

    real_write = os.write

    def short_write(fd: int, buf) -> int:
        view = memoryview(buf)
        n = min(64 * 1024, len(view))  # 64 KiB per syscall — forces ~32 calls
        return real_write(fd, bytes(view[:n]))

    monkeypatch.setattr(at_rest.os, "write", short_write)

    with decrypt_to_tmpfs(sealed, tmp_path / "tmpfs", key) as plain:
        decrypted = plain.read_bytes()
    assert decrypted == payload, "decrypt_to_tmpfs truncated under short writes"
