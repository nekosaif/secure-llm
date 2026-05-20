"""At-rest encryption of model files using age (via ``pyrage``).

Plaintext model bytes are decrypted into a tmpfs file that is immediately
``unlink()``ed after open, so they live only in the page/inode cache backing
the mmap. The decrypted file never appears on persistent storage.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pyrage  # type: ignore[import-untyped]


class AtRestKey:
    """Wrapper over a pyrage X25519 identity loaded from disk."""

    def __init__(self, identity_path: Path) -> None:
        self._identity_path = identity_path
        text = identity_path.read_text(encoding="ascii").strip()
        if not text:
            raise RuntimeError(f"empty age identity at {identity_path}; re-run keystore init")
        self._identity = pyrage.x25519.Identity.from_str(text)
        self._recipient = self._identity.to_public()

    @property
    def recipient(self) -> pyrage.x25519.Recipient:
        return self._recipient

    @property
    def identity(self) -> pyrage.x25519.Identity:
        return self._identity


def _write_all(fd: int, data: bytes) -> None:
    """Loop ``os.write`` until every byte of ``data`` lands on disk.

    ``os.write`` is a thin ``write(2)`` wrapper that returns the number of
    bytes actually written; on Linux a single ``write(2)`` is capped at
    ``0x7FFFF000`` bytes (~2 GiB), so for multi-GiB blobs (e.g. a Q4_K_M
    9B GGUF, ~5 GiB) the syscall silently truncates. Without this loop the
    decrypted model is short and ``llama.cpp`` rejects it with a confusing
    "tensor data not within file bounds" error. The regression test in
    ``tests/unit/test_at_rest.py`` monkey-patches ``os.write`` to return
    short counts and asserts every byte still gets written.
    """
    mv = memoryview(data)
    n = 0
    while n < len(mv):
        written = os.write(fd, mv[n:])
        if written == 0:
            # POSIX says this means EOF (rare for regular files); treat as
            # disk-full / closed-fd. Fail loudly rather than spin forever.
            raise OSError("os.write returned 0 — disk full or fd closed")
        n += written


def encrypt_file(src: Path, dst: Path, key: AtRestKey) -> None:
    """Encrypt ``src`` → ``dst.age`` atomically."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    plaintext = src.read_bytes()
    encrypted = pyrage.encrypt(plaintext, [key.recipient])
    tmp.write_bytes(encrypted)
    os.replace(tmp, dst)


@contextmanager
def decrypt_to_tmpfs(src: Path, tmpfs_dir: Path, key: AtRestKey) -> Iterator[Path]:
    """Decrypt ``src`` into a tmpfs-backed file; unlink it after open.

    Yields the path; the file is only readable until the caller's
    :func:`open` (e.g. ``llama.cpp``'s mmap) succeeds. After the ``with``
    block exits, the inode is gone and the bytes are freed when nothing has
    them mapped.
    """
    tmpfs_dir.mkdir(parents=True, exist_ok=True)
    ciphertext = src.read_bytes()
    plaintext = pyrage.decrypt(ciphertext, [key.identity])
    name = tmpfs_dir / f"{uuid.uuid4()}.gguf"
    fd = os.open(str(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(fd, plaintext)
    finally:
        os.close(fd)
    try:
        yield name
    finally:
        # caller is expected to have mmap'd by this point; unlinking only
        # removes the dentry, the bytes survive in the open mapping.
        try:
            name.unlink()
        except FileNotFoundError:
            pass
