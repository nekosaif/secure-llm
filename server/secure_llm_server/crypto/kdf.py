"""HKDF-SHA-256 + small helpers (fingerprinting, key zeroization)."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Final

HKDF_HASH: Final = hashlib.sha256
HKDF_HASH_LEN: Final = HKDF_HASH().digest_size  # 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * HKDF_HASH_LEN
    return hmac.new(salt, ikm, HKDF_HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * HKDF_HASH_LEN:
        raise ValueError("HKDF length exceeds maximum")
    blocks: list[bytes] = []
    prev = b""
    counter = 1
    while sum(len(b) for b in blocks) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), HKDF_HASH).digest()
        blocks.append(prev)
        counter += 1
    return b"".join(blocks)[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def fingerprint(pubkey: bytes) -> str:
    """Stable short fingerprint for logs/UX. SHA-256, first 16 base32 chars."""
    digest = hashlib.sha256(pubkey).digest()
    return base64.b32encode(digest)[:16].decode("ascii").lower()


def zeroize(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer. Python can't truly wipe immutables."""
    for i in range(len(buf)):
        buf[i] = 0
