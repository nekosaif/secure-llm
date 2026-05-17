"""HKDF-SHA-256 (mirror of server-side; kept independent so the client has no server dep)."""

from __future__ import annotations

import base64
import hashlib
import hmac

_H = hashlib.sha256
_HLEN = _H().digest_size


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * _HLEN
    prk = hmac.new(salt, ikm, _H).digest()
    blocks: list[bytes] = []
    prev = b""
    counter = 1
    while sum(len(b) for b in blocks) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), _H).digest()
        blocks.append(prev)
        counter += 1
    return b"".join(blocks)[:length]


def fingerprint(pubkey: bytes) -> str:
    return base64.b32encode(hashlib.sha256(pubkey).digest())[:16].decode("ascii").lower()
