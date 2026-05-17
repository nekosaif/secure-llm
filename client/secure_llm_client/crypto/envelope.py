"""Client-side AEAD envelope (mirror of server module).

Kept as a near-twin of the server to make protocol audits straightforward:
exactly the same primitive, same nonce derivation, same AAD shape.
"""

from __future__ import annotations

from dataclasses import dataclass

from nacl.bindings import (
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt,
)

from secure_llm_protocol.wire import (
    NONCE_BYTES,
    Envelope,
    build_aad,
    pack_envelope,
    unpack_envelope,
)


class EnvelopeAuthError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class DirectionKeys:
    key: bytes
    nonce_prefix: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("key must be 32 bytes")
        if len(self.nonce_prefix) != 4:
            raise ValueError("nonce_prefix must be 4 bytes")


def nonce_for(direction: DirectionKeys, counter: int) -> bytes:
    if counter < 0 or counter >> 64:
        raise ValueError("counter out of range")
    nonce = direction.nonce_prefix + counter.to_bytes(8, "big")
    assert len(nonce) == NONCE_BYTES
    return nonce


def seal(
    *,
    direction: DirectionKeys,
    counter: int,
    session_id: bytes,
    method: str,
    path: str,
    plaintext: bytes,
) -> bytes:
    nonce = nonce_for(direction, counter)
    aad = build_aad(method=method, path=path, session_id=session_id, counter=counter)
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, nonce, direction.key)
    return pack_envelope(session_id, counter, nonce, ciphertext)


def open_envelope(
    *, direction: DirectionKeys, expected_session_id: bytes, method: str, path: str, body: bytes
) -> tuple[Envelope, bytes]:
    try:
        env = unpack_envelope(body)
    except Exception as e:
        raise EnvelopeAuthError(str(e)) from e
    if env.session_id != expected_session_id:
        raise EnvelopeAuthError("session_id mismatch")
    aad = build_aad(method=method, path=path, session_id=env.session_id, counter=env.counter)
    try:
        plaintext = crypto_aead_chacha20poly1305_ietf_decrypt(
            env.ciphertext, aad, env.nonce, direction.key
        )
    except Exception as e:
        raise EnvelopeAuthError("decrypt failed") from e
    return env, plaintext
