"""ChaCha20-Poly1305-IETF envelope encryption.

The header and AAD shape is defined by :mod:`secure_llm_protocol.wire`; this
module is the actual crypto. Wrap/unwrap are pure — they take a session key and
counter and return bytes. Counter management and replay protection live in
:mod:`.replay`; nonce derivation lives here because it's tightly coupled to
AEAD safety (deterministic nonces are only safe given counter uniqueness).
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
    """AEAD verification failed. Constant-time-equivalent: do not differentiate."""


@dataclass(frozen=True, slots=True)
class DirectionKeys:
    """Per-session, per-direction symmetric key + 4-byte nonce prefix.

    Two of these per session: one for client→server, one for server→client.
    Keeping directions separated means counters can be independent and a stolen
    direction's keystream can't be used to forge in the other direction.
    """

    key: bytes  # 32 bytes
    nonce_prefix: bytes  # 4 bytes; concatenated with 8-byte big-endian counter

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
    """Encrypt + frame.

    AAD binds the envelope to the HTTP method+path+session+counter so a captured
    envelope can't be replayed against a different endpoint.
    """
    nonce = nonce_for(direction, counter)
    aad = build_aad(method=method, path=path, session_id=session_id, counter=counter)
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, aad, nonce, direction.key)
    return pack_envelope(session_id, counter, nonce, ciphertext)


def open_envelope(
    *,
    direction: DirectionKeys,
    expected_session_id: bytes,
    method: str,
    path: str,
    body: bytes,
) -> tuple[Envelope, bytes]:
    """Unframe + decrypt. Returns (parsed_envelope, plaintext).

    Raises :class:`EnvelopeAuthError` on any AEAD or framing failure; callers
    must not branch on the reason in user-visible responses (timing oracle).
    """
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
    except Exception as e:  # nacl raises CryptoError
        raise EnvelopeAuthError("decrypt failed") from e
    return env, plaintext
