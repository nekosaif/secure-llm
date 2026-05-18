"""Application-layer envelope framing.

Wire layout::

    magic(4) | version(1) | session_id(16) | counter(8) | nonce(12) | ciphertext | tag(16)

``magic`` and ``version`` exist so a future protocol bump can be detected
before AEAD verification. ``session_id`` is opaque to clients. ``counter`` is
strictly monotonic per direction; both sides keep a sliding window for
out-of-order tolerance and reject replays. ``nonce`` is derived from a
per-direction prefix concatenated with the counter, never reused, and bound
into the AEAD AAD along with method+path+version.

The envelope carries an opaque ciphertext blob; the actual JSON payload schema
lives in :mod:`secure_llm_protocol.schemas`. Encryption/decryption happens in
the server's and client's ``crypto`` packages; this module only does framing.
"""

from __future__ import annotations

from dataclasses import dataclass

ENVELOPE_MAGIC = b"SLLM"  # 4 bytes
ENVELOPE_VERSION = 1  # bumped only on framing breaks
SESSION_ID_BYTES = 16
COUNTER_BYTES = 8
NONCE_BYTES = 12
TAG_BYTES = 16
ENVELOPE_HEADER_SIZE = len(ENVELOPE_MAGIC) + 1 + SESSION_ID_BYTES + COUNTER_BYTES + NONCE_BYTES
MAX_REQUEST_BYTES = 32 * 1024 * 1024  # v2.0: raised to fit small images; capped per [limits]


class EnvelopeError(ValueError):
    """Malformed envelope header (pre-AEAD)."""


@dataclass(frozen=True, slots=True)
class Envelope:
    """Parsed envelope header + ciphertext."""

    session_id: bytes
    counter: int
    nonce: bytes
    ciphertext: bytes  # includes Poly1305 tag

    @property
    def version(self) -> int:
        return ENVELOPE_VERSION


def pack_envelope(session_id: bytes, counter: int, nonce: bytes, ciphertext: bytes) -> bytes:
    """Concatenate header + ciphertext. Inputs must already be the right length."""
    if len(session_id) != SESSION_ID_BYTES:
        raise EnvelopeError(f"session_id must be {SESSION_ID_BYTES} bytes")
    if len(nonce) != NONCE_BYTES:
        raise EnvelopeError(f"nonce must be {NONCE_BYTES} bytes")
    if counter < 0 or counter >> (COUNTER_BYTES * 8):
        raise EnvelopeError("counter out of range")
    return b"".join(
        [
            ENVELOPE_MAGIC,
            bytes([ENVELOPE_VERSION]),
            session_id,
            counter.to_bytes(COUNTER_BYTES, "big"),
            nonce,
            ciphertext,
        ]
    )


def unpack_envelope(buf: bytes) -> Envelope:
    """Parse the framed envelope. Raises :class:`EnvelopeError` on malformed input."""
    if len(buf) < ENVELOPE_HEADER_SIZE + TAG_BYTES:
        raise EnvelopeError("envelope too short")
    if not buf.startswith(ENVELOPE_MAGIC):
        raise EnvelopeError("bad magic")
    pos = len(ENVELOPE_MAGIC)
    if buf[pos] != ENVELOPE_VERSION:
        raise EnvelopeError(f"unsupported envelope version: {buf[pos]}")
    pos += 1
    session_id = buf[pos : pos + SESSION_ID_BYTES]
    pos += SESSION_ID_BYTES
    counter = int.from_bytes(buf[pos : pos + COUNTER_BYTES], "big")
    pos += COUNTER_BYTES
    nonce = buf[pos : pos + NONCE_BYTES]
    pos += NONCE_BYTES
    ciphertext = buf[pos:]
    return Envelope(session_id=session_id, counter=counter, nonce=nonce, ciphertext=ciphertext)


def build_aad(method: str, path: str, session_id: bytes, counter: int) -> bytes:
    """AEAD additional-data: binds envelope to its HTTP context."""
    return b"|".join(
        [
            ENVELOPE_MAGIC,
            bytes([ENVELOPE_VERSION]),
            session_id,
            counter.to_bytes(COUNTER_BYTES, "big"),
            method.upper().encode("ascii"),
            path.encode("utf-8"),
        ]
    )
