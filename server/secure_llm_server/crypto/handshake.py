"""Static+ephemeral X25519 handshake with Ed25519-signed transcript.

This is close to Noise IK: client's static key is known to the server up-front
(allowlist), server's static key is pinned client-side. The resulting session
key gives mutual authentication, forward secrecy for ephemeral compromise, and
KCI resistance.

Transcript :code:`T` (bytes, NUL-separated) is the same on both sides; both
parties sign / verify the *same* T so swapping any field breaks the signature.

Output: a :class:`SessionMaterial` with two :class:`DirectionKeys` (c2s, s2c)
plus a 16-byte session_id and the ttl.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey
from nacl.signing import VerifyKey

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import HandshakeRequest, HandshakeResponse
from secure_llm_protocol.version import PROTOCOL_LABEL
from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.kdf import hkdf

if TYPE_CHECKING:
    from secure_llm_server.crypto.keystore import AuthorizedClient, ServerIdentity


SESSION_ID_BYTES = 16


class HandshakeError(Exception):
    def __init__(self, code: ErrorCode, message: str = "") -> None:
        super().__init__(message or code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class SessionMaterial:
    session_id: bytes
    c2s: DirectionKeys
    s2c: DirectionKeys
    ttl_seconds: int
    client_fingerprint: str
    scopes: tuple[str, ...]


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _transcript(
    *,
    protocol_label: bytes,
    client_static_pk: bytes,
    client_eph_pk: bytes,
    server_host: bytes,
    timestamp: int,
) -> bytes:
    return b"\x00".join(
        [
            protocol_label,
            b"client_static",
            client_static_pk,
            b"client_eph",
            client_eph_pk,
            b"host",
            server_host,
            b"ts",
            str(timestamp).encode("ascii"),
        ]
    )


def _server_transcript(
    base: bytes, server_eph_pk: bytes, server_static_pk: bytes, session_id: bytes
) -> bytes:
    return b"\x00".join(
        [
            base,
            b"server_eph",
            server_eph_pk,
            b"server_static",
            server_static_pk,
            b"session",
            session_id,
        ]
    )


def perform_handshake(
    *,
    req: HandshakeRequest,
    server_identity: ServerIdentity,
    allowlist: dict[bytes, AuthorizedClient],
    skew_seconds: int,
    ttl_seconds: int,
    expected_host: str | None = None,
    now: int | None = None,
) -> tuple[HandshakeResponse, SessionMaterial]:
    """Validate the client's handshake and derive session material.

    All failures raise :class:`HandshakeError` with a code from
    :class:`ErrorCode`. Callers should map the code to an HTTP response and an
    audit log entry but must not vary the response shape or latency.
    """
    if req.protocol != PROTOCOL_LABEL.split("/")[-1] and req.protocol != PROTOCOL_LABEL:
        raise HandshakeError(ErrorCode.HANDSHAKE_VERSION_MISMATCH)

    now = int(time.time()) if now is None else now
    if abs(now - req.timestamp) > skew_seconds:
        raise HandshakeError(ErrorCode.CLOCK_SKEW)

    try:
        client_static_pk = _b64d(req.client_static_pk)
        client_eph_pk = _b64d(req.client_ephemeral_pk)
        sig = _b64d(req.transcript_sig)
    except Exception as e:
        raise HandshakeError(ErrorCode.BAD_REQUEST, "invalid base64") from e
    if len(client_static_pk) != 32 or len(client_eph_pk) != 32:
        raise HandshakeError(ErrorCode.BAD_REQUEST, "bad pk length")

    entry = allowlist.get(client_static_pk)
    if entry is None:
        raise HandshakeError(ErrorCode.UNKNOWN_CLIENT)
    if entry.revoked:
        raise HandshakeError(ErrorCode.CLIENT_REVOKED)
    if entry.not_before is not None and now < entry.not_before:
        raise HandshakeError(ErrorCode.CLIENT_NOT_YET_VALID)
    if entry.not_after is not None and now > entry.not_after:
        raise HandshakeError(ErrorCode.CLIENT_EXPIRED)

    host = (req.server_host or expected_host or "").strip()
    transcript = _transcript(
        protocol_label=PROTOCOL_LABEL.encode("ascii"),
        client_static_pk=client_static_pk,
        client_eph_pk=client_eph_pk,
        server_host=host.encode("utf-8"),
        timestamp=req.timestamp,
    )

    try:
        VerifyKey(entry.ed25519_pk).verify(transcript, sig)
    except Exception as e:
        raise HandshakeError(ErrorCode.BAD_SIGNATURE) from e

    # Generate server ephemeral; derive two DH shares (eph+static).
    server_eph_sk = PrivateKey.generate()
    server_eph_pk = bytes(server_eph_sk.public_key)
    dh1 = crypto_scalarmult(bytes(server_eph_sk), client_eph_pk)
    dh2 = crypto_scalarmult(bytes(server_identity.x25519_sk), client_static_pk)
    ikm = dh1 + dh2

    session_id = secrets.token_bytes(SESSION_ID_BYTES)
    full_transcript = _server_transcript(
        transcript, server_eph_pk, server_identity.x25519_pk, session_id
    )

    # Derive 32B + 32B keys plus two 4B nonce prefixes via HKDF.
    keystream = hkdf(
        ikm=ikm,
        salt=full_transcript,
        info=b"secure-llm session keys v1",
        length=32 + 32 + 4 + 4,
    )
    c2s = DirectionKeys(key=keystream[0:32], nonce_prefix=keystream[64:68])
    s2c = DirectionKeys(key=keystream[32:64], nonce_prefix=keystream[68:72])

    sig_out = server_identity.ed25519_sk.sign(full_transcript).signature

    response = HandshakeResponse(
        session_id=_b64e(session_id),
        server_static_pk=_b64e(server_identity.x25519_pk),
        server_ed25519_pk=_b64e(server_identity.ed25519_pk),
        server_ephemeral_pk=_b64e(server_eph_pk),
        ttl_seconds=ttl_seconds,
        server_sig=_b64e(sig_out),
        nonce_prefix_c2s=c2s.nonce_prefix.hex(),
        nonce_prefix_s2c=s2c.nonce_prefix.hex(),
    )
    material = SessionMaterial(
        session_id=session_id,
        c2s=c2s,
        s2c=s2c,
        ttl_seconds=ttl_seconds,
        client_fingerprint=entry.fingerprint,
        scopes=tuple(entry.scopes),
    )
    # Drop references to ephemeral DH outputs; Python can't truly wipe these.
    del dh1, dh2, ikm, keystream, server_eph_sk
    return response, material


__all__ = [
    "HandshakeError",
    "SessionMaterial",
    "perform_handshake",
]
