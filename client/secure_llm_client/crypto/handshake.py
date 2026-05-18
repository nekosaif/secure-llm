"""Client-side handshake: builds the request, derives session keys from the response."""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass
from pathlib import Path

from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey

from secure_llm_client.crypto.attestation import (
    AttestationError,
    AttestationVerifier,
    transcript_digest,
)
from secure_llm_client.crypto.envelope import DirectionKeys
from secure_llm_client.crypto.kdf import hkdf
from secure_llm_protocol.schemas import HandshakeRequest, HandshakeResponse
from secure_llm_protocol.version import PROTOCOL_LABEL


@dataclass(frozen=True, slots=True)
class ClientIdentity:
    x25519_sk: PrivateKey
    x25519_pk: bytes
    ed25519_sk: SigningKey
    ed25519_pk: bytes

    @classmethod
    def load(cls, base: Path) -> ClientIdentity:
        x_sk = PrivateKey((base.with_suffix(".x25519.key")).read_bytes())
        e_sk = SigningKey((base.with_suffix(".ed25519.key")).read_bytes())
        return cls(
            x25519_sk=x_sk,
            x25519_pk=bytes(x_sk.public_key),
            ed25519_sk=e_sk,
            ed25519_pk=bytes(e_sk.verify_key),
        )

    @classmethod
    def generate_and_save(cls, base: Path) -> ClientIdentity:
        base.parent.mkdir(parents=True, exist_ok=True)
        x_sk = PrivateKey.generate()
        e_sk = SigningKey.generate()
        x_path = base.with_suffix(".x25519.key")
        e_path = base.with_suffix(".ed25519.key")
        for p, data in [
            (x_path, bytes(x_sk)),
            (e_path, bytes(e_sk)),
            (base.with_suffix(".x25519.key.pub"), bytes(x_sk.public_key)),
            (base.with_suffix(".ed25519.key.pub"), bytes(e_sk.verify_key)),
        ]:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        return cls(
            x25519_sk=x_sk,
            x25519_pk=bytes(x_sk.public_key),
            ed25519_sk=e_sk,
            ed25519_pk=bytes(e_sk.verify_key),
        )


@dataclass(frozen=True, slots=True)
class HandshakeOutcome:
    session_id: bytes
    c2s: DirectionKeys
    s2c: DirectionKeys
    ttl_seconds: int
    server_static_pk: bytes


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _transcript(
    *, client_static_pk: bytes, client_eph_pk: bytes, server_host: bytes, timestamp: int
) -> bytes:
    return b"\x00".join(
        [
            PROTOCOL_LABEL.encode("ascii"),
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


def build_handshake_request(
    *,
    identity: ClientIdentity,
    server_host: str,
    client_eph_pk: bytes,
    now: int | None = None,
) -> HandshakeRequest:
    ts = int(time.time()) if now is None else now
    transcript = _transcript(
        client_static_pk=identity.x25519_pk,
        client_eph_pk=client_eph_pk,
        server_host=server_host.encode("utf-8"),
        timestamp=ts,
    )
    sig = identity.ed25519_sk.sign(transcript).signature
    return HandshakeRequest(
        protocol=PROTOCOL_LABEL.split("/")[-1],
        client_static_pk=_b64e(identity.x25519_pk),
        client_ephemeral_pk=_b64e(client_eph_pk),
        timestamp=ts,
        transcript_sig=_b64e(sig),
        server_host=server_host,
    )


def derive_session(
    *,
    identity: ClientIdentity,
    client_eph_sk: PrivateKey,
    server_host: str,
    handshake_request_ts: int,
    response: HandshakeResponse,
    pinned_server_static_pk: bytes,
    attestation_verifier: AttestationVerifier | None = None,
    pinned_measurement: str | None = None,
    attestation_required: bool = False,
) -> HandshakeOutcome:
    server_static = _b64d(response.server_static_pk)
    server_ed25519 = _b64d(response.server_ed25519_pk)
    server_eph = _b64d(response.server_ephemeral_pk)
    session_id = _b64d(response.session_id)
    sig = _b64d(response.server_sig)

    if server_static != pinned_server_static_pk:
        from secure_llm_client.errors import ServerKeyMismatch

        raise ServerKeyMismatch(
            f"server key mismatch: expected {pinned_server_static_pk.hex()[:16]} "
            f"got {server_static.hex()[:16]}"
        )

    base_transcript = _transcript(
        client_static_pk=identity.x25519_pk,
        client_eph_pk=bytes(client_eph_sk.public_key),
        server_host=server_host.encode("utf-8"),
        timestamp=handshake_request_ts,
    )
    full_transcript = b"\x00".join(
        [
            base_transcript,
            b"server_eph",
            server_eph,
            b"server_static",
            server_static,
            b"session",
            session_id,
        ]
    )
    try:
        VerifyKey(server_ed25519).verify(full_transcript, sig)
    except Exception as e:
        from secure_llm_client.errors import HandshakeFailed

        raise HandshakeFailed("server signature invalid") from e

    # v2.0: optional TEE attestation check. The attestation report (if
    # present) commits to SHA-256(full_transcript) via its userdata
    # field. If the operator pinned a measurement in known_hosts.toml,
    # we require it match what the report claims.
    if response.attestation_report is not None:
        if attestation_verifier is None:
            # The server attached a report but the client has no
            # verifier — fail closed; misconfigured clients shouldn't
            # silently accept attested servers.
            from secure_llm_client.errors import ServerKeyMismatch

            raise ServerKeyMismatch(
                "server attached an attestation report but no verifier is configured client-side"
            )
        blob = _b64d(response.attestation_report)
        try:
            attestation_verifier.verify(
                blob=blob,
                expected_userdata=transcript_digest(full_transcript),
                expected_measurement=pinned_measurement,
            )
        except AttestationError as e:
            from secure_llm_client.errors import ServerKeyMismatch

            raise ServerKeyMismatch(f"attestation failed: {e}") from e
    elif attestation_required:
        from secure_llm_client.errors import ServerKeyMismatch

        raise ServerKeyMismatch(
            "attestation_required=True but server returned no attestation report"
        )

    dh1 = crypto_scalarmult(bytes(client_eph_sk), server_eph)
    dh2 = crypto_scalarmult(bytes(identity.x25519_sk), server_static)
    ikm = dh1 + dh2
    keystream = hkdf(
        ikm=ikm,
        salt=full_transcript,
        info=b"secure-llm session keys v1",
        length=32 + 32 + 4 + 4,
    )
    c2s = DirectionKeys(key=keystream[0:32], nonce_prefix=keystream[64:68])
    s2c = DirectionKeys(key=keystream[32:64], nonce_prefix=keystream[68:72])

    # Sanity-check the nonce prefixes the server announced.
    if c2s.nonce_prefix.hex() != response.nonce_prefix_c2s:
        from secure_llm_client.errors import HandshakeFailed

        raise HandshakeFailed("nonce_prefix_c2s mismatch")
    if s2c.nonce_prefix.hex() != response.nonce_prefix_s2c:
        from secure_llm_client.errors import HandshakeFailed

        raise HandshakeFailed("nonce_prefix_s2c mismatch")

    del dh1, dh2, ikm, keystream
    return HandshakeOutcome(
        session_id=session_id,
        c2s=c2s,
        s2c=s2c,
        ttl_seconds=response.ttl_seconds,
        server_static_pk=server_static,
    )
