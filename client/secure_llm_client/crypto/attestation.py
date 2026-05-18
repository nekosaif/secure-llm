"""Client-side attestation verifiers.

Mirror of ``server/secure_llm_server/crypto/attestation.py``. Each
verifier accepts a vendor-format blob and checks:

1. The blob's userdata field equals ``SHA-256(full_handshake_transcript)``
   — binds the report to the handshake.
2. (Optional) The blob's measurement matches a pinned value from
   ``known_hosts.toml`` — refuses servers whose sealed image differs
   from what the operator approved.
3. The blob's vendor signature (or MAC, in the mock case) validates.

All failures raise :class:`AttestationError`. The SDK promotes that
to :class:`secure_llm_client.errors.ServerKeyMismatch` so callers can
catch a single class for any "this isn't the server I expected"
condition.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Protocol

USERDATA_LEN = 32


class AttestationError(Exception):
    """Raised when an attestation report fails to verify."""


class AttestationVerifier(Protocol):
    """Verifies an attestation report against an expected transcript
    digest and (optionally) a pinned measurement."""

    def verify(
        self,
        *,
        blob: bytes,
        expected_userdata: bytes,
        expected_measurement: str | None,
    ) -> None:
        """Raise :class:`AttestationError` on any mismatch."""
        ...


@dataclass(frozen=True, slots=True)
class NoneVerifier:
    """Accept-anything verifier.

    Used when the client has not pinned a measurement and the server
    is allowed to run without TEE attestation. The transport still
    rejects an *unexpected presence* of an attestation field if the
    verifier is :class:`NoneVerifier` and ``attestation_required`` is
    false, because absence is the contract.
    """

    def verify(
        self,
        *,
        blob: bytes,
        expected_userdata: bytes,
        expected_measurement: str | None,
    ) -> None:
        # If the caller pinned a measurement, they should be using a
        # real verifier — fail closed so a misconfig doesn't silently
        # accept anything.
        if expected_measurement is not None:
            raise AttestationError(
                "NoneVerifier cannot verify pinned measurement; "
                "configure a real attestation verifier"
            )


@dataclass(frozen=True, slots=True)
class MockAttestationVerifier:
    """Counterpart to :class:`MockAttestationBackend` on the server.

    Holds the same shared secret. Recomputes the HMAC over
    ``userdata || measurement`` and rejects any mismatch. Useful for
    CI; **never** ship this in production — the secret is shared
    plaintext, not a vendor-rooted PKI.
    """

    shared_secret: bytes

    def verify(
        self,
        *,
        blob: bytes,
        expected_userdata: bytes,
        expected_measurement: str | None,
    ) -> None:
        if len(expected_userdata) != USERDATA_LEN:
            raise AttestationError(f"expected_userdata must be {USERDATA_LEN} bytes")
        try:
            data = json.loads(blob)
        except (ValueError, json.JSONDecodeError) as e:
            raise AttestationError("blob is not valid JSON") from e
        if data.get("type") != "mock":
            raise AttestationError(f"unexpected attestation type: {data.get('type')!r}")
        if data.get("userdata") != expected_userdata.hex():
            raise AttestationError("userdata does not match transcript digest")
        if expected_measurement is not None and data.get("measurement") != expected_measurement:
            raise AttestationError(
                f"measurement mismatch: got {data.get('measurement')!r}, "
                f"expected {expected_measurement!r}"
            )
        expected_mac = hmac.new(
            self.shared_secret,
            (data["userdata"] + "|" + data["measurement"]).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_mac, data.get("mac", "")):
            raise AttestationError("MAC verification failed")


def transcript_digest(transcript_bytes: bytes) -> bytes:
    """Helper: the 32-byte SHA-256 that every attestation report
    must commit to via its userdata field."""
    return hashlib.sha256(transcript_bytes).digest()


__all__ = [
    "USERDATA_LEN",
    "AttestationError",
    "AttestationVerifier",
    "MockAttestationVerifier",
    "NoneVerifier",
    "transcript_digest",
]
