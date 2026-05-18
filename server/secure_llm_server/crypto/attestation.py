"""Server-side attestation backends.

v2.0 introduces the option for a server running inside a TEE (AMD
SEV-SNP, AWS Nitro Enclaves, ...) to attach a vendor-signed
attestation report to its handshake response. The report's userdata
is bound to ``SHA-256(handshake_transcript)`` so a captured report
cannot be detached and replayed against a different transcript.

This module defines the Protocol every backend implements; v2.0
ships with :class:`NoneBackend` (the default — attestation disabled)
and :class:`MockAttestationBackend` (deterministic, HMAC-signed
blob for CI / integration tests). Hardware backends
(:class:`SevSnpBackend`, :class:`NitroEnclaveBackend`) are stubbed —
they raise :class:`NotImplementedError` until the deployment
infrastructure under ``server/deploy/sev-snp/`` lands.

Threat model: the attestation report itself is **not** secret — it
is part of the handshake response. What it binds is the running
binary's measurement (a hash of the sealed image) to the transcript,
so the client can refuse sessions that don't match a pinned
measurement in ``known_hosts.toml``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Protocol

# Length of the userdata field carried by the report — SHA-256 of the
# full handshake transcript, in raw bytes.
USERDATA_LEN = 32


class AttestationBackend(Protocol):
    """Server-side attestation source."""

    def generate(self, *, transcript_digest: bytes) -> bytes | None:
        """Produce a vendor-format attestation blob whose userdata
        field is ``transcript_digest`` (a 32-byte SHA-256 over the
        full handshake transcript). Returns ``None`` if attestation
        is disabled — the handshake response then omits the field."""
        ...


@dataclass(frozen=True, slots=True)
class NoneBackend:
    """Attestation disabled. Used in dev / non-TEE deployments.

    Clients without ``attestation_required = true`` accept the
    absence of an attestation field; clients that pin a measurement
    will reject the handshake.
    """

    def generate(self, *, transcript_digest: bytes) -> None:
        if len(transcript_digest) != USERDATA_LEN:
            raise ValueError(f"transcript_digest must be {USERDATA_LEN} bytes")


@dataclass(frozen=True, slots=True)
class MockAttestationBackend:
    """Deterministic attestation blob suitable for CI.

    The blob is JSON-encoded ``{type, userdata, measurement, mac}``:

    - ``userdata``: hex(transcript_digest) — what binds the report to
      the handshake.
    - ``measurement``: the fixed string this backend was configured
      with (analogous to a sealed image hash).
    - ``mac``: HMAC-SHA256 over ``userdata || measurement`` keyed by a
      shared secret. The client verifier holds the same secret and
      recomputes the MAC; this stands in for a real vendor signature.

    Real hardware backends produce vendor-format binary blobs; we
    keep this one human-readable so test failures are easy to debug.
    """

    measurement: str
    shared_secret: bytes

    def generate(self, *, transcript_digest: bytes) -> bytes:
        if len(transcript_digest) != USERDATA_LEN:
            raise ValueError(f"transcript_digest must be {USERDATA_LEN} bytes")
        userdata_hex = transcript_digest.hex()
        mac = hmac.new(
            self.shared_secret,
            (userdata_hex + "|" + self.measurement).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return json.dumps(
            {
                "type": "mock",
                "userdata": userdata_hex,
                "measurement": self.measurement,
                "mac": mac,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SevSnpBackend:
    """AMD SEV-SNP backend — stub until hardware deploy lands.

    Production implementation will:
    1. Call ``/dev/sev-guest`` ioctl with ``transcript_digest`` as the
       user-data field of a fresh report request.
    2. Return the kernel-produced ``SnpReport`` bytes (vendor-signed
       by the AMD Secure Processor).
    """

    def generate(self, *, transcript_digest: bytes) -> bytes:  # pragma: no cover
        raise NotImplementedError(
            "SevSnpBackend requires a SEV-SNP guest; not implemented in v2.0a"
        )


@dataclass(frozen=True, slots=True)
class NitroEnclaveBackend:
    """AWS Nitro Enclave backend — stub until hardware deploy lands."""

    def generate(self, *, transcript_digest: bytes) -> bytes:  # pragma: no cover
        raise NotImplementedError(
            "NitroEnclaveBackend requires a Nitro enclave; not implemented in v2.0a"
        )


__all__ = [
    "USERDATA_LEN",
    "AttestationBackend",
    "MockAttestationBackend",
    "NitroEnclaveBackend",
    "NoneBackend",
    "SevSnpBackend",
]
