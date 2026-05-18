"""v2.0a: AttestationBackend (server) + AttestationVerifier (client).

Server and client live in different packages but cooperate via the
mock backend/verifier. These tests exercise the full round-trip.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import pytest

from secure_llm_client.crypto.attestation import (
    AttestationError,
    MockAttestationVerifier,
    NoneVerifier,
    transcript_digest,
)
from secure_llm_server.crypto.attestation import (
    USERDATA_LEN,
    MockAttestationBackend,
    NitroEnclaveBackend,
    NoneBackend,
    SevSnpBackend,
)


def test_none_backend_returns_none():
    backend = NoneBackend()
    assert backend.generate(transcript_digest=b"\x00" * USERDATA_LEN) is None


def test_none_backend_rejects_bad_userdata_length():
    backend = NoneBackend()
    with pytest.raises(ValueError, match="transcript_digest must be"):
        backend.generate(transcript_digest=b"\x00" * 16)


def test_mock_backend_blob_round_trips():
    secret = secrets.token_bytes(32)
    backend = MockAttestationBackend(measurement="sha384:dev-v0", shared_secret=secret)
    verifier = MockAttestationVerifier(shared_secret=secret)
    digest = hashlib.sha256(b"hello").digest()
    blob = backend.generate(transcript_digest=digest)
    verifier.verify(blob=blob, expected_userdata=digest, expected_measurement="sha384:dev-v0")


def test_mock_rejects_wrong_transcript_digest():
    secret = secrets.token_bytes(32)
    backend = MockAttestationBackend(measurement="m1", shared_secret=secret)
    verifier = MockAttestationVerifier(shared_secret=secret)
    blob = backend.generate(transcript_digest=hashlib.sha256(b"correct").digest())
    with pytest.raises(AttestationError, match="userdata"):
        verifier.verify(
            blob=blob,
            expected_userdata=hashlib.sha256(b"different").digest(),
            expected_measurement="m1",
        )


def test_mock_rejects_measurement_mismatch():
    secret = secrets.token_bytes(32)
    backend = MockAttestationBackend(measurement="m1", shared_secret=secret)
    verifier = MockAttestationVerifier(shared_secret=secret)
    digest = hashlib.sha256(b"x").digest()
    blob = backend.generate(transcript_digest=digest)
    with pytest.raises(AttestationError, match="measurement mismatch"):
        verifier.verify(blob=blob, expected_userdata=digest, expected_measurement="m2")


def test_mock_rejects_wrong_secret():
    backend = MockAttestationBackend(measurement="m1", shared_secret=secrets.token_bytes(32))
    verifier = MockAttestationVerifier(shared_secret=secrets.token_bytes(32))
    digest = hashlib.sha256(b"x").digest()
    blob = backend.generate(transcript_digest=digest)
    with pytest.raises(AttestationError, match="MAC"):
        verifier.verify(blob=blob, expected_userdata=digest, expected_measurement="m1")


def test_mock_rejects_malformed_blob():
    verifier = MockAttestationVerifier(shared_secret=secrets.token_bytes(32))
    with pytest.raises(AttestationError, match="JSON"):
        verifier.verify(
            blob=b"\xff\xff\xff",
            expected_userdata=hashlib.sha256(b"x").digest(),
            expected_measurement=None,
        )


def test_mock_rejects_wrong_type():
    verifier = MockAttestationVerifier(shared_secret=secrets.token_bytes(32))
    blob = json.dumps({"type": "real-snp", "userdata": "x"}).encode("utf-8")
    with pytest.raises(AttestationError, match="unexpected attestation type"):
        verifier.verify(
            blob=blob,
            expected_userdata=hashlib.sha256(b"x").digest(),
            expected_measurement=None,
        )


def test_none_verifier_accepts_when_no_measurement_pinned():
    NoneVerifier().verify(
        blob=b"",
        expected_userdata=b"\x00" * USERDATA_LEN,
        expected_measurement=None,
    )


def test_none_verifier_refuses_pinned_measurement():
    """If the caller pinned a measurement, the verifier must be a real
    one — the no-op verifier fails closed so misconfig doesn't
    silently bypass attestation."""
    with pytest.raises(AttestationError, match="cannot verify pinned measurement"):
        NoneVerifier().verify(
            blob=b"",
            expected_userdata=b"\x00" * USERDATA_LEN,
            expected_measurement="sha384:something",
        )


def test_transcript_digest_is_sha256_of_input():
    transcript = b"secure-llm/v1\x00client_static\x00..."
    assert transcript_digest(transcript) == hashlib.sha256(transcript).digest()


def test_sev_snp_backend_stub_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="SEV-SNP"):
        SevSnpBackend().generate(transcript_digest=b"\x00" * USERDATA_LEN)


def test_nitro_enclave_backend_stub_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="Nitro"):
        NitroEnclaveBackend().generate(transcript_digest=b"\x00" * USERDATA_LEN)


def test_mock_blob_is_valid_base64_serializable():
    """Sanity check for the wire path: the blob travels base64-encoded
    inside ``HandshakeResponse.attestation_report``."""
    backend = MockAttestationBackend(measurement="m1", shared_secret=secrets.token_bytes(32))
    blob = backend.generate(transcript_digest=hashlib.sha256(b"x").digest())
    encoded = base64.b64encode(blob).decode("ascii")
    decoded = base64.b64decode(encoded)
    assert decoded == blob
