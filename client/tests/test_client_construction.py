"""SecureLLMClient construction error paths + identity load."""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_llm_client import SecureLLMClient, ServerKeyMismatch
from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import (
    AdminRequiredError,
    DownloadFailed,
    HandshakeFailed,
    ModelNotFound,
    QueueFull,
    RateLimited,
    SecureLLMError,
    from_error_envelope,
)
from secure_llm_protocol.errors import ErrorCode


def test_no_pinned_key_and_no_known_hosts_raises(tmp_path: Path):
    ClientIdentity.generate_and_save(tmp_path / "client")
    with pytest.raises(ServerKeyMismatch):
        SecureLLMClient(
            base_url="https://host:8443",
            client_key_path=str(tmp_path / "client"),
            # neither server_pubkey nor known_hosts_path
        )


def test_host_not_in_known_hosts_raises(tmp_path: Path):
    ClientIdentity.generate_and_save(tmp_path / "client")
    known = tmp_path / "known.toml"
    known.write_text("hosts = []\n", encoding="utf-8")
    with pytest.raises(ServerKeyMismatch):
        SecureLLMClient(
            base_url="https://nope:1",
            client_key_path=str(tmp_path / "client"),
            known_hosts_path=str(known),
        )


def test_from_error_envelope_dispatch():
    """Each ErrorCode → SDK exception class mapping is exercised."""
    cases = [
        (ErrorCode.UNKNOWN_CLIENT, HandshakeFailed),
        (ErrorCode.CLIENT_REVOKED, HandshakeFailed),
        (ErrorCode.SERVER_KEY_MISMATCH, ServerKeyMismatch),
        (ErrorCode.ADMIN_REQUIRED, AdminRequiredError),
        (ErrorCode.QUEUE_FULL, QueueFull),
        (ErrorCode.MODEL_NOT_FOUND, ModelNotFound),
        (ErrorCode.DOWNLOAD_FAILED, DownloadFailed),
        (ErrorCode.RATE_LIMITED, RateLimited),
        # an unmapped code falls back to the base
        (ErrorCode.INTERNAL_ERROR, SecureLLMError),
    ]
    for code, cls in cases:
        err = from_error_envelope(code, "msg", "err-id-1")
        assert isinstance(err, cls)
        if isinstance(err, RateLimited):
            # RateLimited carries an optional retry_after
            assert err.retry_after is None


def test_from_error_envelope_rate_limited_with_retry_after():
    err = from_error_envelope(ErrorCode.RATE_LIMITED, "slow", "id", retry_after=2.5)
    assert isinstance(err, RateLimited)
    assert err.retry_after == 2.5
    assert err.error_id == "id"


def test_identity_load_roundtrip(tmp_path: Path):
    saved = ClientIdentity.generate_and_save(tmp_path / "ident")
    loaded = ClientIdentity.load(tmp_path / "ident")
    assert saved.x25519_pk == loaded.x25519_pk
    assert saved.ed25519_pk == loaded.ed25519_pk
