"""v2.0a: handshake with attestation backend end-to-end through the SDK.

Drives a real handshake through ``fastapi.testclient.TestClient`` with
a Mock attestation backend on the server and a matching verifier on
the client. Validates the transcript-binding guarantee — swapping the
backend's measurement or the shared secret must cause the client's
``derive_session`` to refuse.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secure_llm_client.crypto.attestation import MockAttestationVerifier
from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import ServerKeyMismatch
from secure_llm_client.transport import Transport
from secure_llm_server.crypto.attestation import MockAttestationBackend, NoneBackend

from ._helpers import build_app


def _make_transport(app, keystore, tmp_path: Path, **kwargs) -> Transport:
    identity = ClientIdentity.load(tmp_path / "client")
    base = "http://testserver"
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
        **kwargs,
    )
    t._client = TestClient(app, base_url=base)  # type: ignore[attr-defined]
    return t


def test_handshake_with_mock_attestation_succeeds(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    secret = secrets.token_bytes(32)
    app.state.attestation = MockAttestationBackend(
        measurement="sha384:test-image-v1", shared_secret=secret
    )
    t = _make_transport(
        app,
        keystore,
        tmp_path,
        attestation_verifier=MockAttestationVerifier(shared_secret=secret),
        pinned_measurement="sha384:test-image-v1",
        attestation_required=True,
    )
    # Trigger the handshake by accessing the session.
    state = t._session_state()  # type: ignore[attr-defined]
    assert state.outcome.session_id


def test_handshake_rejects_wrong_measurement(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    secret = secrets.token_bytes(32)
    app.state.attestation = MockAttestationBackend(
        measurement="sha384:attacker-image", shared_secret=secret
    )
    t = _make_transport(
        app,
        keystore,
        tmp_path,
        attestation_verifier=MockAttestationVerifier(shared_secret=secret),
        pinned_measurement="sha384:approved-image",
        attestation_required=True,
    )
    with pytest.raises(ServerKeyMismatch, match="measurement"):
        t._session_state()  # type: ignore[attr-defined]


def test_handshake_rejects_when_required_but_server_omits_report(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    app.state.attestation = NoneBackend()  # server has attestation disabled
    t = _make_transport(
        app,
        keystore,
        tmp_path,
        attestation_required=True,
    )
    with pytest.raises(ServerKeyMismatch, match="no attestation report"):
        t._session_state()  # type: ignore[attr-defined]


def test_handshake_without_attestation_still_works(tmp_path: Path):
    """v1.x clients (no verifier configured) talk to a v2.0 server
    that has attestation disabled — the field is optional."""
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    # Default: app.state.attestation is None (see build_app).
    t = _make_transport(app, keystore, tmp_path)
    state = t._session_state()  # type: ignore[attr-defined]
    assert state.outcome.session_id


def test_handshake_rejects_attested_server_without_verifier(tmp_path: Path):
    """If the server returns a report but the client has no verifier,
    fail closed — silently accepting would defeat attestation."""
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    app.state.attestation = MockAttestationBackend(
        measurement="m1", shared_secret=secrets.token_bytes(32)
    )
    t = _make_transport(app, keystore, tmp_path)  # no verifier configured
    with pytest.raises(ServerKeyMismatch, match="no verifier"):
        t._session_state()  # type: ignore[attr-defined]
