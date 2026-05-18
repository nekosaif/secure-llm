"""Client-side envelope mirrors the server's; same error-path discipline."""

from __future__ import annotations

import secrets

import pytest

from secure_llm_client.crypto.envelope import (
    DirectionKeys,
    EnvelopeAuthError,
    nonce_for,
    open_envelope,
    seal,
)


def _keys() -> DirectionKeys:
    return DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4))


def test_directionkeys_rejects_bad_key_length():
    with pytest.raises(ValueError, match="key must be 32 bytes"):
        DirectionKeys(key=b"short", nonce_prefix=secrets.token_bytes(4))


def test_directionkeys_rejects_bad_prefix_length():
    with pytest.raises(ValueError, match="nonce_prefix must be 4 bytes"):
        DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=b"x")


def test_nonce_for_rejects_negative_counter():
    keys = _keys()
    with pytest.raises(ValueError, match="counter out of range"):
        nonce_for(keys, -1)


def test_open_envelope_session_mismatch_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    other = secrets.token_bytes(16)
    body = seal(direction=keys, counter=1, session_id=sid, method="POST", path="/x", plaintext=b"y")
    with pytest.raises(EnvelopeAuthError, match="session_id mismatch"):
        open_envelope(
            direction=keys,
            expected_session_id=other,
            method="POST",
            path="/x",
            body=body,
        )


def test_open_envelope_aead_failure_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    body = bytearray(
        seal(
            direction=keys,
            counter=1,
            session_id=sid,
            method="POST",
            path="/x",
            plaintext=b"hello",
        )
    )
    body[-1] ^= 0xFF
    with pytest.raises(EnvelopeAuthError, match="decrypt failed"):
        open_envelope(
            direction=keys,
            expected_session_id=sid,
            method="POST",
            path="/x",
            body=bytes(body),
        )


def test_open_envelope_unpack_failure_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    with pytest.raises(EnvelopeAuthError):
        open_envelope(
            direction=keys,
            expected_session_id=sid,
            method="POST",
            path="/x",
            body=b"truncated",
        )


def test_roundtrip_method_swap_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    body = seal(direction=keys, counter=1, session_id=sid, method="POST", path="/x", plaintext=b"z")
    with pytest.raises(EnvelopeAuthError):
        open_envelope(
            direction=keys,
            expected_session_id=sid,
            method="GET",
            path="/x",
            body=body,
        )
