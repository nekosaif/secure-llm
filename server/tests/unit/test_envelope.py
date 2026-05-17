"""Envelope round-trip, tamper detection, AAD binding."""

from __future__ import annotations

import secrets

import pytest

from secure_llm_server.crypto.envelope import (
    DirectionKeys,
    EnvelopeAuthError,
    open_envelope,
    seal,
)


def _keys() -> DirectionKeys:
    return DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4))


def test_roundtrip():
    keys = _keys()
    sid = secrets.token_bytes(16)
    body = b"hello world" * 100
    ct = seal(
        direction=keys, counter=1, session_id=sid, method="POST", path="/v1/x", plaintext=body
    )
    _, pt = open_envelope(
        direction=keys, expected_session_id=sid, method="POST", path="/v1/x", body=ct
    )
    assert pt == body


def test_method_swap_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    ct = seal(
        direction=keys, counter=1, session_id=sid, method="POST", path="/v1/x", plaintext=b"x"
    )
    with pytest.raises(EnvelopeAuthError):
        open_envelope(direction=keys, expected_session_id=sid, method="GET", path="/v1/x", body=ct)


def test_path_swap_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    ct = seal(
        direction=keys, counter=1, session_id=sid, method="POST", path="/v1/x", plaintext=b"x"
    )
    with pytest.raises(EnvelopeAuthError):
        open_envelope(direction=keys, expected_session_id=sid, method="POST", path="/v1/y", body=ct)


def test_tampered_ciphertext_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    ct = bytearray(
        seal(
            direction=keys,
            counter=1,
            session_id=sid,
            method="POST",
            path="/v1/x",
            plaintext=b"hello",
        )
    )
    ct[-1] ^= 0xFF
    with pytest.raises(EnvelopeAuthError):
        open_envelope(
            direction=keys, expected_session_id=sid, method="POST", path="/v1/x", body=bytes(ct)
        )


def test_wrong_session_rejected():
    keys = _keys()
    sid = secrets.token_bytes(16)
    other = secrets.token_bytes(16)
    ct = seal(
        direction=keys, counter=1, session_id=sid, method="POST", path="/v1/x", plaintext=b"x"
    )
    with pytest.raises(EnvelopeAuthError):
        open_envelope(
            direction=keys, expected_session_id=other, method="POST", path="/v1/x", body=ct
        )


def test_counter_changes_ciphertext():
    keys = _keys()
    sid = secrets.token_bytes(16)
    a = seal(
        direction=keys, counter=1, session_id=sid, method="POST", path="/v1/x", plaintext=b"hello"
    )
    b = seal(
        direction=keys, counter=2, session_id=sid, method="POST", path="/v1/x", plaintext=b"hello"
    )
    assert a != b
