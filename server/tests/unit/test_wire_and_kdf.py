"""Wire framing edge cases + KDF helpers."""

from __future__ import annotations

import secrets

import pytest

from secure_llm_protocol.wire import (
    ENVELOPE_VERSION,
    EnvelopeError,
    build_aad,
    pack_envelope,
    unpack_envelope,
)
from secure_llm_server.crypto.kdf import (
    fingerprint,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    zeroize,
)

# --- wire --------------------------------------------------------------


def test_pack_envelope_rejects_bad_session_id_length():
    with pytest.raises(EnvelopeError, match="session_id must be"):
        pack_envelope(b"short", counter=1, nonce=b"x" * 12, ciphertext=b"")


def test_pack_envelope_rejects_bad_nonce_length():
    with pytest.raises(EnvelopeError, match="nonce must be"):
        pack_envelope(secrets.token_bytes(16), counter=1, nonce=b"short", ciphertext=b"")


def test_pack_envelope_rejects_negative_counter():
    with pytest.raises(EnvelopeError, match="counter out of range"):
        pack_envelope(
            secrets.token_bytes(16), counter=-1, nonce=secrets.token_bytes(12), ciphertext=b""
        )


def test_unpack_envelope_too_short():
    with pytest.raises(EnvelopeError, match="too short"):
        unpack_envelope(b"x")


def test_unpack_envelope_bad_magic():
    body = b"WRNG" + bytes([ENVELOPE_VERSION]) + b"\x00" * (16 + 8 + 12 + 16)
    with pytest.raises(EnvelopeError, match="bad magic"):
        unpack_envelope(body)


def test_unpack_envelope_unsupported_version():
    body = b"SLLM" + bytes([99]) + b"\x00" * (16 + 8 + 12 + 16)
    with pytest.raises(EnvelopeError, match="unsupported envelope version"):
        unpack_envelope(body)


def test_build_aad_includes_method_and_path():
    sid = secrets.token_bytes(16)
    aad_a = build_aad(method="POST", path="/x", session_id=sid, counter=1)
    aad_b = build_aad(method="GET", path="/x", session_id=sid, counter=1)
    aad_c = build_aad(method="POST", path="/y", session_id=sid, counter=1)
    aad_d = build_aad(method="POST", path="/x", session_id=sid, counter=2)
    # Every input field must change the AAD.
    assert len({aad_a, aad_b, aad_c, aad_d}) == 4


# --- kdf --------------------------------------------------------------


def test_hkdf_deterministic():
    ikm = b"a" * 32
    salt = b"salt"
    info = b"info"
    a = hkdf(ikm, salt, info, 64)
    b = hkdf(ikm, salt, info, 64)
    assert a == b
    assert len(a) == 64


def test_hkdf_different_info_different_output():
    ikm = b"a" * 32
    salt = b"salt"
    assert hkdf(ikm, salt, b"one", 32) != hkdf(ikm, salt, b"two", 32)


def test_hkdf_empty_salt_uses_hash_block():
    """Empty salt is normalised to N zero bytes — should still produce output."""
    out = hkdf(b"key-material", b"", b"info", 32)
    assert len(out) == 32


def test_hkdf_expand_rejects_overlong_request():
    prk = hkdf_extract(b"salt", b"ikm")
    with pytest.raises(ValueError, match="HKDF length"):
        hkdf_expand(prk, b"info", 32 * 256)


def test_fingerprint_format():
    fp = fingerprint(b"\x00" * 32)
    assert len(fp) == 16
    assert fp.islower()
    # deterministic
    assert fp == fingerprint(b"\x00" * 32)


def test_zeroize_overwrites_buffer():
    buf = bytearray(b"super-secret")
    zeroize(buf)
    assert all(b == 0 for b in buf)
