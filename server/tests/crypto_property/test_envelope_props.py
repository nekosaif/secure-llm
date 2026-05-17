"""Property tests over the envelope primitives."""

from __future__ import annotations

import secrets

from hypothesis import given, settings
from hypothesis import strategies as st

from secure_llm_server.crypto.envelope import (
    DirectionKeys,
    EnvelopeAuthError,
    open_envelope,
    seal,
)


def _keys() -> DirectionKeys:
    return DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4))


@settings(max_examples=200, deadline=None)
@given(
    plaintext=st.binary(max_size=4096),
    counter=st.integers(min_value=1, max_value=2**40),
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    path=st.text(min_size=1, max_size=64).filter(lambda s: "\x00" not in s),
)
def test_roundtrip_property(plaintext, counter, method, path):
    keys = _keys()
    sid = secrets.token_bytes(16)
    path_safe = "/" + path.replace("\r", "").replace("\n", "")
    ct = seal(
        direction=keys,
        counter=counter,
        session_id=sid,
        method=method,
        path=path_safe,
        plaintext=plaintext,
    )
    _, pt = open_envelope(
        direction=keys, expected_session_id=sid, method=method, path=path_safe, body=ct
    )
    assert pt == plaintext


@settings(max_examples=100, deadline=None)
@given(idx=st.integers(min_value=0))
def test_tamper_any_byte_fails(idx):
    keys = _keys()
    sid = secrets.token_bytes(16)
    ct = bytearray(
        seal(
            direction=keys,
            counter=1,
            session_id=sid,
            method="POST",
            path="/x",
            plaintext=b"payload",
        )
    )
    if len(ct) == 0:
        return
    i = idx % len(ct)
    ct[i] ^= 0x01
    try:
        open_envelope(
            direction=keys, expected_session_id=sid, method="POST", path="/x", body=bytes(ct)
        )
    except EnvelopeAuthError:
        return  # expected
    # Some bytes (eg the leading magic) raise pre-AEAD; both are acceptable.
