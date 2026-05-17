"""Unit tests for the SSE streaming envelope encoder."""

from __future__ import annotations

import asyncio
import base64
import secrets
from typing import Any

import pytest

from secure_llm_server.crypto.envelope import DirectionKeys, open_envelope
from secure_llm_server.crypto.replay import ReplayWindow
from secure_llm_server.llm.streaming import _SSE_END_MARKER, stream_chat_envelopes
from secure_llm_server.session.manager import Session


def _make_session() -> Session:
    return Session(
        session_id=secrets.token_bytes(16),
        c2s=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        s2c=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        created_at=0.0,
        last_used_at=0.0,
        ttl_seconds=3600,
        max_lifetime_seconds=86400,
        client_fingerprint="test",
        scopes=frozenset({"chat"}),
        replay=ReplayWindow(),
        s2c_counter=0,
    )


async def _collect(it):
    out = []
    async for v in it:
        out.append(v)
    return out


def _fake_chunks(n: int) -> list[dict[str, Any]]:
    return [
        {
            "id": "x",
            "model": "m",
            "created": 0,
            "choices": [{"index": 0, "delta": {"content": f"t{i}"}, "finish_reason": None}],
        }
        for i in range(n)
    ]


def test_stream_roundtrip(anyio_backend=None):
    session = _make_session()
    chunks = _fake_chunks(5)

    async def run() -> list[bytes]:
        gen = stream_chat_envelopes(
            session=session,
            chunks=chunks,
            method="POST",
            path="/v1/chat/completions",
            model="m",
        )
        return await _collect(gen)

    frames = asyncio.run(run())
    assert frames[-1] == _SSE_END_MARKER

    # Walk every data frame; envelope round-trips and counters are monotonic.
    recovered: list[str] = []
    last_counter = -1
    for f in frames[:-1]:
        assert f.startswith(b"data: ")
        env_bytes = base64.b64decode(f[len(b"data: ") :].rstrip(b"\n"))
        env, plaintext = open_envelope(
            direction=session.s2c,
            expected_session_id=session.session_id,
            method="POST",
            path="/v1/chat/completions",
            body=env_bytes,
        )
        assert env.counter > last_counter
        last_counter = env.counter
        import json

        msg = json.loads(plaintext)
        recovered.append(msg["choices"][0]["delta"]["content"])
    assert recovered == ["t0", "t1", "t2", "t3", "t4"]


def test_stream_wrong_path_fails():
    """A chunk sealed for /v1/chat/completions must not decrypt at /v1/system."""
    session = _make_session()

    async def run() -> bytes:
        gen = stream_chat_envelopes(
            session=session,
            chunks=_fake_chunks(1),
            method="POST",
            path="/v1/chat/completions",
            model="m",
        )
        async for f in gen:
            if f != _SSE_END_MARKER:
                return f
        raise AssertionError("no frame produced")

    frame = asyncio.run(run())
    env_bytes = base64.b64decode(frame[len(b"data: ") :].rstrip(b"\n"))
    from secure_llm_server.crypto.envelope import EnvelopeAuthError

    with pytest.raises(EnvelopeAuthError):
        open_envelope(
            direction=session.s2c,
            expected_session_id=session.session_id,
            method="POST",
            path="/v1/system",  # wrong path
            body=env_bytes,
        )


def test_stream_cancel_stops_early():
    """If cancel_event is set, no further chunks are emitted (only the terminator)."""
    session = _make_session()
    cancel = asyncio.Event()
    cancel.set()  # pre-cancelled

    async def run() -> list[bytes]:
        gen = stream_chat_envelopes(
            session=session,
            chunks=_fake_chunks(10),
            method="POST",
            path="/v1/chat/completions",
            model="m",
            cancel_event=cancel,
        )
        return await _collect(gen)

    frames = asyncio.run(run())
    # Only the [DONE] terminator should come out.
    assert frames == [_SSE_END_MARKER]
