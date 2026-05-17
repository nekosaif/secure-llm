"""End-to-end SSE streaming test against an in-process FastAPI app.

We stub out ``ModelManager`` so no real llama model is needed; the stub
returns a :class:`StreamHandle` that yields a fixed sequence of chunks.
That covers the encrypted-SSE wire path: router framing, envelope per
chunk, base64, ``[DONE]`` terminator, client iter.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.transport import Transport
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.models.manager import _STREAM_DONE, StreamHandle
from secure_llm_server.routers.chat import router as chat_router
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager

_BG_TASKS: set[asyncio.Task[None]] = set()


class _StubModels:
    """Drop-in for ModelManager that only implements ``chat`` for streaming."""

    async def chat(
        self,
        *,
        model_id: str,
        n_ctx: int | None,
        messages: list[dict[str, str]],
        stream: bool,
        loras: tuple[tuple[str, float], ...] = (),
        tenant: str = "default",
        **sampling: Any,
    ) -> Any:
        if not stream:
            return {
                "id": "chatcmpl-stub",
                "choices": [
                    {"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        handle = StreamHandle()

        async def _drain() -> None:
            for piece in ["hello ", "secure ", "llm"]:
                if handle.cancel_event.is_set():
                    break
                await handle._queue.put(
                    {
                        "id": "chatcmpl-stub",
                        "model": model_id,
                        "created": 0,
                        "choices": [
                            {"index": 0, "delta": {"content": piece}, "finish_reason": None}
                        ],
                    }
                )
            await handle._queue.put(_STREAM_DONE)

        # Strong ref so the task isn't GC'd mid-drain.
        task = asyncio.create_task(_drain())
        _BG_TASKS.add(task)
        task.add_done_callback(_BG_TASKS.discard)
        return handle


def _build_app(tmp_path: Path) -> tuple[FastAPI, Keystore, SessionManager, ClientIdentity]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)
    client_id = ClientIdentity.generate_and_save(tmp_path / "client")
    keystore = Keystore(
        server=server_id,
        allowlist={
            client_id.x25519_pk: AuthorizedClient(
                name="t",
                x25519_pk=client_id.x25519_pk,
                ed25519_pk=client_id.ed25519_pk,
                scopes=("chat",),
            )
        },
    )
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)

    app = FastAPI()
    app.state.keystore = keystore
    app.state.session_manager = sm
    app.state.models = _StubModels()
    app.state.settings = type(
        "S",
        (),
        {
            "crypto": type(
                "C",
                (),
                {
                    "handshake_skew_seconds": 30,
                    "session_ttl_seconds": 3600,
                },
            )()
        },
    )()
    app.include_router(session_router)
    app.include_router(chat_router)
    return app, keystore, sm, client_id


def test_chat_stream_roundtrip(tmp_path: Path):
    app, keystore, _sm, _id = _build_app(tmp_path)
    base = "http://testserver"
    http = TestClient(app, base_url=base)
    identity = ClientIdentity.load(tmp_path / "client")
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = http  # type: ignore[attr-defined]

    from secure_llm_protocol.schemas import ChatCompletionChunk

    chunks: list[ChatCompletionChunk] = []
    for raw in t.stream_request(
        "POST",
        "/v1/chat/completions",
        payload={
            "model": "stub",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
            "max_tokens": 32,
        },
    ):
        if "keepalive" in raw:
            continue
        chunks.append(ChatCompletionChunk.model_validate(raw))

    text = "".join((c.choices[0].delta.content or "") for c in chunks if c.choices)
    assert text == "hello secure llm"
