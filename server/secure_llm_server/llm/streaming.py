"""Server-side SSE encoder for streaming chat completions.

Each chunk emitted by :class:`llama_cpp.Llama` becomes one SSE event whose
payload is a fresh application-layer envelope sealed with the session's
``s2c`` keys. The envelope's AAD continues to bind ``method + path +
session_id + counter``, so an attacker can't replay a chunk against a
different endpoint.

The wire shape is::

    HTTP/1.1 200 OK
    Content-Type: text/event-stream
    ...

    data: <base64-encoded envelope>

    data: <base64-encoded envelope>

    : keepalive   (encrypted comment, every ``keepalive_seconds``)

    data: <base64-encoded envelope of the final chunk>

    data: [DONE]

The terminator ``[DONE]`` matches the OpenAI SSE convention. It is plaintext
and carries no secret information.
"""

from __future__ import annotations

import asyncio
import base64
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Iterable
from typing import Any

import structlog
from pydantic import BaseModel

from secure_llm_protocol.schemas import ChatCompletionChunk
from secure_llm_server.crypto.envelope import seal
from secure_llm_server.session.manager import Session

_log = structlog.get_logger("secure_llm_server.llm.streaming")

_SSE_KEEPALIVE_SECONDS = 15.0
_SSE_END_MARKER = b"data: [DONE]\n\n"


def _seal_chunk(
    session: Session, payload: BaseModel | dict[str, Any], method: str, path: str
) -> bytes:
    """Seal one chunk into the session's s2c direction and frame it as an SSE event."""
    if isinstance(payload, BaseModel):
        body = payload.model_dump_json().encode("utf-8")
    else:
        import json

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    session.s2c_counter += 1
    envelope = seal(
        direction=session.s2c,
        counter=session.s2c_counter,
        session_id=session.session_id,
        method=method,
        path=path,
        plaintext=body,
    )
    return b"data: " + base64.b64encode(envelope) + b"\n\n"


def _llama_chunk_to_pydantic(
    raw: dict[str, Any], *, model: str, msg_id: str, created: int
) -> ChatCompletionChunk:
    """Normalize a llama-cpp streaming chunk to our :class:`ChatCompletionChunk`."""
    out_choices: list[dict[str, Any]] = []
    for choice in raw.get("choices") or []:
        delta = choice.get("delta") or {}
        out_choices.append(
            {
                "index": int(choice.get("index", 0)),
                "delta": {
                    "role": delta.get("role"),
                    "content": delta.get("content"),
                },
                "finish_reason": choice.get("finish_reason"),
            }
        )
    return ChatCompletionChunk.model_validate(
        {
            "id": raw.get("id", msg_id),
            "model": raw.get("model", model),
            "created": int(raw.get("created", created)),
            "choices": out_choices,
        }
    )


async def stream_chat_envelopes(
    *,
    session: Session,
    chunks: AsyncIterator[dict[str, Any]] | Iterable[dict[str, Any]],
    method: str,
    path: str,
    model: str,
    cancel_event: asyncio.Event | None = None,
    is_disconnected: Awaitable[bool] | None = None,
) -> AsyncIterator[bytes]:
    """Yield SSE-framed bytes for each chunk, plus periodic keepalives.

    Accepts either a sync or async iterator of llama-cpp chunk dicts. For sync
    iterators we offload :func:`next` via :func:`asyncio.to_thread` so the event
    loop is never blocked.
    """
    msg_id = f"chatcmpl-{secrets.token_hex(8)}"
    created = int(time.time())
    cancel_event = cancel_event or asyncio.Event()

    if hasattr(chunks, "__aiter__"):
        ait: AsyncIterator[dict[str, Any]] = chunks.__aiter__()

        async def _next_chunk() -> Any:
            return await ait.__anext__()
    else:
        sync_iter = iter(chunks)
        _SENTINEL = object()

        async def _next_chunk() -> Any:
            v = await asyncio.to_thread(next, sync_iter, _SENTINEL)
            if v is _SENTINEL:
                raise StopAsyncIteration
            return v

    last_keepalive = time.monotonic()
    while True:
        if cancel_event.is_set():
            _log.info("stream.cancelled", model=model)
            break
        try:
            # Race the next-chunk task against a keepalive timer.
            chunk_task = asyncio.create_task(_next_chunk())
            timeout = max(0.0, _SSE_KEEPALIVE_SECONDS - (time.monotonic() - last_keepalive))
            done, _pending = await asyncio.wait({chunk_task}, timeout=timeout)
            if chunk_task not in done:
                # keepalive — encrypted comment (envelope wraps an empty body)
                chunk_task.cancel()
                yield _seal_chunk(session, {"keepalive": True}, method, path)
                last_keepalive = time.monotonic()
                continue
            raw = chunk_task.result()
        except StopAsyncIteration:
            break
        except asyncio.CancelledError:
            break
        chunk = _llama_chunk_to_pydantic(raw, model=model, msg_id=msg_id, created=created)
        yield _seal_chunk(session, chunk, method, path)
        last_keepalive = time.monotonic()
        if is_disconnected is not None:
            try:
                if await is_disconnected:
                    cancel_event.set()
            except Exception:
                pass

    yield _SSE_END_MARKER
