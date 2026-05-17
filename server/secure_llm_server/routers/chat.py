"""POST /v1/chat/completions (encrypted; non-streaming + SSE streaming)."""

from __future__ import annotations

import secrets
import time
from typing import Any

import structlog
from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from secure_llm_protocol.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ErrorEnvelope,
)
from secure_llm_server.llm.streaming import stream_chat_envelopes
from secure_llm_server.metrics import inference_tokens_total
from secure_llm_server.models.manager import ManagerError, StreamHandle
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)

router = APIRouter(prefix="/v1")
_log = structlog.get_logger("secure_llm_server.routers.chat")


def _sampling(req: ChatCompletionRequest) -> dict[str, Any]:
    s: dict[str, Any] = {
        "temperature": req.temperature,
        "top_p": req.top_p,
        "top_k": req.top_k,
        "repeat_penalty": req.repeat_penalty,
        "presence_penalty": req.presence_penalty,
        "frequency_penalty": req.frequency_penalty,
        "max_tokens": req.max_tokens,
    }
    if req.stop:
        s["stop"] = req.stop
    if req.seed is not None:
        s["seed"] = req.seed
    return s


@router.post("/chat/completions")
async def chat_completions(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, ChatCompletionRequest)
    lora_spec = tuple((lr.id, lr.scale) for lr in req.loras)
    try:
        result = await state.models.chat(
            model_id=req.model,
            n_ctx=req.n_ctx,
            messages=[m.model_dump() for m in req.messages],
            stream=req.stream,
            loras=lora_spec,
            tenant=session.tenant,
            **_sampling(req),
        )
    except ManagerError as e:
        err = ErrorEnvelope(code=e.code, message=str(e))
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=400, content=body, media_type="application/octet-stream")

    if req.stream:
        # `result` is a StreamHandle (async iterator) drained by the
        # ModelManager's worker. Each chunk gets sealed into its own envelope
        # sharing the session's s2c counter.
        assert isinstance(result, StreamHandle)
        handle: StreamHandle = result
        method, path = request.method, request.url.path

        async def _iter() -> Any:
            try:
                async for sse_bytes in stream_chat_envelopes(
                    session=session,
                    chunks=handle,
                    method=method,
                    path=path,
                    model=req.model,
                    cancel_event=handle.cancel_event,
                    is_disconnected=None,
                ):
                    if await request.is_disconnected():
                        handle.cancel()
                    yield sse_bytes
            finally:
                handle.cancel()

        return StreamingResponse(
            _iter(),
            media_type="text/event-stream",
            headers={"cache-control": "no-store", "x-accel-buffering": "no"},
        )

    # llama.cpp returns an OpenAI-shaped dict already.
    choice = result["choices"][0]
    usage = result.get("usage", {})
    inference_tokens_total.labels(req.model, "prompt").inc(usage.get("prompt_tokens", 0))
    inference_tokens_total.labels(req.model, "completion").inc(usage.get("completion_tokens", 0))
    payload = ChatCompletionResponse.model_validate(
        {
            "id": result.get("id", f"chatcmpl-{secrets.token_hex(8)}"),
            "model": req.model,
            "created": int(result.get("created", time.time())),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": choice["message"].get("role", "assistant"),
                        "content": choice["message"].get("content", ""),
                    },
                    "finish_reason": choice.get("finish_reason") or "stop",
                }
            ],
            "usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
        }
    )
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
