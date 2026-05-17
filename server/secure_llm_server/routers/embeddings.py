"""POST /v1/embeddings — OpenAI-compatible embeddings under the same envelope."""

from __future__ import annotations

import secrets
import time

from fastapi import APIRouter, Request, Response

from secure_llm_protocol.schemas import (
    EmbeddingsRequest,
    EmbeddingsResponse,
    ErrorEnvelope,
)
from secure_llm_server.metrics import inference_tokens_total
from secure_llm_server.models.manager import ManagerError
from secure_llm_server.routers._envelope_dep import (
    decrypt_request,
    encrypt_response,
)

router = APIRouter(prefix="/v1")


@router.post("/embeddings")
async def embeddings(request: Request) -> Response:
    state = request.app.state
    session, req = await decrypt_request(request, state.session_manager, EmbeddingsRequest)
    inputs: list[str] = [req.input] if isinstance(req.input, str) else list(req.input)
    try:
        result = await state.models.embed(model_id=req.model, inputs=inputs, tenant=session.tenant)
    except ManagerError as e:
        err = ErrorEnvelope(code=e.code, message=str(e))
        body = encrypt_response(session, err, method=request.method, path=request.url.path)
        return Response(status_code=400, content=body, media_type="application/octet-stream")

    # llama-cpp's create_embedding returns {data: [{embedding: [...], index: int}], usage}.
    data_in = result.get("data", []) if isinstance(result, dict) else []
    usage_in = result.get("usage", {}) if isinstance(result, dict) else {}
    inference_tokens_total.labels(req.model, "prompt").inc(usage_in.get("prompt_tokens", 0))

    payload = EmbeddingsResponse.model_validate(
        {
            "id": f"embd-{secrets.token_hex(8)}",
            "model": req.model,
            "created": int(time.time()),
            "data": [
                {"index": int(item.get("index", i)), "embedding": list(item.get("embedding", []))}
                for i, item in enumerate(data_in)
            ],
            "usage": {
                "prompt_tokens": int(usage_in.get("prompt_tokens", 0)),
                "total_tokens": int(usage_in.get("total_tokens", usage_in.get("prompt_tokens", 0))),
            },
        }
    )
    body = encrypt_response(session, payload, method=request.method, path=request.url.path)
    return Response(content=body, media_type="application/octet-stream")
