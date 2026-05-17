"""client.embeddings.* — OpenAI-shaped embedding requests over the envelope."""

from __future__ import annotations

from typing import TYPE_CHECKING

from secure_llm_protocol.schemas import EmbeddingsRequest, EmbeddingsResponse

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport


class EmbeddingsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def create(self, *, model: str, input: str | list[str]) -> EmbeddingsResponse:
        req = EmbeddingsRequest(model=model, input=input)
        data = self._t.request("POST", "/v1/embeddings", payload=req.model_dump(exclude_none=True))
        return EmbeddingsResponse.model_validate(data)
