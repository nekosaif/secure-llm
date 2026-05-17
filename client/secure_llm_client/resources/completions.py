"""client.completions.*"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from secure_llm_protocol.schemas import CompletionRequest, CompletionResponse

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport


class CompletionsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def create(
        self, *, model: str, prompt: str, stream: bool = False, **sampling: Any
    ) -> CompletionResponse:
        req = CompletionRequest(model=model, prompt=prompt, stream=stream, **sampling)
        data = self._t.request("POST", "/v1/completions", payload=req.model_dump(exclude_none=True))
        return CompletionResponse.model_validate(data)
