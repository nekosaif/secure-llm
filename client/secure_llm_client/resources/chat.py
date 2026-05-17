"""client.chat.completions.*"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from secure_llm_protocol.schemas import ChatCompletionRequest, ChatCompletionResponse

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport


class _Conversation:
    def __init__(self, parent: ChatResource, *, model: str, system: str | None = None) -> None:
        self._parent = parent
        self._model = model
        self._messages: list[dict[str, str]] = []
        if system:
            self._messages.append({"role": "system", "content": system})

    def send(self, content: str, **kwargs: Any) -> str:
        self._messages.append({"role": "user", "content": content})
        resp = self._parent.completions.create(
            model=self._model, messages=list(self._messages), stream=False, **kwargs
        )
        reply = resp.choices[0].message.content
        self._messages.append({"role": "assistant", "content": reply})
        return reply

    def clear(self) -> None:
        self._messages = [m for m in self._messages if m["role"] == "system"]


class _Completions:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def create(
        self, *, model: str, messages: list[dict[str, str]], stream: bool = False, **sampling: Any
    ) -> ChatCompletionResponse:
        req = ChatCompletionRequest.model_validate(
            {"model": model, "messages": messages, "stream": stream, **sampling}
        )
        data = self._t.request(
            "POST", "/v1/chat/completions", payload=req.model_dump(exclude_none=True)
        )
        return ChatCompletionResponse.model_validate(data)


class ChatResource:
    def __init__(self, transport: Transport) -> None:
        self.completions = _Completions(transport)

    def conversation(self, *, model: str, system: str | None = None) -> _Conversation:
        return _Conversation(self, model=model, system=system)
