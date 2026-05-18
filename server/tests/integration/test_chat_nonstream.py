"""Chat completions non-streaming branch + ManagerError surface."""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

import pytest

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import ChatCompletionResponse
from secure_llm_server.models.manager import ManagerError
from secure_llm_server.routers.chat import router as chat_router

from ._helpers import build_app, make_transport


class _StubModels:
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
        return {
            "id": f"chatcmpl-{secrets.token_hex(4)}",
            "model": model_id,
            "created": int(time.time()),
            "choices": [
                {
                    "message": {"role": "assistant", "content": "pong"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }


class _ErrModels:
    async def chat(self, **kwargs: Any) -> Any:
        raise ManagerError(ErrorCode.QUEUE_FULL, "queue full")


def test_chat_completion_nonstream(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[chat_router])
    app.state.models = _StubModels()
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request(
        "POST",
        "/v1/chat/completions",
        payload={
            "model": "stub",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 8,
        },
    )
    resp = ChatCompletionResponse.model_validate(data)
    assert resp.choices[0].message.content == "pong"
    assert resp.usage.total_tokens == 2


def test_chat_manager_error_surfaces(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[chat_router])
    app.state.models = _ErrModels()
    t = make_transport(app, keystore, tmp_path / "client")
    from secure_llm_client.errors import QueueFull

    with pytest.raises(QueueFull):
        t.request(
            "POST",
            "/v1/chat/completions",
            payload={
                "model": "stub",
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1,
            },
        )
