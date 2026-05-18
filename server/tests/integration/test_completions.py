"""POST /v1/completions round-trip + stream=true is rejected."""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

import pytest

from secure_llm_client.errors import SecureLLMError
from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import CompletionResponse
from secure_llm_server.routers.completions import router as completions_router

from ._helpers import build_app, make_transport


class _StubModels:
    async def complete(
        self,
        *,
        model_id: str,
        n_ctx: int | None,
        prompt: str,
        stream: bool,
        loras: tuple[tuple[str, float], ...] = (),
        tenant: str = "default",
        **sampling: Any,
    ) -> Any:
        return {
            "id": f"cmpl-{secrets.token_hex(4)}",
            "model": model_id,
            "created": int(time.time()),
            "choices": [{"text": prompt[::-1], "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }


def test_completion_roundtrip(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[completions_router])
    app.state.models = _StubModels()
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request(
        "POST",
        "/v1/completions",
        payload={"model": "stub", "prompt": "hello", "max_tokens": 8},
    )
    resp = CompletionResponse.model_validate(data)
    assert resp.text == "olleh"
    assert resp.finish_reason == "stop"
    assert resp.usage.total_tokens == 2


def test_completion_manager_error_surfaces(tmp_path: Path):
    """ManagerError(QUEUE_FULL) from the manager → encrypted 400 with QueueFull."""
    from secure_llm_client.errors import QueueFull
    from secure_llm_server.models.manager import ManagerError

    class _Failing:
        async def complete(self, **kwargs: Any) -> Any:
            raise ManagerError(ErrorCode.QUEUE_FULL, "full")

    app, keystore, _ = build_app(tmp_path, extra_routers=[completions_router])
    app.state.models = _Failing()
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(QueueFull):
        t.request("POST", "/v1/completions", payload={"model": "stub", "prompt": "x"})


def test_completion_stream_true_rejected(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[completions_router])
    app.state.models = _StubModels()
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/completions",
            payload={"model": "stub", "prompt": "hi", "stream": True, "max_tokens": 4},
        )
    # Server returns BAD_REQUEST inside an encrypted error envelope.
    assert "streaming" in str(exc.value).lower()
