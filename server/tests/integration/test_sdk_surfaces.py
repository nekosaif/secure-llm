"""SDK resource classes driven against in-process apps.

These tests cover the client/secure_llm_client/resources/*.py thin
wrapper code that pytest hadn't yet exercised: the conversation helper,
client.system.status, client.models.{list,download,remove},
client.debug.*, client.admin.{models,clients,sessions,loras,log_level,gc}.
The server-side handlers are stubbed; the *client SDK code paths* are
the focus.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from secure_llm_protocol.schemas import ModelInfo
from secure_llm_server.observability.error_tracker import ErrorTracker
from secure_llm_server.observability.ring_log import RingLog
from secure_llm_server.routers.admin import router as admin_router
from secure_llm_server.routers.chat import router as chat_router
from secure_llm_server.routers.completions import router as completions_router
from secure_llm_server.routers.debug import router as debug_router
from secure_llm_server.routers.embeddings import router as embeddings_router
from secure_llm_server.routers.models import router as models_router
from secure_llm_server.routers.system import router as system_router

from ._helpers import build_app


def _full_app(tmp_path: Path):
    app, keystore, _ = build_app(
        tmp_path,
        extra_routers=[
            chat_router,
            completions_router,
            embeddings_router,
            system_router,
            debug_router,
            admin_router,
            models_router,
        ],
        scopes=("chat", "admin", "super_admin"),
    )

    class _Models:
        async def chat(self, **kwargs: Any) -> Any:
            return {
                "id": "chatcmpl-1",
                "model": kwargs["model_id"],
                "created": int(time.time()),
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "hi-back"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }

        async def complete(self, **kwargs: Any) -> Any:
            return {
                "id": "cmpl-1",
                "model": kwargs["model_id"],
                "created": int(time.time()),
                "choices": [{"text": "ok", "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }

        async def embed(self, **kwargs: Any) -> Any:
            inputs = kwargs.get("inputs", [])
            return {
                "data": [{"index": i, "embedding": [1.0, 0.0]} for i in range(len(inputs))],
                "usage": {"prompt_tokens": 1},
            }

        async def preload(self, model_id: str, *, tenant: str = "default") -> None:
            pass

        async def force_unload(self, model_id: str, *, tenant: str = "default") -> bool:
            return True

        async def ensure_loaded(self, *args: Any, **kwargs: Any) -> object:
            return object()

        def snapshot(self, *, tenant: str = "default") -> list[ModelInfo]:
            return [
                ModelInfo(
                    id="stub",
                    state="loaded",
                    bytes_on_disk=10,
                    sha256="x" * 64,
                )
            ]

    class _TR:
        def __init__(self) -> None:
            self.storage_dir = tmp_path / "models"

        def all(self) -> list[object]:
            return []

        def add(self, _e: object) -> None:
            pass

        def remove(self, _id: str) -> bool:
            return True

    class _MT:
        def __init__(self) -> None:
            self._inner = _TR()

        def for_tenant(self, _t: str) -> object:
            return self._inner

        def known_tenants(self) -> list[str]:
            return ["default"]

    class _LR:
        def __init__(self) -> None:
            self.entries: list[object] = []
            self.storage_dir = tmp_path / "loras"

        def all(self) -> list[object]:
            return list(self.entries)

        def add(self, e: object) -> None:
            self.entries.append(e)

        def remove(self, _id: str) -> bool:
            return True

    class _MTLora:
        def __init__(self) -> None:
            self._inner = _LR()

        def for_tenant(self, _t: str) -> object:
            return self._inner

    class _Status:
        def system(self) -> object:
            from secure_llm_protocol.schemas import SystemStatus

            return SystemStatus(
                cpu_percent=1.0,
                ram_total_bytes=1,
                ram_available_bytes=1,
                disk_total_bytes=1,
                disk_free_bytes=1,
            )

        def debug_status(self, **_kw: Any) -> object:
            from secure_llm_protocol.schemas import DebugStatus, SystemStatus

            return DebugStatus(
                server_version="0.1.0",
                uptime_seconds=1.0,
                system=SystemStatus(
                    cpu_percent=1.0,
                    ram_total_bytes=1,
                    ram_available_bytes=1,
                    disk_total_bytes=1,
                    disk_free_bytes=1,
                ),
                loaded_models=[],
            )

    app.state.models = _Models()
    app.state.registry = _MT()
    app.state.lora_registry = _MTLora()
    app.state.at_rest_key = object()
    app.state.ring = RingLog(max_size=4)
    app.state.errors = ErrorTracker(capacity=4)
    app.state.status = _Status()
    app.state.settings.observability = type("O", (), {"log_level": "INFO"})()
    return app, keystore


def _sdk(app: FastAPI, keystore: object, tmp_path: Path):
    from fastapi.testclient import TestClient

    from secure_llm_client import SecureLLMClient
    from secure_llm_client.crypto.handshake import ClientIdentity
    from secure_llm_client.transport import Transport

    base = "http://testserver"
    identity = ClientIdentity.load(tmp_path / "client")
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,  # type: ignore[attr-defined]
        verify=False,
    )
    t._client = TestClient(app, base_url=base)  # type: ignore[attr-defined]
    # Build a SecureLLMClient and overwrite its transport with ours so we
    # can drive the full resource API.
    client = SecureLLMClient.__new__(SecureLLMClient)
    client._transport = t  # type: ignore[attr-defined]
    from secure_llm_client.resources.admin import AdminResource
    from secure_llm_client.resources.chat import ChatResource
    from secure_llm_client.resources.completions import CompletionsResource
    from secure_llm_client.resources.debug import DebugResource
    from secure_llm_client.resources.embeddings import EmbeddingsResource
    from secure_llm_client.resources.models import ModelsResource
    from secure_llm_client.resources.system import SystemResource

    client.models = ModelsResource(t)
    client.chat = ChatResource(t)
    client.embeddings = EmbeddingsResource(t)
    client.completions = CompletionsResource(t)
    client.system = SystemResource(t)
    client.debug = DebugResource(t)
    client.admin = AdminResource(t)
    return client


def test_conversation_helper(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    conv = c.chat.conversation(model="stub", system="be terse")
    reply = conv.send("hi")
    assert reply == "hi-back"
    # System message stays; user/assistant exchange recorded.
    conv.send("more")
    conv.clear()
    # After clear, only system survives.
    assert [m["role"] for m in conv._messages] == ["system"]  # type: ignore[attr-defined]


def test_system_status(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    s = c.system.status()
    assert s.cpu_percent == 1.0


def test_completions_resource(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    resp = c.completions.create(model="stub", prompt="x", max_tokens=4)
    assert resp.text == "ok"


def test_embeddings_resource(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    out = c.embeddings.create(model="stub", input=["one", "two"])
    assert [d.index for d in out.data] == [0, 1]


def test_models_resource(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    listed = c.models.list()
    assert [m.id for m in listed] == ["stub"]
    assert c.models.status("stub") is not None
    assert c.models.status("ghost") is None


def test_debug_resource(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    assert c.debug.version()["server_version"] == "0.1.0"
    assert c.debug.status().server_version == "0.1.0"
    rep = c.debug.doctor()
    assert rep.overall in {"ok", "warn", "fail"}
    assert c.debug.logs(limit=10, level="info") == []
    assert c.debug.errors(limit=5) == []


def test_admin_sdk_surface(tmp_path: Path):
    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    assert c.admin.sessions.list()  # at least our own
    assert isinstance(c.admin.clients.list(), list)
    assert c.admin.clients.reload() == 0  # real keystore has no allowlist path
    c.admin.models.preload("stub")
    assert c.admin.models.unload("stub") is True
    assert isinstance(c.admin.loras.list(), list)
    c.admin.log_level.set("x.y", "DEBUG", ttl_seconds=2)
    assert isinstance(c.admin.gc(), int)


def test_admin_loras_apply_with_lora_ref(tmp_path: Path):
    """Apply via a list of LoraRef objects (not tuples) covers the SDK branch."""
    from secure_llm_protocol.schemas import LoraRef

    app, keystore = _full_app(tmp_path)
    c = _sdk(app, keystore, tmp_path)
    out = c.admin.loras.apply("base", loras=[LoraRef(id="a", scale=0.5)], n_ctx=512)
    assert out["base_model_id"] == "base"
