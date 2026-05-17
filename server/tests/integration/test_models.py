"""POST /v1/models/{list, download, remove}."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secure_llm_client.errors import SecureLLMError
from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import ModelInfo, ModelList
from secure_llm_server.models.downloader import DownloadError
from secure_llm_server.models.registry import ModelEntry
from secure_llm_server.routers.models import router as models_router

from ._helpers import build_app, make_transport


def _fake_entry(model_id: str = "stub") -> ModelEntry:
    return ModelEntry(
        id=model_id,
        sha256_plaintext="deadbeef" * 8,
        repo_id="stub/repo",
        filename=f"{model_id}.gguf",
        bytes_plaintext=1024,
        bytes_ciphertext=1100,
    )


class _StubTenantRegistry:
    def __init__(self) -> None:
        self.entries: list[ModelEntry] = []
        self.removed: list[str] = []
        self.storage_dir = Path("/tmp/sllm-test-models")

    def all(self) -> list[ModelEntry]:
        return list(self.entries)

    def add(self, entry: ModelEntry) -> None:
        self.entries.append(entry)

    def remove(self, model_id: str) -> bool:
        self.removed.append(model_id)
        self.entries = [e for e in self.entries if e.id != model_id]
        return True


class _StubMultiTenantRegistry:
    def __init__(self) -> None:
        self._cache: dict[str, _StubTenantRegistry] = {}

    def for_tenant(self, tenant: str) -> _StubTenantRegistry:
        return self._cache.setdefault(tenant, _StubTenantRegistry())


class _StubModels:
    def __init__(self, snapshot_entries: list[ModelInfo] | None = None) -> None:
        self.snapshot_entries = snapshot_entries or []
        self.force_unload_calls: list[tuple[str, str]] = []

    def snapshot(self, *, tenant: str = "default") -> list[ModelInfo]:
        return list(self.snapshot_entries)

    async def force_unload(self, model_id: str, *, tenant: str = "default") -> bool:
        self.force_unload_calls.append((tenant, model_id))
        return True


def _build(tmp_path: Path) -> tuple[Any, Any]:
    app, keystore, _ = build_app(tmp_path, extra_routers=[models_router])
    app.state.registry = _StubMultiTenantRegistry()
    app.state.at_rest_key = object()  # never dereferenced in stubbed tests
    app.state.models = _StubModels(
        snapshot_entries=[
            ModelInfo(
                id="stub",
                repo_id="stub/repo",
                filename="stub.gguf",
                state="present",
                bytes_on_disk=42,
                sha256="cafe" * 16,
            )
        ]
    )
    return app, keystore


def test_models_list(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/models/list", payload={})
    out = ModelList.model_validate(data)
    assert [m.id for m in out.models] == ["stub"]


def test_models_remove(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/models/remove", payload={"id": "stub"})
    # Models list is returned post-remove (still shows whatever stub snapshot has).
    ModelList.model_validate(data)
    # force_unload was invoked with the right tenant + id.
    assert app.state.models.force_unload_calls == [("default", "stub")]
    # The tenant registry's remove was called.
    assert app.state.registry.for_tenant("default").removed == ["stub"]


def test_models_download_disabled(tmp_path: Path):
    app, keystore = _build(tmp_path)
    app.state.settings.models.allow_download = False
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/models/download",
            payload={"repo_id": "x/y", "filename": "m.gguf"},
        )
    # The router emits an `BAD_REQUEST` envelope with the right message.
    assert "downloads disabled" in str(exc.value)


def test_models_download_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app, keystore = _build(tmp_path)

    def _fake_download_and_seal(**kwargs: Any) -> ModelEntry:
        # Mimic the real downloader's contract: append the entry into the
        # registry it was handed, then return it.
        entry = _fake_entry()
        kwargs["registry"].add(entry)
        return entry

    monkeypatch.setattr(
        "secure_llm_server.routers.models.download_and_seal",
        _fake_download_and_seal,
    )
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request(
        "POST",
        "/v1/models/download",
        payload={"repo_id": "stub/repo", "filename": "stub.gguf"},
    )
    ModelList.model_validate(data)
    assert app.state.registry.for_tenant("default").entries[-1].id == "stub"


def test_models_download_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app, keystore = _build(tmp_path)

    def _raise_sha(**_kwargs: Any) -> ModelEntry:
        raise DownloadError(ErrorCode.SHA256_MISMATCH, "expected != got")

    monkeypatch.setattr(
        "secure_llm_server.routers.models.download_and_seal",
        _raise_sha,
    )
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/models/download",
            payload={
                "repo_id": "stub/repo",
                "filename": "m.gguf",
                "sha256": "deadbeef",
            },
        )
    assert exc.value.code == ErrorCode.SHA256_MISMATCH
