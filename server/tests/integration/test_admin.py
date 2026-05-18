"""/v1/admin/* — control-plane endpoints.

Multi-tenant scoping for `sessions/list`, `clients/list`, and
`tenants/list` is in :mod:`test_multi_tenant`. This file exercises the
remaining surface: log-level (with TTL revert), gc, models/{preload,
unload}, loras/{list, pull, rm, apply}, sessions/terminate (own
tenant), clients/{list, reload}, and the deny path for non-admin
callers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secure_llm_client.errors import AdminRequiredError, SecureLLMError
from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import LoraInfo, LoraList
from secure_llm_server.models.downloader import DownloadError
from secure_llm_server.models.registry import LoraEntry
from secure_llm_server.routers.admin import router as admin_router

from ._helpers import build_app, make_transport

# --------------------------------------------------------------------- stubs


class _StubModels:
    def __init__(self) -> None:
        self.preloaded: list[tuple[str, str]] = []
        self.force_unload_calls: list[tuple[str, str]] = []
        self.ensure_loaded_calls: list[tuple[str, str, tuple]] = []

    def snapshot(self, *, tenant: str = "default") -> list:
        return []

    async def preload(self, model_id: str, *, tenant: str = "default") -> None:
        self.preloaded.append((tenant, model_id))

    async def force_unload(self, model_id: str, *, tenant: str = "default") -> bool:
        self.force_unload_calls.append((tenant, model_id))
        return True

    async def ensure_loaded(
        self,
        model_id: str,
        *,
        n_ctx: int | None = None,
        mode: str = "chat",
        loras: tuple = (),
        tenant: str = "default",
    ) -> object:
        self.ensure_loaded_calls.append((tenant, model_id, tuple(loras)))
        return object()


class _StubTenantLoraRegistry:
    def __init__(self) -> None:
        self.entries: list[LoraEntry] = []
        self.removed: list[str] = []
        self.storage_dir = Path("/tmp/sllm-test-loras")

    def all(self) -> list[LoraEntry]:
        return list(self.entries)

    def add(self, entry: LoraEntry) -> None:
        self.entries.append(entry)

    def remove(self, lora_id: str) -> bool:
        self.removed.append(lora_id)
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.id != lora_id]
        return len(self.entries) < before


class _StubMTLoraRegistry:
    def __init__(self) -> None:
        self._cache: dict[str, _StubTenantLoraRegistry] = {}

    def for_tenant(self, tenant: str) -> _StubTenantLoraRegistry:
        return self._cache.setdefault(tenant, _StubTenantLoraRegistry())


class _StubMTRegistry:
    """Just enough for endpoints that touch state.registry."""

    def for_tenant(self, t: str) -> object:
        class _R:
            def all(self) -> list[object]:
                return []

            def remove(self, _id: str) -> bool:
                return True

        return _R()

    def known_tenants(self) -> list[str]:
        return []


def _build(tmp_path: Path, *, scopes: tuple[str, ...] = ("chat", "admin")):
    app, keystore, _ = build_app(tmp_path, extra_routers=[admin_router], scopes=scopes)
    # observability layer
    from secure_llm_server.observability.error_tracker import ErrorTracker
    from secure_llm_server.observability.ring_log import RingLog

    app.state.ring = RingLog(max_size=64)
    app.state.errors = ErrorTracker(capacity=16)
    app.state.models = _StubModels()
    app.state.registry = _StubMTRegistry()
    app.state.lora_registry = _StubMTLoraRegistry()
    app.state.at_rest_key = object()
    # log-level revert lives on settings.observability.log_level
    app.state.settings.observability = type("O", (), {"log_level": "INFO"})()
    return app, keystore


# -------------------------------------------------------------- deny / scopes


def test_non_admin_is_rejected(tmp_path: Path):
    app, keystore = _build(tmp_path, scopes=("chat",))
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(AdminRequiredError):
        t.request("POST", "/v1/admin/models/list", payload={})


# ------------------------------------------------------------- models/preload


def test_admin_models_preload(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/models/preload", payload={"id": "stub"})
    assert out == {"id": "stub", "state": "loaded"}
    assert app.state.models.preloaded == [("default", "stub")]


def test_admin_models_unload(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/models/unload", payload={"id": "stub"})
    assert out == {"id": "stub", "unloaded": True}
    assert app.state.models.force_unload_calls == [("default", "stub")]


def test_admin_models_list(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/models/list", payload={})
    assert out == {"models": []}


# -------------------------------------------------------------- clients/reload


class _ReloadableKeystore:
    """Wraps the real keystore so we can spy on reload_allowlist()."""

    def __init__(self, original) -> None:  # type: ignore[no-untyped-def]
        self._inner = original
        self.reload_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def reload_allowlist(self) -> int:
        self.reload_count += 1
        return 0


def test_admin_clients_reload(tmp_path: Path):
    app, keystore = _build(tmp_path)
    wrapped = _ReloadableKeystore(keystore)
    app.state.keystore = wrapped
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/clients/reload", payload={})
    assert out == {"clients": 0}
    assert wrapped.reload_count == 1


# ---------------------------------------------------------------------- gc


def test_admin_gc(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/gc", payload={})
    assert "collected" in out
    assert isinstance(out["collected"], int)


# ---------------------------------------------------------------- log-level


def test_admin_log_level_set_with_ttl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The TTL branch schedules an asyncio revert task and reports ok.

    Verifying the *revert* fires from a TestClient is fiddly (the
    schedule lives in the test loop, which exits with the response).
    The branch is still exercised — that's the line we want to cover.
    """
    app, keystore = _build(tmp_path)
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "secure_llm_server.routers.admin.set_component_level",
        lambda c, lvl: calls.append((c, lvl)),
    )
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request(
        "POST",
        "/v1/admin/log-level",
        payload={"component": "secure_llm_server.crypto", "level": "DEBUG", "ttl_seconds": 1},
    )
    assert out == {"ok": True}
    assert ("secure_llm_server.crypto", "DEBUG") in calls


def test_admin_log_level_set_no_ttl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app, keystore = _build(tmp_path)
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "secure_llm_server.routers.admin.set_component_level",
        lambda c, lvl: calls.append((c, lvl)),
    )
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request(
        "POST",
        "/v1/admin/log-level",
        payload={"component": "x.y", "level": "WARNING"},
    )
    assert out == {"ok": True}
    assert calls == [("x.y", "WARNING")]


# -------------------------------------------------------------- sessions/terminate


def test_admin_sessions_terminate_own_tenant(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    # We need a session_id to target. Pull our own.
    own = t.request("POST", "/v1/admin/sessions/list", payload={})
    sid = own["sessions"][0]["session_id"]
    out = t.request("POST", "/v1/admin/sessions/terminate", payload={"session_id": sid})
    assert out["terminated"] is True


# ---------------------------------------------------------------- loras/*


def test_admin_loras_list_empty(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/admin/loras/list", payload={})
    out = LoraList.model_validate(data)
    assert out.loras == []


def test_admin_loras_pull_disabled(tmp_path: Path):
    app, keystore = _build(tmp_path)
    app.state.settings.models.allow_download = False
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/admin/loras/pull",
            payload={"repo_id": "x/y", "filename": "z.lora.gguf"},
        )
    assert "downloads disabled" in str(exc.value)


def test_admin_loras_pull_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app, keystore = _build(tmp_path)

    def _fake_pull(**kwargs: Any) -> LoraEntry:
        entry = LoraEntry(
            id="adapter-1",
            sha256_plaintext="abc" * 21 + "a",
            repo_id="stub/repo",
            filename="adapter-1.lora.gguf",
            bytes_plaintext=512,
            bytes_ciphertext=600,
            base_model_id="base",
        )
        kwargs["registry"].add(entry)
        return entry

    monkeypatch.setattr("secure_llm_server.routers.admin.download_and_seal_lora", _fake_pull)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request(
        "POST",
        "/v1/admin/loras/pull",
        payload={
            "repo_id": "stub/repo",
            "filename": "adapter-1.lora.gguf",
            "base_model_id": "base",
        },
    )
    info = LoraInfo.model_validate(data)
    assert info.id == "adapter-1"
    assert info.base_model_id == "base"


def test_admin_loras_pull_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    app, keystore = _build(tmp_path)

    def _raise(**_kwargs: Any) -> LoraEntry:
        raise DownloadError(ErrorCode.SHA256_MISMATCH, "bad sha")

    monkeypatch.setattr("secure_llm_server.routers.admin.download_and_seal_lora", _raise)
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/admin/loras/pull",
            payload={"repo_id": "x/y", "filename": "z.lora.gguf"},
        )
    assert exc.value.code == ErrorCode.SHA256_MISMATCH


def test_admin_loras_rm(tmp_path: Path):
    app, keystore = _build(tmp_path)
    # Seed a LoRA so the remove actually removes something.
    reg = app.state.lora_registry.for_tenant("default")
    reg.add(
        LoraEntry(
            id="zap",
            sha256_plaintext="0" * 64,
            repo_id="x/y",
            filename="zap.lora.gguf",
            bytes_plaintext=1,
            bytes_ciphertext=1,
        )
    )
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request("POST", "/v1/admin/loras/rm", payload={"id": "zap"})
    assert out == {"id": "zap", "removed": True}


def test_admin_loras_apply(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    out = t.request(
        "POST",
        "/v1/admin/loras/apply",
        payload={
            "base_model_id": "base",
            "loras": [{"id": "a", "scale": 0.5}, {"id": "b", "scale": 1.5}],
            "n_ctx": 2048,
        },
    )
    assert out["base_model_id"] == "base"
    assert app.state.models.ensure_loaded_calls == [("default", "base", (("a", 0.5), ("b", 1.5)))]


def test_admin_loras_apply_error_surfaces(tmp_path: Path):
    app, keystore = _build(tmp_path)

    from secure_llm_server.models.manager import ManagerError

    async def _raise(*_args: Any, **_kwargs: Any) -> None:
        raise ManagerError(ErrorCode.MODEL_NOT_FOUND, "lora:missing")

    app.state.models.ensure_loaded = _raise  # type: ignore[assignment]
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(SecureLLMError) as exc:
        t.request(
            "POST",
            "/v1/admin/loras/apply",
            payload={"base_model_id": "base", "loras": [{"id": "missing", "scale": 1.0}]},
        )
    assert exc.value.code == ErrorCode.MODEL_NOT_FOUND


# ---------------------------------------------------------- tenants/list deny


def test_admin_tenants_list_requires_super_admin(tmp_path: Path):
    app, keystore = _build(tmp_path, scopes=("chat", "admin"))
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(AdminRequiredError):
        t.request("POST", "/v1/admin/tenants/list", payload={})
