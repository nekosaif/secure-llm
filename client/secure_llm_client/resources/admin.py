"""client.admin.* — only usable from clients whose allowlist entry has the 'admin' scope."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, cast

from secure_llm_protocol.schemas import (
    LoraInfo,
    LoraList,
    LoraRef,
    ModelInfo,
    ModelList,
)

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport

_List = list


class _Sessions:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> _List[dict[str, Any]]:
        return cast(
            _List[dict[str, Any]],
            self._t.request("POST", "/v1/admin/sessions/list", payload={})["sessions"],
        )

    def terminate(self, session_id_b64: str) -> bool:
        return bool(
            self._t.request(
                "POST", "/v1/admin/sessions/terminate", payload={"session_id": session_id_b64}
            )["terminated"]
        )


class _Clients:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> _List[dict[str, Any]]:
        return cast(
            _List[dict[str, Any]],
            self._t.request("POST", "/v1/admin/clients/list", payload={})["clients"],
        )

    def reload(self) -> int:
        return int(self._t.request("POST", "/v1/admin/clients/reload", payload={})["clients"])


class _Models:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> _List[ModelInfo]:
        data = self._t.request("POST", "/v1/admin/models/list", payload={})
        return ModelList.model_validate(data).models

    def preload(self, model_id: str) -> None:
        self._t.request("POST", "/v1/admin/models/preload", payload={"id": model_id})

    def unload(self, model_id: str) -> bool:
        return bool(
            self._t.request("POST", "/v1/admin/models/unload", payload={"id": model_id})["unloaded"]
        )


class _LogLevel:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def set(self, component: str, level: str, *, ttl_seconds: int | None = None) -> None:
        self._t.request(
            "POST",
            "/v1/admin/log-level",
            payload={"component": component, "level": level, "ttl_seconds": ttl_seconds},
        )


class _Loras:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> _List[LoraInfo]:
        data = self._t.request("POST", "/v1/admin/loras/list", payload={})
        return LoraList.model_validate(data).loras

    def pull(
        self,
        repo_id: str,
        *,
        filename: str,
        sha256: str | None = None,
        base_model_id: str | None = None,
    ) -> LoraInfo:
        data = self._t.request(
            "POST",
            "/v1/admin/loras/pull",
            payload={
                "repo_id": repo_id,
                "filename": filename,
                "sha256": sha256,
                "base_model_id": base_model_id,
            },
        )
        return LoraInfo.model_validate(data)

    def rm(self, lora_id: str) -> bool:
        return bool(
            self._t.request("POST", "/v1/admin/loras/rm", payload={"id": lora_id})["removed"]
        )

    def apply(
        self,
        base_model_id: str,
        *,
        loras: Sequence[LoraRef | tuple[str, float]],
        n_ctx: int | None = None,
    ) -> dict[str, Any]:
        refs: _List[dict[str, Any]] = []
        for item in loras:
            if isinstance(item, LoraRef):
                refs.append(item.model_dump())
            else:
                lid, scale = item
                refs.append({"id": lid, "scale": float(scale)})
        return self._t.request(
            "POST",
            "/v1/admin/loras/apply",
            payload={
                "base_model_id": base_model_id,
                "loras": refs,
                "n_ctx": n_ctx,
            },
        )


class AdminResource:
    def __init__(self, transport: Transport) -> None:
        self.sessions = _Sessions(transport)
        self.clients = _Clients(transport)
        self.models = _Models(transport)
        self.log_level = _LogLevel(transport)
        self.loras = _Loras(transport)
        self._t = transport

    def gc(self) -> int:
        return int(self._t.request("POST", "/v1/admin/gc", payload={})["collected"])

    def shutdown(self, *, grace_seconds: int = 30) -> None:
        self._t.request("POST", "/v1/admin/shutdown", payload={"grace_seconds": grace_seconds})
