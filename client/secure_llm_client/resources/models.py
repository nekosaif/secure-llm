"""client.models.*"""

from __future__ import annotations

from typing import TYPE_CHECKING

from secure_llm_protocol.schemas import ModelInfo, ModelList

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport

# Module-level alias so type annotations inside the class don't resolve to the
# `list` method via class-scope name lookup.
_List = list


class ModelsResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def list(self) -> _List[ModelInfo]:
        data = self._t.request("POST", "/v1/models/list", payload={})
        return ModelList.model_validate(data).models

    def download(
        self, repo_id: str, *, filename: str, sha256: str | None = None
    ) -> _List[ModelInfo]:
        data = self._t.request(
            "POST",
            "/v1/models/download",
            payload={"repo_id": repo_id, "filename": filename, "sha256": sha256},
        )
        return ModelList.model_validate(data).models

    def remove(self, model_id: str) -> _List[ModelInfo]:
        data = self._t.request("POST", "/v1/models/remove", payload={"id": model_id})
        return ModelList.model_validate(data).models

    def status(self, model_id: str) -> ModelInfo | None:
        for m in self.list():
            if m.id == model_id:
                return m
        return None
