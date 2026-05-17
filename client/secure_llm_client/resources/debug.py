"""client.debug.*"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from secure_llm_protocol.schemas import DebugStatus, DoctorReport

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport


class DebugResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def status(self) -> DebugStatus:
        return DebugStatus.model_validate(self._t.request("POST", "/v1/debug/status", payload={}))

    def doctor(self) -> DoctorReport:
        return DoctorReport.model_validate(self._t.request("POST", "/v1/debug/doctor", payload={}))

    def version(self) -> dict[str, Any]:
        return self._t.request("POST", "/v1/debug/version", payload={})

    def logs(
        self,
        *,
        limit: int = 200,
        level: str | None = None,
        component: str | None = None,
        since: float | None = None,
    ) -> list[dict[str, Any]]:
        data = self._t.request(
            "POST",
            "/v1/debug/logs",
            payload={"limit": limit, "level": level, "component": component, "since": since},
        )
        return cast(list[dict[str, Any]], data.get("entries", []))

    def errors(self, *, limit: int = 50) -> list[dict[str, Any]]:
        data = self._t.request("POST", "/v1/debug/errors", payload={"limit": limit})
        return cast(list[dict[str, Any]], data.get("errors", []))
