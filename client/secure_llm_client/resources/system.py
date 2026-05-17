"""client.system.*"""

from __future__ import annotations

from typing import TYPE_CHECKING

from secure_llm_protocol.schemas import SystemStatus

if TYPE_CHECKING:
    from secure_llm_client.transport import Transport


class SystemResource:
    def __init__(self, transport: Transport) -> None:
        self._t = transport

    def status(self) -> SystemStatus:
        data = self._t.request("POST", "/v1/system", payload={})
        return SystemStatus.model_validate(data)
