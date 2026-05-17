"""Assemble the status snapshot used by /v1/debug/status, /v1/admin/system, and `make doctor`."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from secure_llm_protocol.schemas import DebugStatus, SystemStatus
from secure_llm_server import __version__, sysinfo
from secure_llm_server.metrics import disk_free_bytes

if TYPE_CHECKING:
    from secure_llm_server.models.manager import ModelManager
    from secure_llm_server.observability.error_tracker import ErrorTracker
    from secure_llm_server.observability.ring_log import RingLog


class StatusBuilder:
    def __init__(
        self,
        *,
        models: ModelManager,
        errors: ErrorTracker,
        ring: RingLog,
        storage_dir: Path,
        started_at: float | None = None,
    ) -> None:
        self._models = models
        self._errors = errors
        self._ring = ring
        self._storage_dir = storage_dir
        self._started_at = started_at or time.time()

    def system(self) -> SystemStatus:
        total_ram, avail_ram = sysinfo.ram()
        total_disk, free_disk = sysinfo.disk(self._storage_dir)
        disk_free_bytes.set(free_disk)
        return SystemStatus(
            cpu_percent=sysinfo.cpu_percent(),
            ram_total_bytes=total_ram,
            ram_available_bytes=avail_ram,
            disk_total_bytes=total_disk,
            disk_free_bytes=free_disk,
            gpu=sysinfo.gpus(),
            loaded_models=[m.id for m in self._models.snapshot() if m.state == "loaded"],
            queue_depths={m.id: m.queue_depth for m in self._models.snapshot()},
            uptime_seconds=time.time() - self._started_at,
        )

    def debug_status(
        self, *, recent_log_limit: int = 50, recent_err_limit: int = 20
    ) -> DebugStatus:
        return DebugStatus(
            server_version=__version__,
            uptime_seconds=time.time() - self._started_at,
            system=self.system(),
            loaded_models=self._models.snapshot(),
            recent_errors=[e.summary() for e in self._errors.recent(recent_err_limit)],
            recent_logs=self._ring.tail(limit=recent_log_limit),
        )
