"""StatusBuilder snapshot construction (the routers route through this)."""

from __future__ import annotations

from pathlib import Path

from secure_llm_protocol.schemas import ModelInfo
from secure_llm_server.observability.error_tracker import ErrorTracker
from secure_llm_server.observability.ring_log import RingLog
from secure_llm_server.observability.status import StatusBuilder


class _StubModels:
    def snapshot(self, *, tenant: str = "default") -> list[ModelInfo]:
        return [
            ModelInfo(
                id="m1",
                state="loaded",
                bytes_on_disk=10,
                sha256="x" * 64,
                queue_depth=3,
            ),
            ModelInfo(
                id="m2",
                state="present",
                bytes_on_disk=20,
                sha256="y" * 64,
                queue_depth=0,
            ),
        ]


def test_status_builder_system_snapshot(tmp_path: Path):
    builder = StatusBuilder(
        models=_StubModels(),
        errors=ErrorTracker(capacity=8),
        ring=RingLog(max_size=8),
        storage_dir=tmp_path,
        started_at=0.0,
    )
    s = builder.system()
    assert s.loaded_models == ["m1"]
    assert s.queue_depths == {"m1": 3, "m2": 0}
    assert s.uptime_seconds > 0
    assert s.disk_free_bytes >= 0


def test_status_builder_debug_status_carries_loaded_models(tmp_path: Path):
    builder = StatusBuilder(
        models=_StubModels(),
        errors=ErrorTracker(capacity=8),
        ring=RingLog(max_size=8),
        storage_dir=tmp_path,
        started_at=0.0,
    )
    ds = builder.debug_status()
    assert [m.id for m in ds.loaded_models] == ["m1", "m2"]
    assert ds.system.queue_depths["m1"] == 3
    assert ds.recent_errors == []
    assert ds.recent_logs == []
