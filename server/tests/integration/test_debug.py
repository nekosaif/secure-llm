"""/v1/debug/{status, doctor, version, logs, errors}."""

from __future__ import annotations

import time
from pathlib import Path

from secure_llm_protocol.schemas import (
    DebugStatus,
    DoctorReport,
    LogEntry,
    SystemStatus,
)
from secure_llm_server.observability.error_tracker import ErrorTracker
from secure_llm_server.observability.ring_log import RingLog
from secure_llm_server.routers.debug import router as debug_router

from ._helpers import build_app, make_transport


def _fake_debug_status() -> DebugStatus:
    return DebugStatus(
        server_version="0.1.0",
        uptime_seconds=1.5,
        system=SystemStatus(
            cpu_percent=0.0,
            ram_total_bytes=0,
            ram_available_bytes=0,
            disk_total_bytes=0,
            disk_free_bytes=0,
            loaded_models=[],
            queue_depths={},
            uptime_seconds=1.5,
        ),
        loaded_models=[],
        recent_errors=[],
        recent_logs=[],
    )


class _StubStatus:
    def debug_status(
        self, *, recent_log_limit: int = 50, recent_err_limit: int = 20
    ) -> DebugStatus:
        return _fake_debug_status()


def _build(tmp_path: Path, *, scopes: tuple[str, ...] = ("chat",)):
    app, keystore, _ = build_app(tmp_path, extra_routers=[debug_router], scopes=scopes)
    ring = RingLog(max_size=128)
    ring.add(
        {
            "timestamp": time.time(),
            "level": "info",
            "logger": "secure_llm_server.test",
            "event": "hello",
            "client_fp": "anon",
        }
    )
    app.state.ring = ring
    app.state.errors = ErrorTracker(capacity=16)
    app.state.status = _StubStatus()
    return app, keystore


def test_debug_status(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/status", payload={})
    out = DebugStatus.model_validate(data)
    assert out.server_version == "0.1.0"
    assert out.uptime_seconds == 1.5


def test_debug_doctor(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/doctor", payload={})
    report = DoctorReport.model_validate(data)
    assert report.overall in {"ok", "warn", "fail"}
    # run_checks always emits at least the python/uv/toolchain trio.
    assert len(report.steps) >= 1


def test_debug_version(tmp_path: Path):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/version", payload={})
    assert data["server_version"] == "0.1.0"
    assert data["protocol_version"] == "1.0"


def test_debug_logs_non_admin_sees_only_own_fp(tmp_path: Path):
    # Non-admin caller: the router filters by their fingerprint. Our seeded
    # ring entry has client_fp="anon", which won't match the real session's
    # fingerprint, so a non-admin sees an empty list.
    app, keystore = _build(tmp_path, scopes=("chat",))
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/logs", payload={"limit": 10})
    assert data["entries"] == []


def test_debug_logs_admin_sees_everything(tmp_path: Path):
    # Admin caller: no fingerprint filter, so the seeded entry comes back.
    app, keystore = _build(tmp_path, scopes=("chat", "admin"))
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/logs", payload={"limit": 10})
    [entry] = [LogEntry.model_validate(e) for e in data["entries"]]
    assert entry.event == "hello"


def test_debug_errors(tmp_path: Path):
    app, keystore = _build(tmp_path)
    err = app.state.errors.record(  # type: ignore[attr-defined]
        ValueError("boom"),
        code="internal_error",
        request_id="rid-1",
    )
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/debug/errors", payload={"limit": 5})
    assert any(item["error_id"] == err.error_id for item in data["errors"])
