"""GET /healthz, /readyz (plaintext), POST /v1/system (encrypted)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from secure_llm_protocol.schemas import SystemStatus
from secure_llm_server.health import Readiness
from secure_llm_server.routers.system import router as system_router

from ._helpers import build_app, make_transport


class _StubStatus:
    def system(self) -> SystemStatus:
        return SystemStatus(
            cpu_percent=4.2,
            ram_total_bytes=16 * 10**9,
            ram_available_bytes=8 * 10**9,
            disk_total_bytes=500 * 10**9,
            disk_free_bytes=250 * 10**9,
            loaded_models=["stub"],
            queue_depths={"stub": 0},
            uptime_seconds=42.0,
        )


def test_healthz_plain(tmp_path: Path):
    app, _keystore, _ = build_app(tmp_path, extra_routers=[system_router])
    app.state.readiness = Readiness()  # not yet ready
    http = TestClient(app, base_url="http://testserver")
    r = http.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_reflects_readiness(tmp_path: Path):
    app, _keystore, _ = build_app(tmp_path, extra_routers=[system_router])
    readiness = Readiness()
    app.state.readiness = readiness
    http = TestClient(app, base_url="http://testserver")
    # Not ready yet.
    assert http.get("/readyz").status_code == 503
    # Mark ready.
    readiness.config_loaded = True
    readiness.keystore_loaded = True
    readiness.storage_dir_writable = True
    assert http.get("/readyz").status_code == 200


def test_system_encrypted_endpoint(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[system_router])
    app.state.status = _StubStatus()
    t = make_transport(app, keystore, tmp_path / "client")
    data = t.request("POST", "/v1/system", payload={})
    s = SystemStatus.model_validate(data)
    assert s.cpu_percent == 4.2
    assert s.loaded_models == ["stub"]
    assert s.uptime_seconds == 42.0
