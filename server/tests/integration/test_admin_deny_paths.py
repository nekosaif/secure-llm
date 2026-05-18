"""Sweep every admin endpoint as a *non-admin* caller → AdminRequiredError.

This systematically hits the `_require_admin` deny branch on every
handler so the line is exercised in each.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_llm_client.errors import AdminRequiredError
from secure_llm_server.observability.error_tracker import ErrorTracker
from secure_llm_server.observability.ring_log import RingLog
from secure_llm_server.routers.admin import router as admin_router

from ._helpers import build_app, make_transport


def _build(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[admin_router], scopes=("chat",))
    app.state.ring = RingLog(max_size=4)
    app.state.errors = ErrorTracker(capacity=4)
    app.state.models = object()
    app.state.registry = object()
    app.state.lora_registry = object()
    app.state.at_rest_key = object()
    app.state.settings.observability = type("O", (), {"log_level": "INFO"})()
    return app, keystore


ENDPOINTS = [
    ("/v1/admin/sessions/list", {}),
    ("/v1/admin/sessions/terminate", {"session_id": "AAAA"}),
    ("/v1/admin/clients/list", {}),
    ("/v1/admin/clients/reload", {}),
    ("/v1/admin/models/list", {}),
    ("/v1/admin/models/preload", {"id": "stub"}),
    ("/v1/admin/models/unload", {"id": "stub"}),
    ("/v1/admin/log-level", {"component": "x", "level": "INFO"}),
    ("/v1/admin/gc", {}),
    ("/v1/admin/shutdown", {"grace_seconds": 0}),
    ("/v1/admin/loras/list", {}),
    ("/v1/admin/loras/pull", {"repo_id": "x/y", "filename": "z.lora.gguf"}),
    ("/v1/admin/loras/rm", {"id": "z"}),
    ("/v1/admin/loras/apply", {"base_model_id": "b", "loras": []}),
    ("/v1/admin/tenants/list", {}),
]


@pytest.mark.parametrize("path,payload", ENDPOINTS)
def test_endpoint_denies_non_admin(tmp_path: Path, path: str, payload: dict):
    app, keystore = _build(tmp_path)
    t = make_transport(app, keystore, tmp_path / "client")
    with pytest.raises(AdminRequiredError):
        t.request("POST", path, payload=payload)
