"""DELETE /v1/session/{id} — happy + bad-base64 paths."""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi.testclient import TestClient

from ._helpers import build_app, make_transport


def test_delete_session_with_bad_base64(tmp_path: Path):
    app, _ks, _ = build_app(tmp_path, extra_routers=[])
    http = TestClient(app, base_url="http://testserver")
    r = http.delete("/v1/session/not!base64!")
    assert r.status_code == 400


def test_delete_session_happy_path(tmp_path: Path):
    app, keystore, _ = build_app(tmp_path, extra_routers=[])
    # Drive a handshake to get a valid session.
    t = make_transport(app, keystore, tmp_path / "client")
    state = t._session_state()  # type: ignore[attr-defined]
    sid_b64 = base64.urlsafe_b64encode(state.outcome.session_id).decode("ascii")

    http = TestClient(app, base_url="http://testserver")
    r = http.delete(f"/v1/session/{sid_b64}")
    assert r.status_code == 204
