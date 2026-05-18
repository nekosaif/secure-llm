"""Unit tests for ASGI middleware.

request_id, security_headers, size_limit, rate_limit, audit.
"""

from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.middleware.audit import audit_event
from secure_llm_server.middleware.rate_limit import RateLimitMiddleware
from secure_llm_server.middleware.request_id import RequestIdMiddleware
from secure_llm_server.middleware.security_headers import SecurityHeadersMiddleware
from secure_llm_server.middleware.size_limit import SizeLimitMiddleware


def _ping_app(*middlewares: type) -> FastAPI:
    app = FastAPI()
    # Apply in the order callers actually use (outermost first).
    for mw in middlewares:
        app.add_middleware(mw)

    @app.get("/ping")
    async def _ping() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_security_headers_added():
    app = _ping_app(SecurityHeadersMiddleware)
    http = TestClient(app)
    r = http.get("/ping")
    assert r.status_code == 200
    for h in (
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "cache-control",
        "x-frame-options",
    ):
        assert h in r.headers, f"missing {h}"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_request_id_assigned_and_echoed():
    app = _ping_app(RequestIdMiddleware)
    http = TestClient(app)
    r = http.get("/ping")
    assert "x-request-id" in r.headers
    assert len(r.headers["x-request-id"]) == 16  # secrets.token_hex(8)


def test_request_id_honors_inbound_header():
    app = _ping_app(RequestIdMiddleware)
    http = TestClient(app)
    r = http.get("/ping", headers={"x-request-id": "ABC123"})
    assert r.headers["x-request-id"] == "ABC123"


def test_size_limit_rejects_oversize():
    app = FastAPI()
    app.add_middleware(SizeLimitMiddleware, max_bytes=10)

    @app.post("/echo")
    async def _echo() -> dict[str, str]:
        return {"ok": "yes"}

    http = TestClient(app)
    # Content-Length above the cap is rejected pre-handler.
    r = http.post(
        "/echo",
        content=b"x" * 100,
        headers={"content-length": "100", "content-type": "application/octet-stream"},
    )
    assert r.status_code == 413
    assert r.json()["code"] == ErrorCode.BODY_TOO_LARGE.value


def test_size_limit_bad_content_length():
    app = FastAPI()
    app.add_middleware(SizeLimitMiddleware, max_bytes=1024)

    @app.post("/echo")
    async def _echo() -> dict[str, str]:
        return {"ok": "yes"}

    http = TestClient(app)
    r = http.post(
        "/echo",
        content=b"x",
        headers={"content-length": "not-a-number", "content-type": "application/octet-stream"},
    )
    assert r.status_code == 400
    assert r.json()["code"] == ErrorCode.BAD_REQUEST.value


def test_size_limit_passthrough_when_under_cap():
    app = FastAPI()
    app.add_middleware(SizeLimitMiddleware, max_bytes=1024)

    @app.post("/echo")
    async def _echo() -> dict[str, str]:
        return {"ok": "yes"}

    http = TestClient(app)
    r = http.post("/echo", content=b"x")
    assert r.status_code == 200


def test_rate_limit_allows_then_blocks():
    app = FastAPI()
    # 60 rpm = 1 token / second; capacity = max(10, 30) = 30 → first 30 pass.
    app.add_middleware(RateLimitMiddleware, rpm_per_client=60)

    @app.get("/ping")
    async def _ping() -> dict[str, str]:
        return {"ok": "yes"}

    http = TestClient(app)
    # First ~30 succeed (capacity); the 31st-ish must 429.
    successes = 0
    blocked = False
    for _ in range(60):
        r = http.get("/ping")
        if r.status_code == 200:
            successes += 1
        elif r.status_code == 429:
            assert r.json()["code"] == ErrorCode.RATE_LIMITED.value
            assert r.headers.get("retry-after") == "1"
            blocked = True
            break
    assert successes >= 1
    assert blocked, "rate limiter never triggered"


def test_rate_limit_replenishes_over_time():
    app = FastAPI()
    # Tiny capacity, fast refill: 600 rpm → 10 tok/s, capacity max(10, 300)=300.
    # Hammer it for a tick, then wait and confirm a fresh request succeeds.
    app.add_middleware(RateLimitMiddleware, rpm_per_client=60)

    @app.get("/ping")
    async def _ping() -> dict[str, str]:
        return {"ok": "yes"}

    http = TestClient(app)
    for _ in range(40):
        http.get("/ping")
    # Wait for the bucket to refill at least one token (>1 token at 1 tok/s).
    asyncio.run(asyncio.sleep(1.2))
    r = http.get("/ping")
    assert r.status_code == 200


def test_audit_event_does_not_raise(capsys):
    # The audit sink is just a structlog logger; this exercises the import +
    # call path. Any unhandled exception would propagate to the caller.
    audit_event("test.event", actor="x", action="y", count=3)
    # We're not asserting on output content (structlog config varies); just
    # that the call returns cleanly.
    capsys.readouterr()
