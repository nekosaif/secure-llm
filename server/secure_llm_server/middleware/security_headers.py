"""Add common defensive HTTP headers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        h = response.headers
        h.setdefault("strict-transport-security", "max-age=31536000; includeSubDomains")
        h.setdefault("x-content-type-options", "nosniff")
        h.setdefault("referrer-policy", "no-referrer")
        h.setdefault("cache-control", "no-store")
        h.setdefault("x-frame-options", "DENY")
        return response
