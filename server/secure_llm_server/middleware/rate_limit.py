"""Token-bucket rate limit per client fingerprint."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from secure_llm_protocol.errors import ErrorCode


@dataclass(slots=True)
class _Bucket:
    tokens: float
    last: float


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, rpm_per_client: int) -> None:
        super().__init__(app)
        self._rate = max(1, rpm_per_client) / 60.0  # tokens / sec
        self._capacity = max(10, rpm_per_client / 2)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = asyncio.Lock()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        key = getattr(request.state, "client_fingerprint", None) or "anon"
        if not await self._allow(key):
            return JSONResponse(
                {"code": ErrorCode.RATE_LIMITED.value, "message": "slow down"},
                status_code=429,
                headers={"retry-after": "1"},
            )
        return await call_next(request)

    async def _allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _Bucket(tokens=self._capacity, last=now)
                self._buckets[key] = b
            elapsed = now - b.last
            b.tokens = min(self._capacity, b.tokens + elapsed * self._rate)
            b.last = now
            if b.tokens < 1:
                return False
            b.tokens -= 1
            return True
