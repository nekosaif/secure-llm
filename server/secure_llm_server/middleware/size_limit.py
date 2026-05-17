"""Reject oversize bodies before they touch AEAD."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from secure_llm_protocol.errors import ErrorCode


class SizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, max_bytes: int) -> None:
        super().__init__(app)
        self._max = max_bytes

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self._max:
                    return JSONResponse(
                        {
                            "code": ErrorCode.BODY_TOO_LARGE.value,
                            "message": f"max {self._max} bytes",
                        },
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse(
                    {"code": ErrorCode.BAD_REQUEST.value, "message": "bad content-length"},
                    status_code=400,
                )
        return await call_next(request)
