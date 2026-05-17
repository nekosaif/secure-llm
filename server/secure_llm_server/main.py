"""FastAPI app entrypoint. Run via ``secure-llm-server --config path``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.lifespan import lifespan
from secure_llm_server.metrics import registry as metrics_registry
from secure_llm_server.middleware.rate_limit import RateLimitMiddleware
from secure_llm_server.middleware.request_id import RequestIdMiddleware
from secure_llm_server.middleware.security_headers import SecurityHeadersMiddleware
from secure_llm_server.middleware.size_limit import SizeLimitMiddleware
from secure_llm_server.routers import (
    admin,
    chat,
    completions,
    debug,
    embeddings,
    models,
    session,
    system,
)

_log = structlog.get_logger("secure_llm_server.main")


def create_app(config_path: Path) -> FastAPI:
    app = FastAPI(
        title="secure-llm",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,  # OpenAPI/Swagger disabled (auth-bearing endpoints take envelopes)
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.config_path = str(config_path)

    # Middleware order: outermost first.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, rpm_per_client=120)
    app.add_middleware(SizeLimitMiddleware, max_bytes=16 * 1024 * 1024)
    app.add_middleware(RequestIdMiddleware)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        state = request.app.state
        err = state.errors.record(
            exc,
            code=ErrorCode.INTERNAL_ERROR.value,
            request_id=getattr(request.state, "request_id", None),
            client_fingerprint=getattr(request.state, "client_fingerprint", None),
        )
        _log.error(
            "unhandled", error_id=err.error_id, path=request.url.path, exc_type=type(exc).__name__
        )
        return JSONResponse(
            status_code=500,
            content={
                "code": ErrorCode.INTERNAL_ERROR.value,
                "message": "internal error",
                "error_id": err.error_id,
            },
        )

    app.include_router(session.router)
    app.include_router(models.router)
    app.include_router(chat.router)
    app.include_router(completions.router)
    app.include_router(embeddings.router)
    app.include_router(system.router)
    app.include_router(debug.router)
    app.include_router(admin.router)

    # Prometheus
    metrics_app = make_asgi_app(registry=metrics_registry)
    app.mount("/metrics", metrics_app)
    return app


def run() -> None:
    parser = argparse.ArgumentParser(prog="secure-llm-server")
    parser.add_argument(
        "--config", required=False, default=os.environ.get("SECURE_LLM_CONFIG", "data/config.toml")
    )
    parser.add_argument(
        "--no-tls", action="store_true", help="dev only — skip TLS (loopback recommended)"
    )
    parser.add_argument("--host", default=None, help="override [server].host")
    parser.add_argument("--port", type=int, default=None, help="override [server].port")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"config not found: {config_path}", file=sys.stderr)
        sys.exit(2)

    from secure_llm_server.config import load_settings

    settings = load_settings(config_path)
    app = create_app(config_path)

    import uvicorn

    uvicorn_kwargs: dict[str, Any] = {
        "host": args.host or settings.server.host,
        "port": args.port or settings.server.port,
        "log_level": settings.observability.log_level.lower(),
        "timeout_graceful_shutdown": settings.server.shutdown_grace_seconds,
        "access_log": False,
    }
    if not args.no_tls:
        uvicorn_kwargs.update(
            ssl_certfile=str(settings.tls.cert_file),
            ssl_keyfile=str(settings.tls.key_file),
        )
    uvicorn.run(app, **uvicorn_kwargs)


if __name__ == "__main__":
    run()
