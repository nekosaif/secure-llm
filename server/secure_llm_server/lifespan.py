"""ASGI lifespan: load config + keystore + models, wire app.state, graceful shutdown."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI

from secure_llm_server import logging as logmod
from secure_llm_server.config import Settings, load_settings
from secure_llm_server.crypto.at_rest import AtRestKey
from secure_llm_server.crypto.keystore import load_or_init_keystore
from secure_llm_server.health import Readiness
from secure_llm_server.models.manager import ModelManager
from secure_llm_server.models.registry import (
    MultiTenantLoraRegistry,
    MultiTenantRegistry,
)
from secure_llm_server.observability.error_tracker import ErrorTracker
from secure_llm_server.observability.status import StatusBuilder
from secure_llm_server.session.manager import SessionManager
from secure_llm_server.session.store import InMemorySessionStore, SessionStore


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    config_path = Path(app.state.config_path)
    settings: Settings = load_settings(config_path)
    app.state.settings = settings

    ring = logmod.configure(
        level=settings.observability.log_level,
        log_format=settings.observability.log_format,
        log_dir=settings.observability.log_dir,
    )
    app.state.ring = ring
    log = structlog.get_logger("secure_llm_server.lifespan")
    log.info("boot.config", path=str(config_path))

    readiness = Readiness()
    readiness.config_loaded = True
    readiness.check_storage(Path(settings.models.storage_dir))
    app.state.readiness = readiness

    keystore = load_or_init_keystore(
        Path(settings.crypto.key_dir),
        Path(settings.crypto.authorized_clients),
    )
    app.state.keystore = keystore
    readiness.keystore_loaded = True
    log.info(
        "boot.keystore",
        clients=len(keystore.allowlist),
        server_fp=__fingerprint(keystore.server.x25519_pk),
    )

    at_rest = AtRestKey(keystore.server.age_secret_path)
    app.state.at_rest_key = at_rest

    registry = MultiTenantRegistry(Path(settings.models.storage_dir))
    app.state.registry = registry

    # LoRA storage is a sibling of the model dir; per-tenant subdirs are lazy.
    lora_dir = Path(settings.models.storage_dir).parent / "loras"
    lora_registry = MultiTenantLoraRegistry(lora_dir)
    app.state.lora_registry = lora_registry

    models = ModelManager(
        registry=registry,
        at_rest=at_rest,
        tmpfs_dir=Path(settings.models.tmpfs_dir),
        max_loaded=settings.models.max_loaded,
        idle_timeout_seconds=settings.models.idle_timeout_seconds,
        n_gpu_layers=settings.inference.n_gpu_layers,
        n_threads=settings.inference.n_threads,
        n_ctx_default=settings.inference.n_ctx_default,
        queue_depth=settings.inference.queue_depth_per_model,
        lora_registry=lora_registry,
    )
    app.state.models = models

    store: SessionStore
    if settings.federation.session_store == "redis":
        if not settings.federation.session_store_url:
            raise RuntimeError(
                "[federation].session_store='redis' requires "
                "[federation].session_store_url"
            )
        from secure_llm_server.session.redis_store import build_redis_session_store

        store = build_redis_session_store(settings.federation.session_store_url)
        log.info(
            "boot.federation",
            session_store="redis",
            identity_replicated=settings.federation.identity_replicated,
        )
    else:
        store = InMemorySessionStore()
    sessions = SessionManager(
        ttl_seconds=settings.crypto.session_ttl_seconds,
        max_lifetime_seconds=settings.crypto.session_max_lifetime_seconds,
        store=store,
    )
    app.state.session_manager = sessions
    app.state.errors = ErrorTracker(capacity=settings.observability.error_buffer_size)
    app.state.status = StatusBuilder(
        models=models,
        errors=app.state.errors,
        ring=ring,
        storage_dir=Path(settings.models.storage_dir),
        started_at=time.time(),
    )

    reap_task = asyncio.create_task(_reap_sessions(sessions), name="session-reaper")
    log.info("boot.ready")

    try:
        yield
    finally:
        log.info("shutdown.begin")
        reap_task.cancel()
        await models.shutdown()
        log.info("shutdown.done")


def __fingerprint(pubkey: bytes) -> str:
    from secure_llm_server.crypto.kdf import fingerprint as _fp

    return _fp(pubkey)


async def _reap_sessions(sm: SessionManager) -> None:
    try:
        while True:
            await asyncio.sleep(60)
            await sm.reap_expired()
    except asyncio.CancelledError:
        return
