"""LRU of loaded models with idle-timeout offload and per-model queued inference.

``llama_cpp.Llama`` is not thread-safe — every inference call goes through the
per-model asyncio queue served by exactly one worker task. Concurrent callers
share the queue; backpressure is enforced by the queue's bounded size.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import ModelInfo, ModelState
from secure_llm_server.crypto.at_rest import AtRestKey, decrypt_to_tmpfs
from secure_llm_server.llm.backend import LlamaBackend
from secure_llm_server.metrics import (
    inference_queue_depth,
    model_load_seconds,
    model_loaded,
)
from secure_llm_server.models.registry import ModelEntry, ModelRegistry

_log = structlog.get_logger("secure_llm_server.models.manager")


class ManagerError(Exception):
    def __init__(self, code: ErrorCode, message: str = "") -> None:
        super().__init__(message or code.value)
        self.code = code


@dataclass(slots=True)
class _Loaded:
    entry: ModelEntry
    backend: LlamaBackend
    n_ctx: int
    last_used: float
    state: ModelState = "loaded"
    queue: asyncio.Queue[Any] = field(default_factory=lambda: asyncio.Queue(maxsize=8))
    worker_task: asyncio.Task[None] | None = None
    idle_timer: asyncio.TimerHandle | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_error: str | None = None


_SENTINEL_STOP = object()


@dataclass(slots=True)
class _Job:
    kind: str  # "chat" or "complete"
    payload: dict[str, Any]
    stream: bool
    future: asyncio.Future[Any]
    cancel_event: asyncio.Event


class ModelManager:
    def __init__(
        self,
        *,
        registry: ModelRegistry,
        at_rest: AtRestKey,
        tmpfs_dir: Path,
        max_loaded: int,
        idle_timeout_seconds: int,
        n_gpu_layers: int,
        n_threads: int,
        n_ctx_default: int,
        queue_depth: int,
    ) -> None:
        self._registry = registry
        self._at_rest = at_rest
        self._tmpfs_dir = tmpfs_dir
        self._max_loaded = max_loaded
        self._idle_timeout = idle_timeout_seconds
        self._n_gpu_layers = n_gpu_layers
        self._n_threads = n_threads
        self._n_ctx_default = n_ctx_default
        self._queue_depth = queue_depth
        self._loaded: OrderedDict[str, _Loaded] = OrderedDict()
        self._load_locks: dict[str, asyncio.Lock] = {}
        self._closing = False
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------ public

    def snapshot(self) -> list[ModelInfo]:
        out: list[ModelInfo] = []
        for entry in self._registry.all():
            loaded = self._loaded.get(entry.id)
            state: ModelState = loaded.state if loaded is not None else "present"
            out.append(
                ModelInfo(
                    id=entry.id,
                    repo_id=entry.repo_id,
                    filename=entry.filename,
                    state=state,
                    bytes_on_disk=entry.bytes_ciphertext,
                    sha256=entry.sha256_plaintext,
                    n_ctx_max=entry.n_ctx_max,
                    last_used_at=loaded.last_used if loaded else None,
                    queue_depth=loaded.queue.qsize() if loaded else 0,
                    last_error=loaded.last_error if loaded else None,
                )
            )
        return out

    async def ensure_loaded(self, model_id: str, *, n_ctx: int | None = None) -> _Loaded:
        entry = self._registry.get(model_id)
        if entry is None:
            raise ManagerError(ErrorCode.MODEL_NOT_FOUND, model_id)
        # Fast path: already loaded with a compatible ctx.
        loaded = self._loaded.get(model_id)
        if loaded is not None and (n_ctx is None or n_ctx <= loaded.n_ctx):
            self._loaded.move_to_end(model_id)
            self._reset_idle(loaded)
            return loaded

        lock = self._load_locks.setdefault(model_id, asyncio.Lock())
        async with lock:
            loaded = self._loaded.get(model_id)
            if loaded is not None and (n_ctx is None or n_ctx <= loaded.n_ctx):
                self._reset_idle(loaded)
                return loaded
            # Evict LRU if necessary.
            while len(self._loaded) >= self._max_loaded:
                victim_id, victim = next(iter(self._loaded.items()))
                _log.info("manager.evict", id=victim_id)
                await self._unload(victim_id, victim)
            loaded = await self._load(entry, n_ctx or self._n_ctx_default)
            self._loaded[entry.id] = loaded
            return loaded

    async def chat(
        self,
        *,
        model_id: str,
        n_ctx: int | None,
        messages: list[dict[str, str]],
        stream: bool,
        **sampling: Any,
    ) -> Any:
        loaded = await self.ensure_loaded(model_id, n_ctx=n_ctx)
        return await self._submit(
            loaded, kind="chat", payload={"messages": messages, **sampling}, stream=stream
        )

    async def complete(
        self,
        *,
        model_id: str,
        n_ctx: int | None,
        prompt: str,
        stream: bool,
        **sampling: Any,
    ) -> Any:
        loaded = await self.ensure_loaded(model_id, n_ctx=n_ctx)
        return await self._submit(
            loaded, kind="complete", payload={"prompt": prompt, **sampling}, stream=stream
        )

    async def preload(self, model_id: str) -> None:
        await self.ensure_loaded(model_id)

    async def force_unload(self, model_id: str) -> bool:
        loaded = self._loaded.get(model_id)
        if loaded is None:
            return False
        await self._unload(model_id, loaded)
        return True

    async def shutdown(self) -> None:
        self._closing = True
        for mid, loaded in list(self._loaded.items()):
            await self._unload(mid, loaded)

    # ----------------------------------------------------------------- private

    async def _load(self, entry: ModelEntry, n_ctx: int) -> _Loaded:
        _log.info("manager.loading", id=entry.id, n_ctx=n_ctx)
        encrypted_path = self._registry.storage_dir / entry.ciphertext_path
        # Decrypt-to-tmpfs, then mmap; tmpfs file is unlinked after open.
        t0 = time.monotonic()
        with decrypt_to_tmpfs(encrypted_path, self._tmpfs_dir, self._at_rest) as plain:
            backend = LlamaBackend(
                model_path=plain,
                n_ctx=n_ctx,
                n_gpu_layers=self._n_gpu_layers,
                n_threads=self._n_threads,
            )
        load_secs = time.monotonic() - t0
        model_load_seconds.labels(entry.id).observe(load_secs)
        model_loaded.labels(entry.id).set(1)
        loaded = _Loaded(
            entry=entry,
            backend=backend,
            n_ctx=n_ctx,
            last_used=time.monotonic(),
            queue=asyncio.Queue(maxsize=self._queue_depth),
        )
        loaded.worker_task = asyncio.create_task(
            self._worker_loop(loaded), name=f"infer:{entry.id}"
        )
        self._reset_idle(loaded)
        _log.info("manager.loaded", id=entry.id, load_seconds=round(load_secs, 3))
        return loaded

    async def _unload(self, model_id: str, loaded: _Loaded) -> None:
        _log.info("manager.unloading", id=model_id)
        loaded.state = "unloading"
        if loaded.idle_timer is not None:
            loaded.idle_timer.cancel()
            loaded.idle_timer = None
        # signal worker to stop after draining
        await loaded.queue.put(_SENTINEL_STOP)
        if loaded.worker_task is not None:
            try:
                await asyncio.wait_for(loaded.worker_task, timeout=30)
            except TimeoutError:
                loaded.worker_task.cancel()
        loaded.backend.close()
        self._loaded.pop(model_id, None)
        model_loaded.labels(model_id).set(0)
        inference_queue_depth.labels(model_id).set(0)
        _log.info("manager.unloaded", id=model_id)

    def _reset_idle(self, loaded: _Loaded) -> None:
        loop = self._loop or asyncio.get_running_loop()
        self._loop = loop
        if loaded.idle_timer is not None:
            loaded.idle_timer.cancel()
        loaded.idle_timer = loop.call_later(
            self._idle_timeout, lambda: asyncio.create_task(self._idle_offload(loaded))
        )

    async def _idle_offload(self, loaded: _Loaded) -> None:
        if self._closing or loaded.state != "loaded":
            return
        _log.info("manager.idle_offload", id=loaded.entry.id)
        await self._unload(loaded.entry.id, loaded)

    async def _submit(
        self, loaded: _Loaded, *, kind: str, payload: dict[str, Any], stream: bool
    ) -> Any:
        if loaded.queue.full():
            raise ManagerError(ErrorCode.QUEUE_FULL, loaded.entry.id)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        job = _Job(
            kind=kind, payload=payload, stream=stream, future=fut, cancel_event=asyncio.Event()
        )
        await loaded.queue.put(job)
        inference_queue_depth.labels(loaded.entry.id).set(loaded.queue.qsize())
        return await fut

    async def _worker_loop(self, loaded: _Loaded) -> None:
        while True:
            item = await loaded.queue.get()
            inference_queue_depth.labels(loaded.entry.id).set(loaded.queue.qsize())
            if item is _SENTINEL_STOP:
                return
            job: _Job = item
            try:
                if job.kind == "chat":
                    result = loaded.backend.chat(stream=job.stream, **job.payload)
                else:
                    result = loaded.backend.complete(stream=job.stream, **job.payload)
                if job.stream:
                    # Hand the iterator straight to the caller; they iterate
                    # synchronously off the worker thread via run_in_executor.
                    job.future.set_result(result)
                else:
                    job.future.set_result(result)
                loaded.last_used = time.monotonic()
                self._reset_idle(loaded)
            except Exception as e:
                loaded.last_error = str(e)[:200]
                if not job.future.done():
                    job.future.set_exception(e)
