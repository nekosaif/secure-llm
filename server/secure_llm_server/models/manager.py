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
from secure_llm_server.models.registry import (
    DEFAULT_TENANT,
    LoraRegistry,
    ModelEntry,
    ModelRegistry,
    MultiTenantLoraRegistry,
    MultiTenantRegistry,
)

LoraSpec = tuple[tuple[str, float], ...]
"""Tuple of ``(lora_id, scale)`` pairs. Order matters; sort for cache fingerprints."""

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
    cache_key: str = ""
    state: ModelState = "loaded"
    queue: asyncio.Queue[Any] = field(default_factory=lambda: asyncio.Queue(maxsize=8))
    worker_task: asyncio.Task[None] | None = None
    idle_timer: asyncio.TimerHandle | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_error: str | None = None


_SENTINEL_STOP = object()
_STREAM_DONE = object()


class StreamHandle:
    """Async iterator the worker uses to hand streamed chunks back to a router.

    The worker is the sole task touching the underlying ``llama_cpp.Llama``
    instance; it iterates the generator off-thread via :func:`asyncio.to_thread`
    and pushes each chunk into ``_queue``. The consumer (router) iterates
    asynchronously; backpressure comes from ``_queue``'s bounded size.

    Setting :attr:`cancel_event` from the consumer signals the worker to break
    out of its iteration loop on the next chunk boundary.
    """

    __slots__ = ("_queue", "cancel_event", "error")

    def __init__(self, *, maxsize: int = 64) -> None:
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=maxsize)
        self.cancel_event = asyncio.Event()
        self.error: BaseException | None = None

    def __aiter__(self) -> StreamHandle:
        return self

    async def __anext__(self) -> dict[str, Any]:
        item = await self._queue.get()
        if item is _STREAM_DONE:
            if self.error is not None:
                raise self.error
            raise StopAsyncIteration
        return item  # type: ignore[no-any-return]

    def cancel(self) -> None:
        self.cancel_event.set()


@dataclass(slots=True)
class _Job:
    kind: str  # "chat", "complete", or "embed"
    payload: dict[str, Any]
    stream: bool
    future: asyncio.Future[Any]
    cancel_event: asyncio.Event
    stream_handle: StreamHandle | None = None


class ModelManager:
    def __init__(
        self,
        *,
        registry: ModelRegistry | MultiTenantRegistry,
        at_rest: AtRestKey,
        tmpfs_dir: Path,
        max_loaded: int,
        idle_timeout_seconds: int,
        n_gpu_layers: int,
        n_threads: int,
        n_ctx_default: int,
        queue_depth: int,
        lora_registry: LoraRegistry | MultiTenantLoraRegistry | None = None,
    ) -> None:
        # Accept either a single registry (legacy single-tenant tests) or a
        # multi-tenant factory. Internally we always go through ``_registry_for``
        # / ``_lora_registry_for`` so the per-tenant lookup is uniform.
        self._mt_models = registry if isinstance(registry, MultiTenantRegistry) else None
        self._single_models = registry if isinstance(registry, ModelRegistry) else None
        self._mt_loras = (
            lora_registry if isinstance(lora_registry, MultiTenantLoraRegistry) else None
        )
        self._single_loras = lora_registry if isinstance(lora_registry, LoraRegistry) else None
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

    def _registry_for(self, tenant: str) -> ModelRegistry:
        if self._mt_models is not None:
            return self._mt_models.for_tenant(tenant)
        assert self._single_models is not None
        return self._single_models

    def _lora_registry_for(self, tenant: str) -> LoraRegistry | None:
        if self._mt_loras is not None:
            return self._mt_loras.for_tenant(tenant)
        return self._single_loras

    @property
    def lora_registry(self) -> LoraRegistry | None:
        """Default-tenant LoRA registry (preserved for backward-compat callers)."""
        return self._lora_registry_for(DEFAULT_TENANT)

    @staticmethod
    def _lora_fingerprint(loras: LoraSpec) -> str:
        if not loras:
            return ""
        return "+".join(f"{lid}@{scale:.4f}" for lid, scale in sorted(loras))

    # ------------------------------------------------------------------ public

    def snapshot(self, *, tenant: str = DEFAULT_TENANT) -> list[ModelInfo]:
        out: list[ModelInfo] = []
        registry = self._registry_for(tenant)
        prefix = f"{tenant}:"
        for entry in registry.all():
            # Find any loaded slot that matches this tenant+model regardless
            # of mode/lora — for the snapshot we only report top-level state.
            loaded: _Loaded | None = None
            for key, cand in self._loaded.items():
                if key.startswith(f"{prefix}{entry.id}:") and cand.entry.id == entry.id:
                    loaded = cand
                    break
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

    async def ensure_loaded(
        self,
        model_id: str,
        *,
        n_ctx: int | None = None,
        mode: str = "chat",
        loras: LoraSpec = (),
        tenant: str = DEFAULT_TENANT,
    ) -> _Loaded:
        registry = self._registry_for(tenant)
        entry = registry.get(model_id)
        if entry is None:
            raise ManagerError(ErrorCode.MODEL_NOT_FOUND, model_id)
        lora_fp = self._lora_fingerprint(loras)
        cache_key = f"{tenant}:{model_id}:{mode}:{lora_fp}"
        # Fast path: already loaded with compatible ctx + same LoRA set.
        loaded = self._loaded.get(cache_key)
        if loaded is not None and (n_ctx is None or n_ctx <= loaded.n_ctx):
            self._loaded.move_to_end(cache_key)
            self._reset_idle(loaded)
            return loaded

        # Validate LoRA ids before we evict anything.
        lora_reg = self._lora_registry_for(tenant)
        if loras and lora_reg is None:
            raise ManagerError(ErrorCode.BAD_REQUEST, "LoRA support not configured on server")
        for lid, _scale in loras:
            if lora_reg is None or lora_reg.get(lid) is None:
                raise ManagerError(ErrorCode.MODEL_NOT_FOUND, f"lora:{lid}")

        lock = self._load_locks.setdefault(cache_key, asyncio.Lock())
        async with lock:
            loaded = self._loaded.get(cache_key)
            if loaded is not None and (n_ctx is None or n_ctx <= loaded.n_ctx):
                self._reset_idle(loaded)
                return loaded
            # Evict LRU if necessary.
            while len(self._loaded) >= self._max_loaded:
                victim_id, victim = next(iter(self._loaded.items()))
                _log.info("manager.evict", id=victim_id)
                await self._unload(victim_id, victim)
            loaded = await self._load(
                entry,
                n_ctx or self._n_ctx_default,
                cache_key=cache_key,
                mode=mode,
                loras=loras,
                tenant=tenant,
            )
            self._loaded[cache_key] = loaded
            return loaded

    async def chat(
        self,
        *,
        model_id: str,
        n_ctx: int | None,
        messages: list[dict[str, str]],
        stream: bool,
        loras: LoraSpec = (),
        tenant: str = DEFAULT_TENANT,
        **sampling: Any,
    ) -> Any:
        loaded = await self.ensure_loaded(
            model_id, n_ctx=n_ctx, mode="chat", loras=loras, tenant=tenant
        )
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
        loras: LoraSpec = (),
        tenant: str = DEFAULT_TENANT,
        **sampling: Any,
    ) -> Any:
        loaded = await self.ensure_loaded(
            model_id, n_ctx=n_ctx, mode="chat", loras=loras, tenant=tenant
        )
        return await self._submit(
            loaded, kind="complete", payload={"prompt": prompt, **sampling}, stream=stream
        )

    async def embed(
        self,
        *,
        model_id: str,
        inputs: str | list[str],
        tenant: str = DEFAULT_TENANT,
    ) -> Any:
        loaded = await self.ensure_loaded(model_id, mode="embedding", tenant=tenant)
        return await self._submit(loaded, kind="embed", payload={"inputs": inputs}, stream=False)

    async def preload(self, model_id: str, *, tenant: str = DEFAULT_TENANT) -> None:
        await self.ensure_loaded(model_id, tenant=tenant)

    async def force_unload(self, model_id: str, *, tenant: str = DEFAULT_TENANT) -> bool:
        """Drop every loaded slot for ``(tenant, model_id)`` regardless of mode/LoRA set."""
        prefix = f"{tenant}:{model_id}:"
        targets = [(k, v) for k, v in self._loaded.items() if k.startswith(prefix)]
        if not targets:
            return False
        for cache_key, loaded in targets:
            await self._unload(cache_key, loaded)
        return True

    async def shutdown(self) -> None:
        self._closing = True
        for mid, loaded in list(self._loaded.items()):
            await self._unload(mid, loaded)

    # ----------------------------------------------------------------- private

    async def _load(
        self,
        entry: ModelEntry,
        n_ctx: int,
        *,
        cache_key: str = "",
        mode: str = "chat",
        loras: LoraSpec = (),
        tenant: str = DEFAULT_TENANT,
    ) -> _Loaded:
        _log.info(
            "manager.loading",
            id=entry.id,
            tenant=tenant,
            n_ctx=n_ctx,
            mode=mode,
            n_loras=len(loras),
        )
        registry = self._registry_for(tenant)
        lora_reg = self._lora_registry_for(tenant)
        encrypted_path = registry.storage_dir / entry.ciphertext_path
        # Decrypt model + every LoRA into tmpfs simultaneously; all files are
        # mmap-bound by Llama() inside the with-block and then unlinked.
        from contextlib import ExitStack

        t0 = time.monotonic()
        with ExitStack() as stack:
            plain = stack.enter_context(
                decrypt_to_tmpfs(encrypted_path, self._tmpfs_dir, self._at_rest)
            )
            lora_paths: list[tuple[Path, float]] = []
            for lid, scale in loras:
                # Validated up in ensure_loaded; lora_registry is non-None here.
                assert lora_reg is not None
                lentry = lora_reg.get(lid)
                assert lentry is not None
                lora_blob = lora_reg.storage_dir / lentry.ciphertext_path
                lpath = stack.enter_context(
                    decrypt_to_tmpfs(lora_blob, self._tmpfs_dir, self._at_rest)
                )
                lora_paths.append((lpath, float(scale)))
            backend = LlamaBackend(
                model_path=plain,
                n_ctx=n_ctx,
                n_gpu_layers=self._n_gpu_layers,
                n_threads=self._n_threads,
                embedding=(mode == "embedding"),
                lora_paths=tuple(lora_paths),
            )
        load_secs = time.monotonic() - t0
        model_load_seconds.labels(entry.id).observe(load_secs)
        model_loaded.labels(entry.id).set(1)
        loaded = _Loaded(
            entry=entry,
            backend=backend,
            n_ctx=n_ctx,
            last_used=time.monotonic(),
            cache_key=cache_key,
            queue=asyncio.Queue(maxsize=self._queue_depth),
        )
        slot_name = f"{entry.id}:{mode}"
        if loras:
            slot_name = f"{slot_name}:{self._lora_fingerprint(loras)}"
        loaded.worker_task = asyncio.create_task(
            self._worker_loop(loaded), name=f"infer:{slot_name}"
        )
        self._reset_idle(loaded)
        _log.info(
            "manager.loaded",
            id=entry.id,
            mode=mode,
            n_loras=len(loras),
            load_seconds=round(load_secs, 3),
        )
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
        await self._unload(loaded.cache_key, loaded)

    async def _submit(
        self, loaded: _Loaded, *, kind: str, payload: dict[str, Any], stream: bool
    ) -> Any:
        if loaded.queue.full():
            raise ManagerError(ErrorCode.QUEUE_FULL, loaded.entry.id)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        handle = StreamHandle() if stream else None
        job = _Job(
            kind=kind,
            payload=payload,
            stream=stream,
            future=fut,
            cancel_event=asyncio.Event() if not stream else handle.cancel_event,  # type: ignore[union-attr]
            stream_handle=handle,
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
                if job.kind == "embed":
                    result = loaded.backend.embed(**job.payload)
                    job.future.set_result(result)
                    loaded.last_used = time.monotonic()
                    self._reset_idle(loaded)
                    continue
                if job.kind == "chat":
                    result = loaded.backend.chat(stream=job.stream, **job.payload)
                else:
                    result = loaded.backend.complete(stream=job.stream, **job.payload)

                if not job.stream:
                    job.future.set_result(result)
                    loaded.last_used = time.monotonic()
                    self._reset_idle(loaded)
                    continue

                # Streaming: the worker is the sole task touching this Llama
                # instance, so it must drain the generator itself. Hand the
                # StreamHandle to the caller immediately; then pump chunks
                # via asyncio.to_thread so the event loop stays responsive.
                handle = job.stream_handle
                assert handle is not None
                job.future.set_result(handle)
                generator = result  # llama-cpp returns a sync generator
                try:
                    while not handle.cancel_event.is_set():
                        chunk = await asyncio.to_thread(next, generator, _STREAM_DONE)
                        if chunk is _STREAM_DONE:
                            break
                        await handle._queue.put(chunk)
                except Exception as e:
                    handle.error = e
                    loaded.last_error = str(e)[:200]
                finally:
                    await handle._queue.put(_STREAM_DONE)
                    loaded.last_used = time.monotonic()
                    self._reset_idle(loaded)
            except Exception as e:
                loaded.last_error = str(e)[:200]
                if not job.future.done():
                    job.future.set_exception(e)
