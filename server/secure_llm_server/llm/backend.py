"""llama.cpp wrapper. Owns one ``Llama`` instance per loaded model.

``llama_cpp.Llama`` is not thread-safe; callers must hold the model's
:class:`asyncio.Lock` (managed by ModelManager) before invoking
:meth:`LlamaBackend.chat` or :meth:`LlamaBackend.complete`.
"""

from __future__ import annotations

import gc
import time
from pathlib import Path
from typing import Any

import structlog

_log = structlog.get_logger("secure_llm_server.llm.backend")


class LlamaBackend:
    def __init__(
        self,
        *,
        model_path: Path,
        n_ctx: int,
        n_gpu_layers: int,
        n_threads: int,
        seed: int | None = None,
        embedding: bool = False,
        lora_paths: tuple[tuple[Path, float], ...] = (),
        clip_model_path: Path | None = None,
    ) -> None:
        from llama_cpp import Llama  # local import — heavy

        t0 = time.monotonic()
        # llama-cpp-python v1 only accepts a single ``lora_path`` + ``lora_scale``
        # at construction (no public hot-swap). For now we stack at most one
        # adapter; multi-LoRA composition lands when the binding exposes the
        # multi-adapter API.
        lora_kwargs: dict[str, Any] = {}
        if lora_paths:
            head_path, head_scale = lora_paths[0]
            lora_kwargs["lora_path"] = str(head_path)
            lora_kwargs["lora_scale"] = float(head_scale)
        # v2.0: vision (Llava-style). The Llama binding accepts a
        # ``chat_handler`` for Llava-15. Pass clip path through via
        # ``clip_model_path`` so the manager can route image-bearing
        # chat messages here.
        vision_kwargs: dict[str, Any] = {}
        if clip_model_path is not None:
            vision_kwargs["clip_model_path"] = str(clip_model_path)
        self._llm = Llama(
            model_path=str(model_path),
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            n_threads=(n_threads or None),
            seed=seed if seed is not None else 0xC0FFEE,
            embedding=embedding,
            verbose=False,
            **lora_kwargs,
            **vision_kwargs,
        )
        self._embedding = embedding
        self._lora_paths = lora_paths
        self._clip_model_path = clip_model_path
        _log.info(
            "backend.loaded",
            path=str(model_path),
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            embedding=embedding,
            n_loras=len(lora_paths),
            multimodal=clip_model_path is not None,
            load_seconds=round(time.monotonic() - t0, 3),
        )

    @property
    def is_multimodal(self) -> bool:
        return self._clip_model_path is not None

    @property
    def embedding_mode(self) -> bool:
        return self._embedding

    def chat(
        self,
        *,
        messages: list[dict[str, str]],
        stream: bool,
        **sampling: Any,
    ) -> Any:
        return self._llm.create_chat_completion(messages=messages, stream=stream, **sampling)

    def complete(self, *, prompt: str, stream: bool, **sampling: Any) -> Any:
        return self._llm.create_completion(prompt=prompt, stream=stream, **sampling)

    def embed(self, *, inputs: str | list[str]) -> Any:
        return self._llm.create_embedding(input=inputs)

    def close(self) -> None:
        try:
            del self._llm
        finally:
            gc.collect()
            try:  # pragma: no cover — only fires on CUDA builds
                import torch  # type: ignore[import-not-found]

                torch.cuda.empty_cache()
            except Exception:
                pass
