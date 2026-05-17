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
    ) -> None:
        from llama_cpp import Llama  # local import — heavy

        t0 = time.monotonic()
        self._llm = Llama(
            model_path=str(model_path),
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            n_threads=(n_threads or None),
            seed=seed if seed is not None else 0xC0FFEE,
            verbose=False,
        )
        _log.info(
            "backend.loaded",
            path=str(model_path),
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            load_seconds=round(time.monotonic() - t0, 3),
        )

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
