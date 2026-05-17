"""System metrics: CPU/RAM/disk via psutil, optional GPU via pynvml."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import psutil

try:
    import pynvml  # type: ignore[import-untyped]

    pynvml.nvmlInit()
    _NVML_OK = True
except Exception:
    _NVML_OK = False


def cpu_percent() -> float:
    return psutil.cpu_percent(interval=None)


def ram() -> tuple[int, int]:
    m = psutil.virtual_memory()
    return m.total, m.available


def disk(path: Path) -> tuple[int, int]:
    u = shutil.disk_usage(path)
    return u.total, u.free


def gpus() -> list[dict[str, Any]]:
    if not _NVML_OK:
        return []
    out: list[dict[str, Any]] = []
    try:
        n = pynvml.nvmlDeviceGetCount()
        for i in range(n):
            h = pynvml.nvmlDeviceGetHandleByIndex(i)
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)
            util = pynvml.nvmlDeviceGetUtilizationRates(h)
            out.append(
                {
                    "index": i,
                    "name": pynvml.nvmlDeviceGetName(h),
                    "mem_total": int(mem.total),
                    "mem_used": int(mem.used),
                    "util_gpu": int(util.gpu),
                    "util_mem": int(util.memory),
                }
            )
    except Exception:
        return out
    return out
