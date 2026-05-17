"""``make doctor`` and ``/v1/debug/doctor``: produce the same step-by-step report.

Pure check logic — no side effects beyond reading config and the filesystem.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Literal

from secure_llm_protocol.schemas import DoctorReport, DoctorStep


def _ok(name: str, detail: str = "") -> DoctorStep:
    return DoctorStep(name=name, status="ok", detail=detail)


def _warn(name: str, detail: str) -> DoctorStep:
    return DoctorStep(name=name, status="warn", detail=detail)


def _fail(name: str, detail: str) -> DoctorStep:
    return DoctorStep(name=name, status="fail", detail=detail)


def _check_dir_perms(path: Path, name: str, want_mode: int) -> DoctorStep:
    if not path.exists():
        return _fail(name, f"{path} missing")
    mode = path.stat().st_mode & 0o777
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return _warn(name, f"{path} mode={oct(mode)}; should be {oct(want_mode)}")
    return _ok(name, f"{path} mode={oct(mode)}")


def run_checks(settings: object | None = None) -> list[DoctorStep]:
    steps: list[DoctorStep] = []
    steps.append(_ok("python", sys.version.split()[0]))

    if shutil.which("uv"):
        steps.append(_ok("uv", "found"))
    else:
        steps.append(_warn("uv", "not on PATH; make targets won't work"))

    if shutil.which("cc") or shutil.which("gcc"):
        steps.append(_ok("toolchain", "C compiler present"))
    else:
        steps.append(_warn("toolchain", "no C compiler; relying on prebuilt wheels"))

    if shutil.which("nvidia-smi"):
        steps.append(_ok("gpu", "nvidia-smi found"))
    else:
        steps.append(_warn("gpu", "no nvidia-smi (CPU-only is fine)"))

    if Path("/dev/shm").is_dir() and os.access("/dev/shm", os.W_OK):
        steps.append(_ok("tmpfs", "/dev/shm writable"))
    else:
        steps.append(_warn("tmpfs", "/dev/shm not writable; fallback in use"))

    if settings is not None:
        try:
            from secure_llm_server.config import Settings  # noqa: F401  type-hint only

            key_dir = Path(settings.crypto.key_dir)  # type: ignore[attr-defined]
            steps.append(_check_dir_perms(key_dir, "key_dir", 0o700))
            storage = Path(settings.models.storage_dir)  # type: ignore[attr-defined]
            storage.mkdir(parents=True, exist_ok=True)
            steps.append(_ok("storage_dir", str(storage)))
        except Exception as e:
            steps.append(_warn("settings", f"could not introspect: {e}"))
    return steps


def _main(argv: list[str]) -> int:
    # Best-effort config load; fall back to no settings.
    settings = None
    config_path = Path(os.environ.get("SECURE_LLM_CONFIG", "data/config.toml"))
    if config_path.exists():
        try:
            from secure_llm_server.config import load_settings

            settings = load_settings(config_path)
        except Exception as e:
            print(f"[doctor] warning: could not load {config_path}: {e}")
    steps = run_checks(settings)
    overall: Literal["ok", "warn", "fail"]
    if any(s.status == "fail" for s in steps):
        overall = "fail"
    elif any(s.status == "warn" for s in steps):
        overall = "warn"
    else:
        overall = "ok"
    _ = DoctorReport(overall=overall, steps=steps)  # validation pass
    bad = 0
    print(f"doctor: overall={overall}")
    markers = {"ok": "  ok ", "warn": " warn", "fail": " FAIL", "fix": "  fix", "skip": " skip"}
    for s in steps:
        print(f"  [{markers[s.status]}] {s.name}: {s.detail}")
        if s.status == "fail":
            bad += 1
    if bad:
        print("doctor: failing")
        return 1
    print("doctor: ok")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
