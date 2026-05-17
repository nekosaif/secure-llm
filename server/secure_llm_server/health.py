"""Liveness/readiness probe helpers; plain HTTP, no envelope."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Readiness:
    config_loaded: bool = False
    keystore_loaded: bool = False
    storage_dir_writable: bool = False

    @property
    def ok(self) -> bool:
        return self.config_loaded and self.keystore_loaded and self.storage_dir_writable

    def check_storage(self, path: Path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
            test = path / ".rw_check"
            test.write_bytes(b"x")
            test.unlink()
            self.storage_dir_writable = True
        except Exception:
            self.storage_dir_writable = False
