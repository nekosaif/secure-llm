"""On-disk catalog of encrypted model blobs and their metadata.

Layout::

    <storage_dir>/
      <sha256-of-plaintext>.gguf.age
      <sha256-of-plaintext>.meta.json

Metadata is non-secret (repo, filename, sizes, ctx, layers). The ``id`` clients
use is the filename without ``.gguf``, normalized.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ModelEntry:
    id: str
    sha256_plaintext: str
    repo_id: str
    filename: str
    bytes_plaintext: int
    bytes_ciphertext: int
    n_ctx_max: int | None = None
    downloaded_at: float = field(default_factory=lambda: time.time())

    @property
    def ciphertext_path(self) -> Path:
        return Path(f"{self.sha256_plaintext}.gguf.age")

    @property
    def meta_path(self) -> Path:
        return Path(f"{self.sha256_plaintext}.meta.json")


def normalize_id(filename: str) -> str:
    base = Path(filename).stem
    return base.replace(" ", "_")


def write_meta(dir_: Path, entry: ModelEntry) -> None:
    (dir_ / entry.meta_path).write_text(
        json.dumps(
            {
                "id": entry.id,
                "sha256": entry.sha256_plaintext,
                "repo_id": entry.repo_id,
                "filename": entry.filename,
                "bytes_plaintext": entry.bytes_plaintext,
                "bytes_ciphertext": entry.bytes_ciphertext,
                "n_ctx_max": entry.n_ctx_max,
                "downloaded_at": entry.downloaded_at,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_meta(path: Path) -> ModelEntry:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ModelEntry(
        id=data["id"],
        sha256_plaintext=data["sha256"],
        repo_id=data["repo_id"],
        filename=data["filename"],
        bytes_plaintext=int(data["bytes_plaintext"]),
        bytes_ciphertext=int(data["bytes_ciphertext"]),
        n_ctx_max=data.get("n_ctx_max"),
        downloaded_at=float(data.get("downloaded_at", time.time())),
    )


class ModelRegistry:
    def __init__(self, storage_dir: Path) -> None:
        self._dir = storage_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._by_id: dict[str, ModelEntry] = {}
        self._reload()

    @property
    def storage_dir(self) -> Path:
        return self._dir

    def _reload(self) -> None:
        self._by_id.clear()
        for meta in self._dir.glob("*.meta.json"):
            try:
                entry = read_meta(meta)
                self._by_id[entry.id] = entry
            except Exception:
                # corrupt sidecar — skip but don't fail the whole boot
                continue

    def all(self) -> list[ModelEntry]:
        return list(self._by_id.values())

    def get(self, id_: str) -> ModelEntry | None:
        return self._by_id.get(id_)

    def add(self, entry: ModelEntry) -> None:
        write_meta(self._dir, entry)
        self._by_id[entry.id] = entry

    def remove(self, id_: str) -> bool:
        entry = self._by_id.pop(id_, None)
        if entry is None:
            return False
        for p in (entry.ciphertext_path, entry.meta_path):
            try:
                (self._dir / p).unlink()
            except FileNotFoundError:
                pass
        return True


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
