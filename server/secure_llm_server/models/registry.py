"""On-disk catalog of encrypted model blobs and their metadata.

Layout (per tenant)::

    <storage_dir>/                          # default tenant
      <sha256-of-plaintext>.gguf.age
      <sha256-of-plaintext>.meta.json
    <storage_dir>/tenants/<tenant>/         # named tenants
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

DEFAULT_TENANT = "default"


def tenant_subdir(base: Path, tenant: str) -> Path:
    """Storage directory for *this* tenant.

    The default tenant keeps the legacy single-dir layout so existing v1.0/v1.1
    deployments don't have to move any files. Named tenants land under
    ``<base>/tenants/<tenant>``.
    """
    if tenant == DEFAULT_TENANT:
        return base
    return base / "tenants" / tenant


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
    tenant: str = DEFAULT_TENANT

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


# ---------------------------------------------------------------------------
# LoRA adapters
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LoraEntry:
    id: str
    sha256_plaintext: str
    repo_id: str
    filename: str
    bytes_plaintext: int
    bytes_ciphertext: int
    base_model_id: str | None = None
    downloaded_at: float = field(default_factory=lambda: time.time())

    @property
    def ciphertext_path(self) -> Path:
        return Path(f"{self.sha256_plaintext}.lora.gguf.age")

    @property
    def meta_path(self) -> Path:
        return Path(f"{self.sha256_plaintext}.lora.meta.json")


def write_lora_meta(dir_: Path, entry: LoraEntry) -> None:
    (dir_ / entry.meta_path).write_text(
        json.dumps(
            {
                "id": entry.id,
                "sha256": entry.sha256_plaintext,
                "repo_id": entry.repo_id,
                "filename": entry.filename,
                "bytes_plaintext": entry.bytes_plaintext,
                "bytes_ciphertext": entry.bytes_ciphertext,
                "base_model_id": entry.base_model_id,
                "downloaded_at": entry.downloaded_at,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_lora_meta(path: Path) -> LoraEntry:
    data = json.loads(path.read_text(encoding="utf-8"))
    return LoraEntry(
        id=data["id"],
        sha256_plaintext=data["sha256"],
        repo_id=data["repo_id"],
        filename=data["filename"],
        bytes_plaintext=int(data["bytes_plaintext"]),
        bytes_ciphertext=int(data["bytes_ciphertext"]),
        base_model_id=data.get("base_model_id"),
        downloaded_at=float(data.get("downloaded_at", time.time())),
    )


class LoraRegistry:
    """On-disk catalog of encrypted LoRA adapter blobs.

    Layout mirrors :class:`ModelRegistry` under a sibling ``loras/`` dir::

        <loras_dir>/
          <sha256>.lora.gguf.age
          <sha256>.lora.meta.json
    """

    def __init__(self, storage_dir: Path) -> None:
        self._dir = storage_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._by_id: dict[str, LoraEntry] = {}
        self._reload()

    @property
    def storage_dir(self) -> Path:
        return self._dir

    def _reload(self) -> None:
        self._by_id.clear()
        for meta in self._dir.glob("*.lora.meta.json"):
            try:
                entry = read_lora_meta(meta)
                self._by_id[entry.id] = entry
            except Exception:
                continue

    def all(self) -> list[LoraEntry]:
        return list(self._by_id.values())

    def get(self, id_: str) -> LoraEntry | None:
        return self._by_id.get(id_)

    def add(self, entry: LoraEntry) -> None:
        write_lora_meta(self._dir, entry)
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


# ---------------------------------------------------------------------------
# Multi-tenant factories
# ---------------------------------------------------------------------------


class MultiTenantRegistry:
    """Lazy factory returning a per-tenant :class:`ModelRegistry`.

    Each tenant gets its own subdirectory (see :func:`tenant_subdir`) and its
    own registry instance. Calling :meth:`for_tenant` is idempotent — repeat
    calls return the cached registry for that tenant.
    """

    def __init__(self, base_dir: Path) -> None:
        self._base = base_dir
        self._cache: dict[str, ModelRegistry] = {}

    @property
    def base_dir(self) -> Path:
        return self._base

    def for_tenant(self, tenant: str) -> ModelRegistry:
        reg = self._cache.get(tenant)
        if reg is None:
            reg = ModelRegistry(tenant_subdir(self._base, tenant))
            self._cache[tenant] = reg
        return reg

    def known_tenants(self) -> list[str]:
        """Tenants we've ever cached, plus any whose dir exists on disk."""
        seen = set(self._cache.keys())
        if self._base.exists() and any(self._base.glob("*.meta.json")):
            seen.add(DEFAULT_TENANT)
        tenants_dir = self._base / "tenants"
        if tenants_dir.is_dir():
            for sub in tenants_dir.iterdir():
                if sub.is_dir():
                    seen.add(sub.name)
        return sorted(seen)


class MultiTenantLoraRegistry:
    """Lazy factory returning a per-tenant :class:`LoraRegistry`."""

    def __init__(self, base_dir: Path) -> None:
        self._base = base_dir
        self._cache: dict[str, LoraRegistry] = {}

    @property
    def base_dir(self) -> Path:
        return self._base

    def for_tenant(self, tenant: str) -> LoraRegistry:
        reg = self._cache.get(tenant)
        if reg is None:
            reg = LoraRegistry(tenant_subdir(self._base, tenant))
            self._cache[tenant] = reg
        return reg
