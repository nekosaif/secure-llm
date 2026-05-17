"""Pull GGUF files from Hugging Face, SHA-256 verify, encrypt-on-write."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import structlog
from huggingface_hub import hf_hub_download  # type: ignore[import-untyped]

from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.crypto.at_rest import AtRestKey, encrypt_file
from secure_llm_server.models.registry import (
    ModelEntry,
    ModelRegistry,
    normalize_id,
    sha256_file,
)

_log = structlog.get_logger("secure_llm_server.models.downloader")


class DownloadError(Exception):
    def __init__(self, code: ErrorCode, message: str = "") -> None:
        super().__init__(message or code.value)
        self.code = code


def _check_repo_allowed(repo_id: str, prefixes: list[str]) -> None:
    if not prefixes:
        return
    if not any(repo_id.startswith(p) for p in prefixes):
        raise DownloadError(
            ErrorCode.REPO_NOT_ALLOWED,
            f"repo {repo_id!r} is not in the allowed list",
        )


def _check_disk_quota(dst_dir: Path, quota_gb: int, incoming_bytes: int) -> None:
    used = sum(p.stat().st_size for p in dst_dir.glob("*.gguf.age"))
    quota = quota_gb * (1 << 30)
    if used + incoming_bytes > quota:
        raise DownloadError(
            ErrorCode.DISK_QUOTA_EXCEEDED,
            f"would exceed {quota_gb} GiB quota",
        )


def download_and_seal(
    *,
    repo_id: str,
    filename: str,
    expected_sha256: str | None,
    registry: ModelRegistry,
    at_rest: AtRestKey,
    allowed_repo_prefixes: list[str],
    disk_quota_gb: int,
) -> ModelEntry:
    _check_repo_allowed(repo_id, allowed_repo_prefixes)

    with tempfile.TemporaryDirectory(prefix="sllm-dl-") as scratch:
        scratch_path = Path(scratch)
        _log.info("download.start", repo_id=repo_id, filename=filename)
        try:
            local = Path(
                hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                    local_dir=str(scratch_path),
                    local_dir_use_symlinks=False,
                )
            )
        except Exception as e:
            _log.warning("download.failed", repo_id=repo_id, filename=filename, err=str(e))
            raise DownloadError(ErrorCode.DOWNLOAD_FAILED, str(e)) from e

        plaintext_bytes = local.stat().st_size
        _check_disk_quota(registry.storage_dir, disk_quota_gb, plaintext_bytes)

        sha = sha256_file(local)
        if expected_sha256 and sha.lower() != expected_sha256.lower():
            _log.warning("download.sha_mismatch", expected=expected_sha256, got=sha)
            raise DownloadError(ErrorCode.SHA256_MISMATCH)

        encrypted_name = f"{sha}.gguf.age"
        encrypted_path = registry.storage_dir / encrypted_name
        _log.info("download.encrypt", sha=sha)
        encrypt_file(local, encrypted_path, at_rest)
        ciphertext_bytes = encrypted_path.stat().st_size

        entry = ModelEntry(
            id=normalize_id(filename),
            sha256_plaintext=sha,
            repo_id=repo_id,
            filename=filename,
            bytes_plaintext=plaintext_bytes,
            bytes_ciphertext=ciphertext_bytes,
        )
        registry.add(entry)

        # scrub the plaintext download
        try:
            shutil.rmtree(scratch_path, ignore_errors=True)
        except Exception:
            pass

    _log.info("download.done", id=entry.id, bytes=ciphertext_bytes)
    return entry
