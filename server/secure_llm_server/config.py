"""Server configuration: TOML file + env overrides via pydantic-settings.

Boot will fail (loudly, before any port is bound) if the config can't be
loaded or if any required path has bad permissions. Fail-closed by design.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSection(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8443
    shutdown_grace_seconds: int = 30
    workers: int = 1


class TLSSection(BaseSettings):
    cert_file: Path
    key_file: Path
    min_version: str = "TLSv1.3"


class CryptoSection(BaseSettings):
    key_dir: Path
    authorized_clients: Path
    session_ttl_seconds: int = 3600
    session_max_lifetime_seconds: int = 28_800
    handshake_skew_seconds: int = 30


class ModelsSection(BaseSettings):
    storage_dir: Path
    tmpfs_dir: Path
    max_loaded: int = 1
    idle_timeout_seconds: int = 300
    disk_quota_gb: int = 200
    allow_download: bool = True
    allowed_repo_prefixes: list[str] = Field(default_factory=list)


class InferenceSection(BaseSettings):
    n_gpu_layers: int = 0
    n_threads: int = 0
    n_ctx_default: int = 2048
    queue_depth_per_model: int = 8
    max_tokens_hard_cap: int = 2048


class LimitsSection(BaseSettings):
    max_request_bytes: int = 8 * 1024 * 1024
    max_response_stream_bytes: int = 64 * 1024 * 1024
    rate_limit_rpm_per_client: int = 120
    slowloris_header_timeout_seconds: int = 10


class ObservabilitySection(BaseSettings):
    log_level: str = "INFO"
    log_format: str = "json"
    log_dir: Path | None = None
    metrics_enabled: bool = True
    metrics_bind: str = "127.0.0.1:9090"
    ring_buffer_size: int = 10_000
    error_buffer_size: int = 1_000

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURE_LLM_", env_nested_delimiter="__")

    server: ServerSection
    tls: TLSSection
    crypto: CryptoSection
    models: ModelsSection
    inference: InferenceSection
    limits: LimitsSection = Field(default_factory=LimitsSection)
    observability: ObservabilitySection = Field(default_factory=ObservabilitySection)


def load_settings(path: Path) -> Settings:
    with path.open("rb") as f:
        raw: dict[str, Any] = tomllib.load(f)
    # Resolve any relative paths against the config file's parent.
    base = path.parent.resolve()

    def _resolve(d: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in d.items():
            if isinstance(v, str) and (
                k.endswith("_file") or k.endswith("_dir") or k == "authorized_clients"
            ):
                p = Path(v)
                if not p.is_absolute():
                    p = (base / p).resolve()
                out[k] = p
            else:
                out[k] = v
        return out

    raw = {
        section: _resolve(body) if isinstance(body, dict) else body for section, body in raw.items()
    }
    return Settings(**raw)
