"""Pydantic v2 request/response models. The plaintext-inside-the-envelope shape."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.version import PROTOCOL_VERSION


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


# ---- handshake (plaintext on the wire; only endpoint that is) ----


class HandshakeRequest(_Strict):
    protocol: str = Field(default=PROTOCOL_VERSION)
    client_static_pk: str  # base64
    client_ephemeral_pk: str
    timestamp: int  # unix seconds
    transcript_sig: str  # base64 Ed25519 sig over transcript

    server_host: str | None = None  # the hostname the client *thinks* it's talking to


class HandshakeResponse(_Strict):
    protocol: str = Field(default=PROTOCOL_VERSION)
    session_id: str  # base64, 16 bytes
    server_static_pk: str  # X25519 (used for the DH share)
    server_ed25519_pk: str  # Ed25519 (the actual pinned identity used for signature verify)
    server_ephemeral_pk: str
    ttl_seconds: int
    server_sig: str  # Ed25519 over full transcript
    nonce_prefix_c2s: str  # 4-byte hex, client→server direction
    nonce_prefix_s2c: str  # 4-byte hex, server→client direction


# ---- error envelope (plaintext-inside-envelope) ----


class ErrorEnvelope(_Strict):
    code: ErrorCode
    message: str = ""
    error_id: str | None = None  # cross-reference for /v1/admin/errors/{id}
    retry_after_seconds: float | None = None


# ---- chat / completions (OpenAI-compatible subset) ----

Role = Literal["system", "user", "assistant", "tool"]


class ChatMessage(_Strict):
    role: Role
    content: str
    name: str | None = None


SamplingFloat = Annotated[float, Field(ge=0.0, le=4.0)]


class _BaseGenerationParams(_Strict):
    model: str
    max_tokens: Annotated[int, Field(ge=1, le=32_768)] = 512
    temperature: SamplingFloat = 0.7
    top_p: Annotated[float, Field(ge=0.0, le=1.0)] = 0.95
    top_k: Annotated[int, Field(ge=0, le=4096)] = 40
    repeat_penalty: Annotated[float, Field(ge=0.0, le=4.0)] = 1.1
    presence_penalty: Annotated[float, Field(ge=-2.0, le=2.0)] = 0.0
    frequency_penalty: Annotated[float, Field(ge=-2.0, le=2.0)] = 0.0
    seed: int | None = None
    stop: list[str] = Field(default_factory=list)
    stream: bool = False
    n_ctx: Annotated[int, Field(ge=128, le=131_072)] | None = None


class ChatCompletionRequest(_BaseGenerationParams):
    messages: list[ChatMessage] = Field(min_length=1)


class CompletionRequest(_BaseGenerationParams):
    prompt: str


class _ChoiceMessage(_Strict):
    role: Role
    content: str


class _Choice(_Strict):
    index: int
    message: _ChoiceMessage
    finish_reason: Literal["stop", "length", "cancelled", "error"]


class _Usage(_Strict):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(_Strict):
    id: str
    model: str
    created: int
    choices: list[_Choice]
    usage: _Usage


class _ChunkDelta(_Strict):
    role: Role | None = None
    content: str | None = None


class _ChunkChoice(_Strict):
    index: int
    delta: _ChunkDelta
    finish_reason: Literal["stop", "length", "cancelled", "error"] | None = None


class ChatCompletionChunk(_Strict):
    id: str
    model: str
    created: int
    choices: list[_ChunkChoice]


class CompletionResponse(_Strict):
    id: str
    model: str
    created: int
    text: str
    finish_reason: Literal["stop", "length", "cancelled", "error"]
    usage: _Usage


# ---- models ----

ModelState = Literal[
    "absent",
    "downloading",
    "present",
    "loading",
    "loaded",
    "unloading",
    "error",
]


class ModelInfo(_Strict):
    id: str
    repo_id: str | None = None
    filename: str | None = None
    state: ModelState
    bytes_on_disk: int = 0
    sha256: str | None = None
    n_ctx_max: int | None = None
    last_used_at: float | None = None
    queue_depth: int = 0
    last_error: str | None = None


class ModelList(_Strict):
    models: list[ModelInfo]


class ModelDownloadRequest(_Strict):
    repo_id: str
    filename: str
    sha256: str | None = None  # if provided, downloader verifies


# ---- system / debug / admin ----


class SystemStatus(_Strict):
    cpu_percent: float
    ram_total_bytes: int
    ram_available_bytes: int
    disk_total_bytes: int
    disk_free_bytes: int
    gpu: list[dict[str, Any]] = Field(default_factory=list)
    loaded_models: list[str] = Field(default_factory=list)
    queue_depths: dict[str, int] = Field(default_factory=dict)
    uptime_seconds: float = 0.0


class LogEntry(_Strict):
    ts: float
    level: str
    component: str
    event: str
    fields: dict[str, Any] = Field(default_factory=dict)


class DebugStatus(_Strict):
    protocol_version: str = PROTOCOL_VERSION
    server_version: str
    build_sha: str | None = None
    uptime_seconds: float
    system: SystemStatus
    loaded_models: list[ModelInfo]
    recent_errors: list[dict[str, Any]] = Field(default_factory=list)
    recent_logs: list[LogEntry] = Field(default_factory=list)


class DoctorStep(_Strict):
    name: str
    status: Literal["ok", "fix", "skip", "fail", "warn"]
    detail: str = ""


class DoctorReport(_Strict):
    overall: Literal["ok", "warn", "fail"]
    steps: list[DoctorStep]


class AdminSessionInfo(_Strict):
    session_id: str
    client_fingerprint: str
    scopes: list[str]
    created_at: float
    last_used_at: float
    ttl_seconds: int


class AdminClientInfo(_Strict):
    name: str
    fingerprint: str
    scopes: list[str]
    revoked: bool
    not_before: int | None = None
    not_after: int | None = None
