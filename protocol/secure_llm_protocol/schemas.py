"""Pydantic v2 request/response models. The plaintext-inside-the-envelope shape."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.version import PROTOCOL_VERSION


class _Strict(BaseModel):
    # ``str_strip_whitespace`` is intentionally NOT set: chat/completion
    # content payloads carry meaningful whitespace (leading/trailing newlines
    # in prompts, multi-token deltas like " the ") and stripping them mangles
    # streaming output.
    model_config = ConfigDict(extra="forbid", frozen=True)


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
    # v2.0: optional TEE attestation report (base64). The report's
    # userdata field equals SHA-256(full_handshake_transcript) so a
    # captured report cannot be detached and replayed against a
    # different transcript. ``None`` means the server is not running
    # under attestation — clients with attestation_required=true in
    # known_hosts.toml refuse such handshakes.
    attestation_report: str | None = None


# ---- error envelope (plaintext-inside-envelope) ----


class ErrorEnvelope(_Strict):
    code: ErrorCode
    message: str = ""
    error_id: str | None = None  # cross-reference for /v1/admin/errors/{id}
    retry_after_seconds: float | None = None


# ---- chat / completions (OpenAI-compatible subset) ----

Role = Literal["system", "user", "assistant", "tool"]


class TextContentPart(_Strict):
    """OpenAI-shape text content part."""

    type: Literal["text"] = "text"
    text: str


class ImageUrlPayload(_Strict):
    """OpenAI-shape image url payload.

    Accepts either a ``data:image/...;base64,...`` URL or an ``https://``
    URL. The server side only honors ``data:`` URIs in v2.0 — remote URLs
    require an outbound network egress that the server explicitly refuses
    (would let a prompt exfiltrate via DNS / GET).
    """

    url: str
    detail: Literal["auto", "low", "high"] = "auto"


class ImageContentPart(_Strict):
    """OpenAI-shape image content part."""

    type: Literal["image_url"] = "image_url"
    image_url: ImageUrlPayload


# Union of allowed part shapes. ``Annotated[..., Field(discriminator="type")]``
# keeps pydantic from probing each branch.
ChatContentPart = Annotated[
    TextContentPart | ImageContentPart,
    Field(discriminator="type"),
]


class ChatMessage(_Strict):
    role: Role
    # v2.0 widens ``content`` to either a plain string (the v1.x shape,
    # still the common case) or an OpenAI-shape list of parts mixing
    # text and image_url entries. The server enforces that image parts
    # are only honored against a model whose registry entry has a
    # ``clip_companion`` set.
    content: str | list[ChatContentPart]
    name: str | None = None


SamplingFloat = Annotated[float, Field(ge=0.0, le=4.0)]


class LoraRef(_Strict):
    """A LoRA adapter the caller wants stacked on the base model for this request."""

    id: str
    scale: Annotated[float, Field(ge=-2.0, le=2.0)] = 1.0


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
    loras: list[LoraRef] = Field(default_factory=list)


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


# ---- embeddings (OpenAI-compatible subset) ----


class EmbeddingsRequest(_Strict):
    model: str
    input: str | list[str]


class _EmbeddingDatum(_Strict):
    index: int
    embedding: list[float]


class _EmbeddingsUsage(_Strict):
    prompt_tokens: int
    total_tokens: int


class EmbeddingsResponse(_Strict):
    id: str
    model: str
    created: int
    data: list[_EmbeddingDatum]
    usage: _EmbeddingsUsage


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


# ---- LoRA adapters ----


class LoraInfo(_Strict):
    id: str
    repo_id: str
    filename: str
    sha256: str
    bytes_on_disk: int
    base_model_id: str | None = None


class LoraList(_Strict):
    loras: list[LoraInfo]


class LoraDownloadRequest(_Strict):
    repo_id: str
    filename: str
    sha256: str | None = None
    base_model_id: str | None = None


class LoraApplyRequest(_Strict):
    """Eagerly load a base model with these adapters stacked, ready for inference."""

    base_model_id: str
    loras: list[LoraRef] = Field(default_factory=list)
    n_ctx: Annotated[int, Field(ge=128, le=131_072)] | None = None


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
