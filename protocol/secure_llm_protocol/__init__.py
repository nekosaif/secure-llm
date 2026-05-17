"""Wire-format schemas shared between secure-llm server and client.

This package is the single source of truth for what goes on the wire. Both
sides depend on it; bumping :data:`PROTOCOL_VERSION` is the only sanctioned way
to change request/response shapes.
"""

from secure_llm_protocol.errors import ErrorCode
from secure_llm_protocol.schemas import (
    AdminClientInfo,
    AdminSessionInfo,
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    CompletionRequest,
    CompletionResponse,
    DebugStatus,
    DoctorReport,
    DoctorStep,
    EmbeddingsRequest,
    EmbeddingsResponse,
    ErrorEnvelope,
    HandshakeRequest,
    HandshakeResponse,
    LogEntry,
    LoraApplyRequest,
    LoraDownloadRequest,
    LoraInfo,
    LoraList,
    LoraRef,
    ModelDownloadRequest,
    ModelInfo,
    ModelList,
    SystemStatus,
)
from secure_llm_protocol.version import PROTOCOL_VERSION
from secure_llm_protocol.wire import (
    ENVELOPE_HEADER_SIZE,
    ENVELOPE_MAGIC,
    ENVELOPE_VERSION,
    MAX_REQUEST_BYTES,
    pack_envelope,
    unpack_envelope,
)

__all__ = [
    "ENVELOPE_HEADER_SIZE",
    "ENVELOPE_MAGIC",
    "ENVELOPE_VERSION",
    "MAX_REQUEST_BYTES",
    "PROTOCOL_VERSION",
    "AdminClientInfo",
    "AdminSessionInfo",
    "ChatCompletionChunk",
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "ChatMessage",
    "CompletionRequest",
    "CompletionResponse",
    "DebugStatus",
    "DoctorReport",
    "DoctorStep",
    "EmbeddingsRequest",
    "EmbeddingsResponse",
    "ErrorCode",
    "ErrorEnvelope",
    "HandshakeRequest",
    "HandshakeResponse",
    "LogEntry",
    "LoraApplyRequest",
    "LoraDownloadRequest",
    "LoraInfo",
    "LoraList",
    "LoraRef",
    "ModelDownloadRequest",
    "ModelInfo",
    "ModelList",
    "SystemStatus",
    "pack_envelope",
    "unpack_envelope",
]
