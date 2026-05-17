"""Canonical error codes. Stable strings — clients pattern-match on these."""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # Auth / handshake
    UNKNOWN_CLIENT = "unknown_client"
    CLIENT_REVOKED = "client_revoked"
    CLIENT_NOT_YET_VALID = "client_not_yet_valid"
    CLIENT_EXPIRED = "client_expired"
    BAD_SIGNATURE = "bad_signature"
    CLOCK_SKEW = "clock_skew"
    SERVER_KEY_MISMATCH = "server_key_mismatch"
    HANDSHAKE_VERSION_MISMATCH = "handshake_version_mismatch"

    # Session / envelope
    UNKNOWN_SESSION = "unknown_session"
    SESSION_EXPIRED = "session_expired"
    BAD_ENVELOPE = "bad_envelope"
    DECRYPT_FAILED = "decrypt_failed"
    REPLAY_DETECTED = "replay_detected"
    BODY_TOO_LARGE = "body_too_large"

    # Authorization
    ADMIN_REQUIRED = "admin_required"
    SCOPE_DENIED = "scope_denied"

    # Models / inference
    MODEL_NOT_FOUND = "model_not_found"
    MODEL_BUSY = "model_busy"
    QUEUE_FULL = "queue_full"
    LOAD_FAILED = "load_failed"
    DOWNLOAD_FAILED = "download_failed"
    SHA256_MISMATCH = "sha256_mismatch"
    REPO_NOT_ALLOWED = "repo_not_allowed"
    DISK_QUOTA_EXCEEDED = "disk_quota_exceeded"

    # Generic
    RATE_LIMITED = "rate_limited"
    BAD_REQUEST = "bad_request"
    INTERNAL_ERROR = "internal_error"
    NOT_READY = "not_ready"
    CANCELLED = "cancelled"
