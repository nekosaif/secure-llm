"""Typed exception hierarchy. SDK callers pattern-match on these."""

from __future__ import annotations

from secure_llm_protocol.errors import ErrorCode


class SecureLLMError(Exception):
    """Base for all SDK errors. Carries the canonical :class:`ErrorCode`."""

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self, message: str = "", *, code: ErrorCode | None = None, error_id: str | None = None
    ) -> None:
        super().__init__(message or (code.value if code else self.code.value))
        if code is not None:
            self.code = code
        self.error_id = error_id


class AuthError(SecureLLMError):
    code = ErrorCode.BAD_SIGNATURE


class HandshakeFailed(AuthError):
    pass


class ServerKeyMismatch(HandshakeFailed):
    code = ErrorCode.SERVER_KEY_MISMATCH


class SessionExpired(AuthError):
    code = ErrorCode.SESSION_EXPIRED


class AdminRequiredError(SecureLLMError):
    code = ErrorCode.ADMIN_REQUIRED


class RateLimited(SecureLLMError):
    code = ErrorCode.RATE_LIMITED

    def __init__(
        self, message: str = "", *, retry_after: float | None = None, error_id: str | None = None
    ) -> None:
        super().__init__(message, error_id=error_id)
        self.retry_after = retry_after


class QueueFull(SecureLLMError):
    code = ErrorCode.QUEUE_FULL


class ModelNotFound(SecureLLMError):
    code = ErrorCode.MODEL_NOT_FOUND


class DownloadFailed(SecureLLMError):
    code = ErrorCode.DOWNLOAD_FAILED


_BY_CODE: dict[ErrorCode, type[SecureLLMError]] = {
    ErrorCode.BAD_SIGNATURE: HandshakeFailed,
    ErrorCode.SERVER_KEY_MISMATCH: ServerKeyMismatch,
    ErrorCode.SESSION_EXPIRED: SessionExpired,
    ErrorCode.ADMIN_REQUIRED: AdminRequiredError,
    ErrorCode.SCOPE_DENIED: AdminRequiredError,
    ErrorCode.RATE_LIMITED: RateLimited,
    ErrorCode.QUEUE_FULL: QueueFull,
    ErrorCode.MODEL_NOT_FOUND: ModelNotFound,
    ErrorCode.DOWNLOAD_FAILED: DownloadFailed,
    ErrorCode.UNKNOWN_CLIENT: HandshakeFailed,
    ErrorCode.CLIENT_REVOKED: HandshakeFailed,
    ErrorCode.CLIENT_EXPIRED: HandshakeFailed,
    ErrorCode.CLIENT_NOT_YET_VALID: HandshakeFailed,
    ErrorCode.CLOCK_SKEW: HandshakeFailed,
}


def from_error_envelope(
    code: ErrorCode, message: str, error_id: str | None, retry_after: float | None = None
) -> SecureLLMError:
    cls = _BY_CODE.get(code, SecureLLMError)
    if cls is RateLimited:
        return RateLimited(message, retry_after=retry_after, error_id=error_id)
    return cls(message, code=code, error_id=error_id)
