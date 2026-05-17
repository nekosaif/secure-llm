"""Bounded ring of sanitized exception records keyed by short error_id."""

from __future__ import annotations

import secrets
import threading
import time
import traceback
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

_SENSITIVE_LOCAL_NAMES = frozenset(
    {
        "prompt",
        "messages",
        "content",
        "delta",
        "completion",
        "plaintext",
        "ciphertext",
        "key",
        "x25519_sk",
        "ed25519_sk",
        "secret",
    }
)


@dataclass(slots=True)
class ErrorRecord:
    error_id: str
    ts: float
    code: str
    message: str
    stack: str
    request_id: str | None = None
    client_fingerprint: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "error_id": self.error_id,
            "ts": self.ts,
            "code": self.code,
            "message": self.message,
            "request_id": self.request_id,
        }


def _sanitized_traceback(exc: BaseException) -> str:
    # We deliberately do not include local variables — they may contain payloads.
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


class ErrorTracker:
    def __init__(self, capacity: int = 1000) -> None:
        self._cap = capacity
        self._records: OrderedDict[str, ErrorRecord] = OrderedDict()
        self._lock = threading.Lock()

    def record(
        self,
        exc: BaseException,
        *,
        code: str,
        request_id: str | None = None,
        client_fingerprint: str | None = None,
        **extra: Any,
    ) -> ErrorRecord:
        eid = secrets.token_hex(4).upper()  # short, opaque to clients
        rec = ErrorRecord(
            error_id=eid,
            ts=time.time(),
            code=code,
            message=str(exc)[:500],
            stack=_sanitized_traceback(exc),
            request_id=request_id,
            client_fingerprint=client_fingerprint,
            extra={k: v for k, v in extra.items() if k not in _SENSITIVE_LOCAL_NAMES},
        )
        with self._lock:
            self._records[eid] = rec
            if len(self._records) > self._cap:
                self._records.popitem(last=False)
        return rec

    def get(self, error_id: str) -> ErrorRecord | None:
        with self._lock:
            return self._records.get(error_id)

    def recent(self, limit: int = 50) -> list[ErrorRecord]:
        with self._lock:
            return list(self._records.values())[-limit:][::-1]
