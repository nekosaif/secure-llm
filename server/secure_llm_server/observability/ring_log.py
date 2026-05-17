"""In-memory bounded log buffer backing the debug-API log tail."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from secure_llm_protocol.schemas import LogEntry


class RingLog:
    """Thread-safe ring of structured log entries. Redaction happens upstream."""

    def __init__(self, max_size: int = 10_000) -> None:
        self._buf: deque[LogEntry] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def add(self, event_dict: dict[str, Any]) -> None:
        entry = LogEntry(
            ts=event_dict.get("timestamp", time.time()),
            level=str(event_dict.get("level", "info")).lower(),
            component=str(event_dict.get("logger", event_dict.get("component", ""))),
            event=str(event_dict.get("event", "")),
            fields={
                k: v
                for k, v in event_dict.items()
                if k not in {"timestamp", "level", "logger", "event", "component"}
            },
        )
        with self._lock:
            self._buf.append(entry)

    def tail(
        self,
        *,
        limit: int = 200,
        level: str | None = None,
        component: str | None = None,
        since: float | None = None,
        client_fingerprint: str | None = None,
    ) -> list[LogEntry]:
        with self._lock:
            snapshot = list(self._buf)
        out: list[LogEntry] = []
        for entry in reversed(snapshot):
            if since is not None and entry.ts < since:
                break
            if level and entry.level != level.lower():
                continue
            if component and not entry.component.startswith(component):
                continue
            if client_fingerprint and entry.fields.get("client_fp") != client_fingerprint:
                continue
            out.append(entry)
            if len(out) >= limit:
                break
        return list(reversed(out))
