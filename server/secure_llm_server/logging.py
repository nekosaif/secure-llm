"""Structlog configuration with payload redaction + ring-buffer sink.

Public entry: :func:`configure`. After it returns, ``structlog.get_logger(__name__)``
yields a logger that writes JSON to stdout, appends to a rotating file, and
mirrors into the in-memory ring used by the debug API.

Redaction is enforced at the structlog processor layer: any key whose name
matches a sensitive set is dropped before serialization. A test (in
``tests/unit/test_log_redaction.py``) verifies the canary string never leaks.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import time
from pathlib import Path
from typing import Any

import structlog

from secure_llm_server.observability.ring_log import RingLog

_SENSITIVE_KEYS = frozenset(
    {
        "prompt",
        "messages",
        "content",
        "delta",
        "completion",
        "text",
        "plaintext",
        "ciphertext",
        "session_key",
        "secret",
        "private_key",
    }
)


def _redact(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Drop sensitive keys; refuse to serialize raw bytes."""
    for k in list(event_dict.keys()):
        if k in _SENSITIVE_KEYS:
            event_dict[k] = "<redacted>"
        elif isinstance(event_dict[k], (bytes, bytearray)):
            event_dict[k] = f"<{len(event_dict[k])}B>"
    return event_dict


def _add_ts(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    event_dict.setdefault("timestamp", time.time())
    return event_dict


class _RingSink:
    """Structlog processor that also appends to a shared ring buffer."""

    def __init__(self, ring: RingLog) -> None:
        self._ring = ring

    def __call__(self, _: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        try:
            self._ring.add(dict(event_dict))
        except Exception:
            pass
        return event_dict


def configure(
    *,
    level: str = "INFO",
    log_format: str = "json",
    log_dir: Path | None = None,
    ring: RingLog | None = None,
) -> RingLog:
    ring = ring or RingLog()
    level_int = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_dir / "server.log",
                maxBytes=50 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
        )

    logging.basicConfig(level=level_int, format="%(message)s", handlers=handlers, force=True)

    renderer: structlog.types.Processor
    if log_format == "console":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:
        renderer = structlog.processors.JSONRenderer(sort_keys=True)

    structlog.configure(
        cache_logger_on_first_use=True,
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.stdlib.add_logger_name,
            _add_ts,
            _redact,
            _RingSink(ring),
            structlog.processors.format_exc_info,
            renderer,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    return ring


def get_level_overrides() -> dict[str, str]:  # placeholder for admin API
    return {}


def set_component_level(component: str, level: str) -> None:
    """Adjust a single component's level via stdlib logging."""
    logging.getLogger(component).setLevel(getattr(logging, level.upper(), logging.INFO))
