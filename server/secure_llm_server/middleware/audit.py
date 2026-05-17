"""Security/audit event emitter — separate sink from regular request logs."""

from __future__ import annotations

import structlog

_audit = structlog.get_logger("secure_llm_server.audit")


def audit_event(event: str, **fields: object) -> None:
    """Emit a structured audit event. No payload content ever flows through here."""
    _audit.info(event, **fields)
