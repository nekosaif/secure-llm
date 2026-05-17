"""Sensitive keys must be stripped before serialization."""

from __future__ import annotations

import json

import structlog

from secure_llm_server import logging as logmod


def test_redacts_sensitive_keys(tmp_path):
    ring = logmod.configure(level="DEBUG", log_format="json", log_dir=tmp_path)
    log = structlog.get_logger("test")
    canary = "TOPSECRET_CANARY_12345"
    log.info(
        "chat.completion",
        prompt=canary,
        messages=[{"role": "user", "content": canary}],
        content=canary,
        ok=True,
    )

    log_file = tmp_path / "server.log"
    contents = log_file.read_text(encoding="utf-8")
    assert canary not in contents, "canary leaked into log file!"
    assert "<redacted>" in contents

    entries = ring.tail(limit=10)
    serialized = json.dumps([e.model_dump() for e in entries])
    assert canary not in serialized
