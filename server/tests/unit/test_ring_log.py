"""RingLog: bounded buffer, tail filtering, redacting-by-fingerprint."""

from __future__ import annotations

import time

from secure_llm_server.observability.ring_log import RingLog


def _event(
    event: str = "x",
    level: str = "info",
    logger: str = "secure_llm_server.a",
    client_fp: str = "anon",
    t: float | None = None,
) -> dict:
    return {
        "timestamp": t if t is not None else time.time(),
        "level": level,
        "logger": logger,
        "event": event,
        "client_fp": client_fp,
    }


def test_bounded_size_evicts_oldest():
    ring = RingLog(max_size=3)
    for i in range(5):
        ring.add(_event(event=f"e{i}"))
    tail = ring.tail(limit=10)
    assert [e.event for e in tail] == ["e2", "e3", "e4"]


def test_filter_by_level_and_component_and_since():
    ring = RingLog(max_size=16)
    now = time.time()
    ring.add(_event(event="early", t=now - 100))
    ring.add(_event(event="mid", level="warning", t=now - 50))
    ring.add(_event(event="late", logger="secure_llm_server.b", t=now))

    # level filter
    warns = ring.tail(level="warning", limit=10)
    assert [e.event for e in warns] == ["mid"]
    # component prefix filter
    bs = ring.tail(component="secure_llm_server.b", limit=10)
    assert [e.event for e in bs] == ["late"]
    # since filter
    recent = ring.tail(since=now - 60, limit=10)
    assert {e.event for e in recent} == {"mid", "late"}


def test_filter_by_fingerprint():
    ring = RingLog(max_size=4)
    ring.add(_event(event="alice-1", client_fp="alice"))
    ring.add(_event(event="bob-1", client_fp="bob"))
    ring.add(_event(event="alice-2", client_fp="alice"))
    tail = ring.tail(client_fingerprint="alice", limit=10)
    assert [e.event for e in tail] == ["alice-1", "alice-2"]


def test_limit_cap():
    ring = RingLog(max_size=10)
    for i in range(8):
        ring.add(_event(event=f"e{i}"))
    assert len(ring.tail(limit=3)) == 3
