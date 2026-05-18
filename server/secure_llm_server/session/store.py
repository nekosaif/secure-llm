"""Pluggable backing store for :class:`Session` state.

v1.3 introduces a ``SessionStore`` Protocol so the same `SessionManager`
can be backed either by an in-memory dict (single instance) or by
Redis (federated fleet). The in-memory implementation is the default
and is what every test in this repo exercises.

Design notes:

- ``lookup`` and ``all`` are intentionally *synchronous*. They read
  the in-process cache only; they never touch the network. The hot
  path (every encrypted request) hits ``lookup`` and we don't want
  to await on every request when no federation is configured.
- ``hydrate`` is the explicit async escape hatch for the federated
  case — Redis-backed stores read the canonical state from Redis
  and warm the local cache. For the in-memory backend it's an alias
  for ``lookup``.
- ``put`` / ``delete`` / ``reap_expired`` are async — Redis ops may
  block — even though the in-memory implementation never awaits.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from secure_llm_server.session.manager import Session


class SessionStore(Protocol):
    """Backing store for the live session table."""

    def lookup(self, session_id: bytes) -> Session | None:
        """Cache-only lookup. Never blocks. Returns ``None`` on miss
        *or* if the entry is known to be expired."""
        ...

    def all(self) -> list[Session]:
        """All non-expired sessions known to this instance's cache."""
        ...

    async def hydrate(self, session_id: bytes) -> Session | None:
        """Read canonical state from the backing store and warm the
        cache. For in-memory backends, equivalent to ``lookup``."""
        ...

    async def put(self, session: Session) -> None:
        """Write through to the backing store."""
        ...

    async def delete(self, session_id: bytes) -> bool:
        """Remove from the backing store. Returns ``True`` if a row
        was actually deleted."""
        ...

    async def reap_expired(self) -> int:
        """Drop expired entries. Returns the number reaped."""
        ...


class InMemorySessionStore:
    """The default backend. Backing store IS the in-process cache.

    Safe under FastAPI's single-loop concurrency model: every mutation
    runs on the event-loop thread, so no lock is needed for dict ops.
    """

    __slots__ = ("_by_id",)

    def __init__(self) -> None:
        self._by_id: dict[bytes, Session] = {}

    def lookup(self, session_id: bytes) -> Session | None:
        sess = self._by_id.get(session_id)
        if sess is None or sess.is_expired():
            return None
        return sess

    def all(self) -> list[Session]:
        return [s for s in self._by_id.values() if not s.is_expired()]

    async def hydrate(self, session_id: bytes) -> Session | None:
        # In-memory: nothing to fetch — the cache is authoritative.
        return self.lookup(session_id)

    async def put(self, session: Session) -> None:
        self._by_id[session.session_id] = session

    async def delete(self, session_id: bytes) -> bool:
        return self._by_id.pop(session_id, None) is not None

    async def reap_expired(self) -> int:
        removed = 0
        for sid in list(self._by_id.keys()):
            if self._by_id[sid].is_expired():
                del self._by_id[sid]
                removed += 1
        return removed


__all__ = ["InMemorySessionStore", "SessionStore"]
