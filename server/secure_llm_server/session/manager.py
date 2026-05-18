"""In-memory or federated session table.

The default backend (``InMemorySessionStore``) keeps session keys in
RAM only — no disk persistence. With ``[federation].session_store =
"redis"`` configured, ``RedisSessionStore`` mirrors session state into
Redis so a stateless fleet of servers behind one LB can serve a
session even if the original instance dies.

In every case the AEAD direction keys live in RAM (or in Redis under
the same trust boundary as the server). They are never written to
disk on the server itself.
"""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field

from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.handshake import SessionMaterial
from secure_llm_server.crypto.replay import ReplayWindow
from secure_llm_server.session.store import InMemorySessionStore, SessionStore


@dataclass(slots=True)
class Session:
    session_id: bytes
    c2s: DirectionKeys
    s2c: DirectionKeys
    created_at: float
    last_used_at: float
    ttl_seconds: int
    max_lifetime_seconds: int
    client_fingerprint: str
    scopes: frozenset[str]
    tenant: str = "default"
    replay: ReplayWindow = field(default_factory=ReplayWindow)
    s2c_counter: int = 0
    closed: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if self.closed:
            return True
        if now - self.last_used_at > self.ttl_seconds:
            return True
        return now - self.created_at > self.max_lifetime_seconds

    def touch(self) -> None:
        self.last_used_at = time.time()

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    @property
    def session_id_b64(self) -> str:
        return base64.b64encode(self.session_id).decode("ascii")


class SessionManager:
    """Public session API. Thin wrapper over a :class:`SessionStore`.

    The default store is :class:`InMemorySessionStore`. To enable
    federated state, pass a :class:`RedisSessionStore` instance.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int,
        max_lifetime_seconds: int,
        store: SessionStore | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_life = max_lifetime_seconds
        self._store: SessionStore = store if store is not None else InMemorySessionStore()
        self._lock = asyncio.Lock()

    @property
    def store(self) -> SessionStore:
        return self._store

    async def create(self, material: SessionMaterial) -> Session:
        now = time.time()
        sess = Session(
            session_id=material.session_id,
            c2s=material.c2s,
            s2c=material.s2c,
            created_at=now,
            last_used_at=now,
            ttl_seconds=material.ttl_seconds or self._ttl,
            max_lifetime_seconds=self._max_life,
            client_fingerprint=material.client_fingerprint,
            scopes=frozenset(material.scopes),
            tenant=material.tenant,
        )
        async with self._lock:
            await self._store.put(sess)
        return sess

    def lookup(self, session_id: bytes) -> Session | None:
        """Synchronous cache-only lookup. Returns ``None`` on miss.

        For federated setups, prefer :meth:`lookup_async` so the
        backing store can rehydrate after a failover.
        """
        return self._store.lookup(session_id)

    async def lookup_async(self, session_id: bytes) -> Session | None:
        """Like :meth:`lookup`, but falls back to the backing store on
        local-cache miss. Used by the request decryption helper and by
        admin endpoints that may target a session pinned to another
        instance in a federated fleet."""
        sess = self._store.lookup(session_id)
        if sess is None:
            sess = await self._store.hydrate(session_id)
        if sess is None or sess.is_expired():
            if sess is not None:
                self._zeroize(sess)
                await self._store.delete(session_id)
            return None
        return sess

    def all(self) -> list[Session]:
        return self._store.all()

    async def terminate(self, session_id: bytes) -> bool:
        async with self._lock:
            sess = self._store.lookup(session_id)
            if sess is None:
                sess = await self._store.hydrate(session_id)
            if sess is None:
                return False
            self._zeroize(sess)
            return await self._store.delete(session_id)

    async def reap_expired(self) -> int:
        async with self._lock:
            return await self._store.reap_expired()

    async def persist(self, session: Session) -> None:
        """Write the latest session state to the backing store.

        Called after mutations that need to survive a failover: replay
        watermark advances, ``last_used_at`` updates, ``s2c_counter``
        increments. For :class:`InMemorySessionStore` this is a cheap
        dict re-insert (the cached and stored object are the same
        reference). For Redis it is an actual write.
        """
        await self._store.put(session)

    @staticmethod
    def _zeroize(session: Session) -> None:
        session.closed = True
        # Replace dataclass key fields with zeroed bytes of same length.
        # The originals will be GC'd; we can't truly memset, but we can drop
        # references immediately so they're not retained anywhere.
        zero = b"\x00" * 32
        object.__setattr__(
            session,
            "c2s",
            DirectionKeys(key=zero, nonce_prefix=session.c2s.nonce_prefix),
        )
        object.__setattr__(
            session,
            "s2c",
            DirectionKeys(key=zero, nonce_prefix=session.s2c.nonce_prefix),
        )
