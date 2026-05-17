"""In-memory session table. Keys live in RAM only; no disk persistence."""

from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field

from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.handshake import SessionMaterial
from secure_llm_server.crypto.replay import ReplayWindow


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
    def __init__(self, *, ttl_seconds: int, max_lifetime_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._max_life = max_lifetime_seconds
        self._by_id: dict[bytes, Session] = {}
        self._lock = asyncio.Lock()

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
            self._by_id[sess.session_id] = sess
        return sess

    def lookup(self, session_id: bytes) -> Session | None:
        sess = self._by_id.get(session_id)
        if sess is None or sess.is_expired():
            if sess is not None:
                self._zeroize(sess)
                self._by_id.pop(sess.session_id, None)
            return None
        return sess

    def all(self) -> list[Session]:
        return [s for s in self._by_id.values() if not s.is_expired()]

    async def terminate(self, session_id: bytes) -> bool:
        async with self._lock:
            sess = self._by_id.pop(session_id, None)
            if sess is None:
                return False
            self._zeroize(sess)
            return True

    async def reap_expired(self) -> int:
        async with self._lock:
            removed = 0
            for sid in list(self._by_id.keys()):
                s = self._by_id[sid]
                if s.is_expired():
                    self._zeroize(s)
                    del self._by_id[sid]
                    removed += 1
            return removed

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
