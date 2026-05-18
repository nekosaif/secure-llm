"""Redis-backed session store for federated deployments.

Trust boundary: the Redis instance is treated as **inside** the server
trust boundary — it stores AEAD direction keys, replay watermarks, and
counter state. Run Redis on the same host or a VPC peer of the LLM
servers, never expose it to a wider network. Document this constraint
in ``docs/threat-model.md`` (v1.3 entry).

Failover semantics:

- Session created on instance A is visible to instance B after
  instance B's next ``hydrate`` for that session id.
- The replay bitmap (the 1024-bit sliding window) is **not** mirrored
  across instances; only ``head`` is. After failover, the new
  instance's window starts empty at the persisted ``head``, accepting
  any counter strictly greater than ``head``. This is safe because
  client counters are strictly monotonic per direction; the only loss
  is the ability to detect duplicates from the *old instance's*
  in-flight requests within the 1024-counter window. Documented in
  the v1.3 threat-model addendum.
- ``s2c_counter`` is persisted *after* the response is sealed in the
  next request's ``persist`` call — there is a one-request lag.
  Documented in the operator guide as "use session-affinity LB
  routing for best UX".
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Protocol

from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.replay import ReplayWindow
from secure_llm_server.session.manager import Session

_KEY_PREFIX = "secure_llm:session:"


class RedisClient(Protocol):
    """Minimal async surface we use from redis-py's ``redis.asyncio.Redis``.

    Defined as a Protocol so tests can pass a fake client without
    pulling redis as a test dep.
    """

    async def set(self, name: str, value: bytes, ex: int | None = None) -> Any: ...
    async def get(self, name: str) -> bytes | None: ...
    async def delete(self, *names: str) -> int: ...

    def scan_iter(self, match: str | None = None) -> Any:
        """Returns an async iterator of matching keys (bytes or str)."""
        ...


def _key(session_id: bytes) -> str:
    return _KEY_PREFIX + session_id.hex()


def _serialize(sess: Session) -> bytes:
    return json.dumps(
        {
            "session_id": base64.b64encode(sess.session_id).decode("ascii"),
            "c2s_key": base64.b64encode(sess.c2s.key).decode("ascii"),
            "c2s_np": base64.b64encode(sess.c2s.nonce_prefix).decode("ascii"),
            "s2c_key": base64.b64encode(sess.s2c.key).decode("ascii"),
            "s2c_np": base64.b64encode(sess.s2c.nonce_prefix).decode("ascii"),
            "created_at": sess.created_at,
            "last_used_at": sess.last_used_at,
            "ttl_seconds": sess.ttl_seconds,
            "max_lifetime_seconds": sess.max_lifetime_seconds,
            "client_fingerprint": sess.client_fingerprint,
            "scopes": sorted(sess.scopes),
            "tenant": sess.tenant,
            "replay_high": sess.replay.high,
            "s2c_counter": sess.s2c_counter,
            "closed": sess.closed,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _deserialize(blob: bytes) -> Session:
    data = json.loads(blob)
    return Session(
        session_id=base64.b64decode(data["session_id"]),
        c2s=DirectionKeys(
            key=base64.b64decode(data["c2s_key"]),
            nonce_prefix=base64.b64decode(data["c2s_np"]),
        ),
        s2c=DirectionKeys(
            key=base64.b64decode(data["s2c_key"]),
            nonce_prefix=base64.b64decode(data["s2c_np"]),
        ),
        created_at=float(data["created_at"]),
        last_used_at=float(data["last_used_at"]),
        ttl_seconds=int(data["ttl_seconds"]),
        max_lifetime_seconds=int(data["max_lifetime_seconds"]),
        client_fingerprint=str(data["client_fingerprint"]),
        scopes=frozenset(data["scopes"]),
        tenant=str(data["tenant"]),
        replay=ReplayWindow(high=int(data["replay_high"]), bitmap=0),
        s2c_counter=int(data["s2c_counter"]),
        closed=bool(data["closed"]),
    )


class RedisSessionStore:
    """``SessionStore`` impl backed by Redis with an in-process cache.

    The cache exists so that the hot path (``lookup``) stays sync and
    doesn't await on Redis for every request when the session is
    already local. Cache entries are evicted on TTL expiry just like
    Redis-side entries.
    """

    __slots__ = ("_cache", "_client", "_key_ttl_floor")

    def __init__(self, client: RedisClient, *, key_ttl_floor_seconds: int = 60) -> None:
        self._client = client
        self._cache: dict[bytes, Session] = {}
        # Don't let a session's effective Redis TTL drop below this.
        # Avoids races where the key expires between hydrate and persist.
        self._key_ttl_floor = key_ttl_floor_seconds

    # ----- SessionStore protocol -----

    def lookup(self, session_id: bytes) -> Session | None:
        sess = self._cache.get(session_id)
        if sess is None or sess.is_expired():
            if sess is not None:
                self._cache.pop(session_id, None)
            return None
        return sess

    def all(self) -> list[Session]:
        return [s for s in self._cache.values() if not s.is_expired()]

    async def hydrate(self, session_id: bytes) -> Session | None:
        cached = self._cache.get(session_id)
        if cached is not None and not cached.is_expired():
            return cached
        blob = await self._client.get(_key(session_id))
        if blob is None:
            return None
        sess = _deserialize(blob)
        if sess.is_expired():
            await self._client.delete(_key(session_id))
            return None
        self._cache[session_id] = sess
        return sess

    async def put(self, session: Session) -> None:
        self._cache[session.session_id] = session
        # Redis TTL = remaining session lifetime, floored.
        now = time.time()
        remaining_ttl = max(0, int(session.last_used_at + session.ttl_seconds - now))
        remaining_max = max(0, int(session.created_at + session.max_lifetime_seconds - now))
        ttl = max(self._key_ttl_floor, min(remaining_ttl, remaining_max))
        await self._client.set(_key(session.session_id), _serialize(session), ex=ttl)

    async def delete(self, session_id: bytes) -> bool:
        self._cache.pop(session_id, None)
        n = await self._client.delete(_key(session_id))
        return bool(n)

    async def reap_expired(self) -> int:
        # Redis TTLs already evict server-side. We only need to drop
        # stale entries from the local cache.
        removed = 0
        for sid in list(self._cache.keys()):
            if self._cache[sid].is_expired():
                del self._cache[sid]
                removed += 1
        return removed


def build_redis_session_store(url: str) -> RedisSessionStore:
    """Construct a :class:`RedisSessionStore` from a Redis URL.

    Importing ``redis.asyncio`` is deferred to this constructor so the
    base server install doesn't need the redis client when federation
    is disabled.
    """
    try:
        import redis.asyncio as redis_async  # type: ignore[import-not-found]
    except ImportError as e:  # pragma: no cover - tested via the protocol path
        raise RuntimeError(
            "[federation].session_store='redis' requires `pip install "
            "secure-llm-server[federation]` to bring in the redis client"
        ) from e
    client = redis_async.from_url(url)
    return RedisSessionStore(client)


__all__ = [
    "RedisClient",
    "RedisSessionStore",
    "build_redis_session_store",
]
