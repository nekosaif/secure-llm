"""v1.3 federation: SessionStore Protocol, Redis-backed store, fail-over.

The Redis tests don't need a real broker — :class:`RedisSessionStore`
is constructed against the ``RedisClient`` Protocol, so a fake dict-
backed client is sufficient to exercise the serialization, hydrate,
and TTL handling.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any

import pytest

from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.handshake import SessionMaterial
from secure_llm_server.crypto.replay import ReplayWindow
from secure_llm_server.session.manager import Session, SessionManager
from secure_llm_server.session.redis_store import (
    RedisSessionStore,
    _deserialize,
    _key,
    _serialize,
)
from secure_llm_server.session.store import InMemorySessionStore

# ----- fake redis-py-compatible client -----


class FakeRedis:
    """Minimal stand-in for ``redis.asyncio.Redis`` covering the
    methods :class:`RedisSessionStore` uses. Stores values in a dict.
    Honors TTL via wall-clock comparison so ``hydrate`` tests can
    simulate expiry."""

    def __init__(self) -> None:
        self.kv: dict[str, tuple[bytes, float | None]] = {}

    async def set(self, name: str, value: bytes, ex: int | None = None) -> Any:
        expiry = (time.time() + ex) if ex is not None else None
        self.kv[name] = (value, expiry)
        return True

    async def get(self, name: str) -> bytes | None:
        item = self.kv.get(name)
        if item is None:
            return None
        value, expiry = item
        if expiry is not None and time.time() > expiry:
            del self.kv[name]
            return None
        return value

    async def delete(self, *names: str) -> int:
        removed = 0
        for n in names:
            if n in self.kv:
                del self.kv[n]
                removed += 1
        return removed


def _make_session(tenant: str = "default") -> Session:
    now = time.time()
    return Session(
        session_id=secrets.token_bytes(16),
        c2s=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        s2c=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        created_at=now,
        last_used_at=now,
        ttl_seconds=3600,
        max_lifetime_seconds=28800,
        client_fingerprint="abc123",
        scopes=frozenset({"chat"}),
        tenant=tenant,
        replay=ReplayWindow(high=42, bitmap=0xDEADBEEF),
        s2c_counter=7,
    )


def _material(tenant: str = "default") -> SessionMaterial:
    return SessionMaterial(
        session_id=secrets.token_bytes(16),
        c2s=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        s2c=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        ttl_seconds=3600,
        client_fingerprint="fp:test",
        scopes=("chat",),
        tenant=tenant,
    )


# ----- serialization -----


def test_serialize_roundtrip_preserves_session_fields():
    sess = _make_session()
    blob = _serialize(sess)
    rehydrated = _deserialize(blob)
    assert rehydrated.session_id == sess.session_id
    assert rehydrated.c2s.key == sess.c2s.key
    assert rehydrated.c2s.nonce_prefix == sess.c2s.nonce_prefix
    assert rehydrated.s2c.key == sess.s2c.key
    assert rehydrated.tenant == sess.tenant
    assert rehydrated.client_fingerprint == sess.client_fingerprint
    assert rehydrated.scopes == sess.scopes
    assert rehydrated.replay.high == sess.replay.high
    # Bitmap is intentionally NOT persisted across instances — see the
    # module docstring on failover semantics.
    assert rehydrated.replay.bitmap == 0
    assert rehydrated.s2c_counter == sess.s2c_counter


def test_key_format_is_stable():
    sid = bytes.fromhex("0011223344556677" * 2)
    assert _key(sid) == "secure_llm:session:" + sid.hex()


# ----- RedisSessionStore via FakeRedis -----


def test_redis_store_put_then_hydrate_roundtrip():
    async def go() -> None:
        store = RedisSessionStore(FakeRedis())
        sess = _make_session()
        await store.put(sess)
        # Drop the local cache to force a real hydrate from "Redis".
        store._cache.clear()
        rehydrated = await store.hydrate(sess.session_id)
        assert rehydrated is not None
        assert rehydrated.session_id == sess.session_id
        # Cache is repopulated on hydrate.
        assert store.lookup(sess.session_id) is rehydrated

    asyncio.run(go())


def test_redis_store_lookup_returns_none_on_cache_miss():
    """``lookup`` is the sync hot path — it should *not* hit Redis.
    Only ``hydrate`` may touch the network."""

    async def go() -> None:
        store = RedisSessionStore(FakeRedis())
        sess = _make_session()
        await store.put(sess)
        store._cache.clear()
        assert store.lookup(sess.session_id) is None

    asyncio.run(go())


def test_redis_store_delete_clears_both_sides():
    async def go() -> None:
        store = RedisSessionStore(FakeRedis())
        sess = _make_session()
        await store.put(sess)
        removed = await store.delete(sess.session_id)
        assert removed is True
        assert store.lookup(sess.session_id) is None
        assert await store.hydrate(sess.session_id) is None
        # Deleting again is a no-op.
        assert await store.delete(sess.session_id) is False

    asyncio.run(go())


def test_redis_store_drops_expired_on_hydrate():
    async def go() -> None:
        redis = FakeRedis()
        store = RedisSessionStore(redis)
        sess = _make_session()
        # Force expiry by stamping the timestamps in the past.
        sess.created_at = time.time() - 100_000
        sess.last_used_at = time.time() - 100_000
        await store.put(sess)
        store._cache.clear()
        rehydrated = await store.hydrate(sess.session_id)
        assert rehydrated is None
        # Expired key is purged from Redis too.
        assert _key(sess.session_id) not in redis.kv

    asyncio.run(go())


def test_redis_store_reap_drops_local_cache_only():
    async def go() -> None:
        store = RedisSessionStore(FakeRedis())
        live = _make_session()
        dead = _make_session()
        dead.last_used_at = time.time() - 100_000
        await store.put(live)
        await store.put(dead)
        n = await store.reap_expired()
        assert n == 1
        assert store.lookup(live.session_id) is live
        assert store.lookup(dead.session_id) is None

    asyncio.run(go())


# ----- failover via two SessionManagers sharing one FakeRedis -----


def test_failover_session_created_on_a_is_visible_on_b():
    """The canonical v1.3 federation scenario."""

    async def go() -> None:
        broker = FakeRedis()
        store_a = RedisSessionStore(broker)
        store_b = RedisSessionStore(broker)
        manager_a = SessionManager(ttl_seconds=3600, max_lifetime_seconds=28800, store=store_a)
        manager_b = SessionManager(ttl_seconds=3600, max_lifetime_seconds=28800, store=store_b)
        sess = await manager_a.create(_material())
        # B has no local cache for this session ...
        assert manager_b.lookup(sess.session_id) is None
        # ... but lookup_async hydrates from the shared Redis.
        rehydrated = await manager_b.lookup_async(sess.session_id)
        assert rehydrated is not None
        assert rehydrated.session_id == sess.session_id
        assert rehydrated.tenant == sess.tenant
        # Now lookup on B finds it in B's cache.
        assert manager_b.lookup(sess.session_id) is rehydrated

    asyncio.run(go())


def test_failover_terminate_on_b_propagates_to_redis():
    async def go() -> None:
        broker = FakeRedis()
        manager_a = SessionManager(
            ttl_seconds=3600,
            max_lifetime_seconds=28800,
            store=RedisSessionStore(broker),
        )
        manager_b = SessionManager(
            ttl_seconds=3600,
            max_lifetime_seconds=28800,
            store=RedisSessionStore(broker),
        )
        sess = await manager_a.create(_material())
        # B terminates a session it has never seen locally — it must
        # hydrate, then delete.
        removed = await manager_b.terminate(sess.session_id)
        assert removed is True
        # Redis-side: gone.
        assert _key(sess.session_id) not in broker.kv
        # A's *cache* still has it (no out-of-band invalidation in
        # v1.3) but lookup_async returns None because hydrate misses.
        assert manager_a.lookup(sess.session_id) is sess  # local-cache zombie
        # The zombie is dropped on the next forced rehydrate.
        manager_a._store._cache.clear()  # type: ignore[attr-defined]
        assert await manager_a.lookup_async(sess.session_id) is None

    asyncio.run(go())


def test_persist_writes_through_after_state_change():
    """``persist`` is called by ``decrypt_request`` after the replay
    watermark advances; the new state must round-trip through Redis."""

    async def go() -> None:
        broker = FakeRedis()
        manager_a = SessionManager(
            ttl_seconds=3600,
            max_lifetime_seconds=28800,
            store=RedisSessionStore(broker),
        )
        manager_b = SessionManager(
            ttl_seconds=3600,
            max_lifetime_seconds=28800,
            store=RedisSessionStore(broker),
        )
        sess = await manager_a.create(_material())
        sess.replay.check_and_advance(5)
        sess.s2c_counter = 12
        await manager_a.persist(sess)
        # B sees the advanced state.
        seen = await manager_b.lookup_async(sess.session_id)
        assert seen is not None
        assert seen.replay.high == 5
        assert seen.s2c_counter == 12

    asyncio.run(go())


# ----- SessionStore Protocol contract -----


def test_inmemory_store_implements_protocol_surface():
    """If a method is renamed/removed on the protocol, this fails."""

    async def go() -> None:
        store = InMemorySessionStore()
        sess = _make_session()
        await store.put(sess)
        assert store.lookup(sess.session_id) is sess
        assert sess in store.all()
        # In-memory hydrate is an alias for lookup.
        assert await store.hydrate(sess.session_id) is sess
        assert await store.delete(sess.session_id) is True
        assert store.lookup(sess.session_id) is None
        assert await store.delete(sess.session_id) is False
        assert await store.reap_expired() == 0

    asyncio.run(go())


def test_inmemory_store_reaps_expired():
    async def go() -> None:
        store = InMemorySessionStore()
        live = _make_session()
        dead = _make_session()
        dead.last_used_at = time.time() - 100_000
        await store.put(live)
        await store.put(dead)
        assert await store.reap_expired() == 1
        assert store.lookup(live.session_id) is live
        assert store.lookup(dead.session_id) is None

    asyncio.run(go())


# ----- error path -----


def test_build_redis_session_store_missing_dep_raises():
    """If ``redis`` isn't installed, the helper must fail loudly with
    a remediation message — not silently drop into a degraded mode."""
    import sys

    saved = sys.modules.pop("redis.asyncio", None)
    saved_redis = sys.modules.pop("redis", None)
    sys.modules["redis"] = None  # type: ignore[assignment]
    try:
        from secure_llm_server.session.redis_store import build_redis_session_store

        with pytest.raises(RuntimeError, match=r"federation"):
            build_redis_session_store("redis://localhost:6379/0")
    finally:
        if saved is not None:
            sys.modules["redis.asyncio"] = saved
        if saved_redis is not None:
            sys.modules["redis"] = saved_redis
        else:
            sys.modules.pop("redis", None)
