"""SessionManager lifecycle: create, lookup, expiry, terminate, reap, has_scope."""

from __future__ import annotations

import secrets
import time

import pytest

from secure_llm_server.crypto.envelope import DirectionKeys
from secure_llm_server.crypto.handshake import SessionMaterial
from secure_llm_server.session.manager import SessionManager


def _material(*, ttl: int = 3600, scopes: tuple[str, ...] = ("chat",)) -> SessionMaterial:
    return SessionMaterial(
        session_id=secrets.token_bytes(16),
        c2s=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        s2c=DirectionKeys(key=secrets.token_bytes(32), nonce_prefix=secrets.token_bytes(4)),
        ttl_seconds=ttl,
        client_fingerprint="fp",
        scopes=scopes,
        tenant="default",
    )


@pytest.mark.asyncio
async def test_create_lookup_terminate_zeroizes():
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)
    sess = await sm.create(_material())
    sid = sess.session_id
    assert sm.lookup(sid) is sess
    saved_key = sess.s2c.key
    assert any(b != 0 for b in saved_key)  # not yet zeroed

    assert await sm.terminate(sid) is True
    # The session's key fields are zeroed.
    assert all(b == 0 for b in sess.s2c.key)
    assert all(b == 0 for b in sess.c2s.key)
    assert sm.lookup(sid) is None
    # Second terminate is a no-op.
    assert await sm.terminate(sid) is False


@pytest.mark.asyncio
async def test_has_scope_and_b64_helpers():
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)
    sess = await sm.create(_material(scopes=("chat", "admin")))
    assert sess.has_scope("admin") is True
    assert sess.has_scope("ghost") is False
    assert isinstance(sess.session_id_b64, str) and len(sess.session_id_b64) > 0


@pytest.mark.asyncio
async def test_expired_session_pruned_on_lookup():
    sm = SessionManager(ttl_seconds=1, max_lifetime_seconds=10)
    sess = await sm.create(_material(ttl=1))
    sid = sess.session_id
    # Force expiry by rewinding last_used_at.
    sess.last_used_at = time.time() - 100
    assert sm.lookup(sid) is None
    # Subsequent lookup is also None (entry was popped on the first miss).
    assert sm.lookup(sid) is None


@pytest.mark.asyncio
async def test_reap_expired():
    sm = SessionManager(ttl_seconds=1, max_lifetime_seconds=10)
    live = await sm.create(_material())
    dead = await sm.create(_material(ttl=1))
    dead.last_used_at = time.time() - 100
    n = await sm.reap_expired()
    assert n == 1
    # Live session still findable.
    assert sm.lookup(live.session_id) is live


@pytest.mark.asyncio
async def test_all_filters_expired():
    sm = SessionManager(ttl_seconds=1, max_lifetime_seconds=10)
    a = await sm.create(_material())
    b = await sm.create(_material(ttl=1))
    b.last_used_at = time.time() - 100
    ids = {s.session_id for s in sm.all()}
    assert a.session_id in ids
    assert b.session_id not in ids
