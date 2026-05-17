"""End-to-end handshake: server validates client, both sides derive same keys."""

from __future__ import annotations

import time

import pytest
from nacl.public import PrivateKey

from secure_llm_client.crypto.handshake import ClientIdentity as _CID
from secure_llm_client.crypto.handshake import (
    build_handshake_request,
    derive_session,
)
from secure_llm_protocol.errors import ErrorCode
from secure_llm_server.crypto.handshake import HandshakeError, perform_handshake
from secure_llm_server.crypto.keystore import AuthorizedClient, ServerIdentity


def _server_identity() -> ServerIdentity:
    from nacl.signing import SigningKey

    x = PrivateKey.generate()
    e = SigningKey.generate()
    from pathlib import Path

    return ServerIdentity(
        x25519_sk=x,
        x25519_pk=bytes(x.public_key),
        ed25519_sk=e,
        ed25519_pk=bytes(e.verify_key),
        age_secret_path=Path("/tmp/unused"),
    )


def _client_identity():
    from nacl.signing import SigningKey

    x = PrivateKey.generate()
    e = SigningKey.generate()
    return _CID(
        x25519_sk=x,
        x25519_pk=bytes(x.public_key),
        ed25519_sk=e,
        ed25519_pk=bytes(e.verify_key),
    )


def test_handshake_happy_path():
    server = _server_identity()
    client = _client_identity()
    allowlist = {
        client.x25519_pk: AuthorizedClient(
            name="t",
            x25519_pk=client.x25519_pk,
            ed25519_pk=client.ed25519_pk,
            scopes=("chat",),
        )
    }
    eph = PrivateKey.generate()
    ts = int(time.time())
    req = build_handshake_request(
        identity=client, server_host="h", client_eph_pk=bytes(eph.public_key), now=ts
    )
    resp, material = perform_handshake(
        req=req,
        server_identity=server,
        allowlist=allowlist,
        skew_seconds=30,
        ttl_seconds=3600,
        expected_host="h",
        now=ts,
    )
    outcome = derive_session(
        identity=client,
        client_eph_sk=eph,
        server_host="h",
        handshake_request_ts=ts,
        response=resp,
        pinned_server_static_pk=server.x25519_pk,
    )
    assert material.session_id == outcome.session_id
    assert material.c2s.key == outcome.c2s.key
    assert material.s2c.key == outcome.s2c.key


def test_unknown_client_rejected():
    server = _server_identity()
    client = _client_identity()
    eph = PrivateKey.generate()
    ts = int(time.time())
    req = build_handshake_request(
        identity=client, server_host="h", client_eph_pk=bytes(eph.public_key), now=ts
    )
    with pytest.raises(HandshakeError) as exc:
        perform_handshake(
            req=req,
            server_identity=server,
            allowlist={},
            skew_seconds=30,
            ttl_seconds=3600,
            expected_host="h",
            now=ts,
        )
    assert exc.value.code == ErrorCode.UNKNOWN_CLIENT


def test_revoked_client_rejected():
    server = _server_identity()
    client = _client_identity()
    allowlist = {
        client.x25519_pk: AuthorizedClient(
            name="t",
            x25519_pk=client.x25519_pk,
            ed25519_pk=client.ed25519_pk,
            scopes=("chat",),
            revoked=True,
        )
    }
    eph = PrivateKey.generate()
    ts = int(time.time())
    req = build_handshake_request(
        identity=client, server_host="h", client_eph_pk=bytes(eph.public_key), now=ts
    )
    with pytest.raises(HandshakeError) as exc:
        perform_handshake(
            req=req,
            server_identity=server,
            allowlist=allowlist,
            skew_seconds=30,
            ttl_seconds=3600,
            expected_host="h",
            now=ts,
        )
    assert exc.value.code == ErrorCode.CLIENT_REVOKED


def test_clock_skew_rejected():
    server = _server_identity()
    client = _client_identity()
    allowlist = {
        client.x25519_pk: AuthorizedClient(
            name="t",
            x25519_pk=client.x25519_pk,
            ed25519_pk=client.ed25519_pk,
        )
    }
    eph = PrivateKey.generate()
    now = int(time.time())
    req = build_handshake_request(
        identity=client, server_host="h", client_eph_pk=bytes(eph.public_key), now=now - 600
    )
    with pytest.raises(HandshakeError) as exc:
        perform_handshake(
            req=req,
            server_identity=server,
            allowlist=allowlist,
            skew_seconds=30,
            ttl_seconds=3600,
            expected_host="h",
            now=now,
        )
    assert exc.value.code == ErrorCode.CLOCK_SKEW
