"""Client-side known_hosts (TOFU pinning store)."""

from __future__ import annotations

import secrets
from pathlib import Path

from secure_llm_client import known_hosts


def test_load_missing_file_returns_empty(tmp_path: Path):
    assert known_hosts.load(tmp_path / "nope.toml") == {}


def test_trust_then_lookup_roundtrip(tmp_path: Path):
    path = tmp_path / "known.toml"
    pk = secrets.token_bytes(32)
    known_hosts.trust(path, "example.com:8443", pk, note="prod")
    entry = known_hosts.lookup(path, "example.com:8443")
    assert entry is not None
    assert entry.x25519_pk == pk
    # Adding a second host preserves the first.
    pk2 = secrets.token_bytes(32)
    known_hosts.trust(path, "other.example.com:8443", pk2)
    loaded = known_hosts.load(path)
    assert set(loaded) == {"example.com:8443", "other.example.com:8443"}
    assert loaded["other.example.com:8443"].x25519_pk == pk2


def test_lookup_unknown_host(tmp_path: Path):
    path = tmp_path / "known.toml"
    known_hosts.trust(path, "a:1", secrets.token_bytes(32))
    assert known_hosts.lookup(path, "b:2") is None
