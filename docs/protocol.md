# Wire protocol (v1.0)

This document is the byte-for-byte spec. The Python schemas in
`protocol/secure_llm_protocol/` are the canonical implementation; if the
two disagree, the implementation wins and this doc gets updated.

## Endpoints

| Method | Path | Body |
|---|---|---|
| `POST` | `/v1/session` | plaintext JSON `HandshakeRequest` → `HandshakeResponse` |
| `DELETE` | `/v1/session/{id_b64}` | plaintext, idempotent terminate |
| `POST` | `/v1/models/list` | encrypted envelope |
| `POST` | `/v1/models/download` | encrypted envelope |
| `POST` | `/v1/models/remove` | encrypted envelope |
| `POST` | `/v1/chat/completions` | encrypted envelope |
| `POST` | `/v1/completions` | encrypted envelope |
| `POST` | `/v1/system` | encrypted envelope |
| `POST` | `/v1/debug/{status,doctor,version,logs,errors}` | encrypted envelope |
| `POST` | `/v1/admin/...` | encrypted envelope, requires `admin` scope |
| `GET` | `/healthz` `/readyz` | plain |
| `GET` | `/metrics` | Prometheus, served on internal bind |

## Handshake

Plain JSON, only endpoint that is.

`HandshakeRequest` carries `client_static_pk`, `client_ephemeral_pk`,
`timestamp`, `transcript_sig` (Ed25519). Server verifies allowlist
membership, scopes, validity window, signature, and clock skew (≤30s).

Server derives `session_key = HKDF-SHA-256(ikm, salt, info, 32+32+4+4)`
where:

```
ikm  = X25519(server_eph_sk, client_eph_pk) || X25519(server_static_sk, client_static_pk)
salt = full transcript bytes
info = "secure-llm session keys v1"
```

Keystream layout: `[c2s_key(32) | s2c_key(32) | c2s_prefix(4) | s2c_prefix(4)]`.

Response includes `server_static_pk`, `server_ephemeral_pk`,
`session_id` (16 bytes, base64), `ttl_seconds`, `server_sig` (Ed25519
over the full transcript), and the two nonce prefixes (hex).

## Envelope (everything else)

```
magic(4 = "SLLM") | version(1 = 0x01) | session_id(16) | counter(8) | nonce(12) | ciphertext | tag(16)
```

- `nonce` is `prefix(4) || counter(8)` (big-endian). The 4-byte prefix
  per-direction comes from the handshake.
- `ciphertext` is `ChaCha20-Poly1305-IETF(plaintext, key, nonce, aad)`.
- `aad = magic || version || session_id || counter || method || path`
  where `method` is uppercase ASCII and `path` is UTF-8.
- Counters are strictly monotonic per direction. Receivers keep a
  1024-bit sliding window and reject duplicates or anything older.
- Replay across directions is impossible because `c2s_key != s2c_key`.

Failures (malformed framing, replay, AEAD verify, schema validation) all
respond with a JSON error envelope:

```json
{ "code": "decrypt_failed", "message": "...", "error_id": "ABCDEF12" }
```

Auth-related failures pad latency with a configurable floor (default
200 ms) to dampen timing oracles.

## Error codes

Canonical list in `protocol/secure_llm_protocol/errors.py`. Stable
strings — clients pattern-match on them. Adding a code is a minor bump;
renaming or removing one is a major bump.

## Versioning

`PROTOCOL_VERSION = "1.0"`. Major bump = wire-incompatible change. The
handshake's `protocol` field is checked first; mismatch produces
`handshake_version_mismatch` and the session is not created.

## Streaming (deferred to v1.1)

Server v1.0 returns `bad_request` if `stream=true`. v1.1 will add SSE
with per-event envelopes sharing the session's s2c counter; keepalive
frames are encrypted comments.
