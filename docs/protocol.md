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
| `POST` | `/v1/chat/completions` | encrypted envelope — SSE response when `stream=true` (v1.1) |
| `POST` | `/v1/completions` | encrypted envelope |
| `POST` | `/v1/embeddings` | encrypted envelope (v1.1) |
| `POST` | `/v1/system` | encrypted envelope |
| `POST` | `/v1/debug/{status,doctor,version,logs,errors}` | encrypted envelope |
| `POST` | `/v1/admin/...` | encrypted envelope, requires `admin` scope |
| `POST` | `/v1/admin/loras/{list,pull,rm,apply}` | encrypted envelope (v1.2) |
| `POST` | `/v1/admin/tenants/list` | encrypted envelope, requires `super_admin` (v1.2) |
| `GET` | `/healthz` `/readyz` | plain |
| `GET` | `/metrics` | Prometheus, served on internal bind |

**Tenant scoping (v1.2).** All envelope endpoints honor
`session.tenant`, which the server derives from the client's allowlist
entry during the handshake. The wire format does *not* carry a tenant
field — claiming a tenant is impossible from the wire alone. Admin
endpoints filter their view to the caller's tenant; cross-tenant ops
require the `super_admin` scope.

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

## Streaming (v1.1)

When the client sets `stream=true` on `/v1/chat/completions`, the
response is `Content-Type: text/event-stream`. Each `data:` line is a
**base64-encoded application-layer envelope** sealed with the
session's `s2c_key`. The envelope's counter shares the same monotonic
`s2c_counter` as non-streaming responses, so the receiver's replay
window catches duplicates regardless of which response path produced
them. The AAD's `path` field is the request path
(`/v1/chat/completions`), so an event captured here cannot be replayed
against another endpoint.

A keepalive every 15 seconds is emitted as a `data: …` event whose
plaintext is `{"keepalive": true}` — never a raw SSE comment, so it
still carries an envelope and a valid AAD. The stream terminates with
the literal line `data: [DONE]` (the OpenAI convention; plaintext, no
secret content).

Server-side streaming runs inside the inference worker (not the router
task), so the single-`Llama` invariant holds even mid-stream.
Cancellation propagates from `request.is_disconnected()` to a
`StreamHandle.cancel_event` checked between tokens — best-effort, not
synchronous.

## Embeddings (v1.1)

`POST /v1/embeddings` with `EmbeddingsRequest { model, input: str |
list[str] }` returns `EmbeddingsResponse { id, model, created, data:
list[{embedding, index}], usage }`. The server caches the loaded model
in a separate slot per `(model_id, "embedding")` so chat and embedding
mode on the same base model don't collide.

## LoRA adapters (v1.2)

Adapters are sealed with the server's age identity into
`data/loras/<sha>.lora.gguf.age` (or
`data/loras/tenants/<tenant>/<sha>.lora.gguf.age`). The wire types
are:

- `LoraRef { id: str, scale: float }` — a single adapter pin.
- `LoraInfo { id, repo_id, filename, sha256, bytes_on_disk,
  base_model_id? }`.
- `LoraDownloadRequest { repo_id, filename, sha256?, base_model_id? }`.
- `LoraApplyRequest { base_model_id, loras: list[LoraRef], n_ctx? }`.

`ChatCompletionRequest` and `CompletionRequest` carry an optional
`loras: list[LoraRef]` field. Setting it picks (or transparently
reloads into) a `(model, mode, lora-set)` slot. Cache eviction is
LRU across all slots.

## Tenants (v1.2)

Tenants are *server-side* metadata derived from
`AuthorizedClient.tenant` (loaded from
`data/keys/authorized_clients.toml` or
`data/keys/tenants/<tenant>/authorized_clients.toml`). The wire never
carries a `tenant` field — claiming a tenant is impossible from the
wire alone. Tenant context propagates through the session to:

- `ModelManager._loaded` cache key (`(tenant, model_id, mode, lora-fp)`),
- per-tenant `data/models/...` and `data/loras/...` directories,
- rate-limit bucket key (`f"{tenant}:{client_fp}"`),
- every audit event (`tenant=…` field),
- every structlog log line via contextvars.

The new `super_admin` scope is required for cross-tenant ops:
`/v1/admin/tenants/list` returns 403 (`admin_required`) without it,
and `/v1/admin/sessions/terminate` refuses to drop a session that
isn't in the caller's tenant unless the caller is `super_admin`.
