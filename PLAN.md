# Plan: v1.1 → v2.0 Roadmap

## Context

v1.0 shipped; every test target is green. The user wants the v1
"out-of-scope" list above converted into a real implementation
roadmap. Goal: a phased plan with concrete file paths and reusable
hooks so each feature can be picked up independently without
re-discovering the codebase.

Touchpoints surveyed (Phase 1 exploration — verified file paths and
current shapes):

| Feature | Files | Reuses | Size |
|---|---|---|---|
| SSE streaming | `server/.../routers/chat.py:46-100`, `server/.../llm/backend.py:49-56`, `client/.../transport.py:147-182` | backend already returns the llama iterator when `stream=True` — only the router and client transport need to learn SSE | M |
| Embeddings | new `server/.../routers/embeddings.py`, `server/.../models/manager.py:65-288` | mirrors `routers/completions.py`; add `embed()` to ModelManager | S |
| LoRA hot-swap | `server/.../llm/backend.py:21-47`, `server/.../models/manager.py:187-214` | extend `LlamaBackend.__init__` (llama.cpp itself needs a reload to swap LoRA — no true hot-swap) | M |
| Multi-tenant | `server/.../crypto/keystore.py:40-47`, `server/.../models/registry.py:23-40` | add `tenant: str` to `AuthorizedClient` + `ModelEntry`; namespace storage dir | S–M |
| Federation | `server/.../session/manager.py:49-121`, `server/.../crypto/keystore.py:119-137`, `server/.../config.py:78-113` | refactor `SessionManager` behind a `SessionStore` interface; pluggable identity backend | L |
| TEE / attestation | `server/.../crypto/handshake.py:183-192`, `protocol/.../schemas.py:30-39`, `protocol/.../version.py` | add optional `attestation_report` field to `HandshakeResponse` (backward-compat); real attestation gate at v2.0 | S→L |
| Multimodal | `protocol/.../schemas.py:57-60`, `protocol/.../wire.py:30` | widen `ChatMessage.content` to `str \| list[ChatContentPart]`; add `clip_model_path` to backend | S→M |

## Phasing

```
v1.1   Streaming + Embeddings              ~1–2 sprints
v1.2   LoRA hot-swap + Multi-tenant        ~2–3 sprints
v1.3   Federated routing                   ~1 sprint
v2.0   TEE attestation + Multimodal        ~3–6 months
```

Cross-cutting invariants that must survive every phase:

- `protocol/secure_llm_protocol/` stays the single source of wire truth.
- Payload-redaction in `server/.../logging.py` continues to scrub all
  new content fields (images, audio, embeddings inputs).
- AEAD AAD includes the new endpoint paths.
- `_require_admin` guards every new admin endpoint.
- One inference worker per loaded model — never share `Llama` across
  tasks, even for embeddings.

---

## v1.1 — SSE streaming + Embeddings

### SSE streaming chat completions

**Wire-format addition.** SSE response with `Content-Type:
text/event-stream`. Each event payload is one application-layer
envelope (same `s2c_key`, same monotonic `s2c_counter`); the AAD's
`path` field is the request path so framing is identical to a
regular response. Client iterates `r.iter_lines()`, decodes each
`data:` line as base64, opens the envelope, parses
`ChatCompletionChunk`.

**Server (`server/secure_llm_server/`):**
- `routers/chat.py`: drop the v1 "stream=true → bad_request" branch.
  When `stream=True`, return `fastapi.responses.StreamingResponse`
  wrapping a generator that runs the llama iterator off-thread.
- `llm/streaming.py` (new): `async def stream_chat_envelopes(session,
  iterator, method, path) -> AsyncIterator[bytes]` — yields one SSE
  frame per token chunk. Keepalive frame every 15 s (encrypted SSE
  comment). Cancellation propagates from `request.is_disconnected()`.
- `models/manager.py`: `chat(..., stream=True)` already returns the
  llama iterator via `_submit`; expose a cancellation event on `_Job`
  so the worker can break between tokens.

**Client (`client/secure_llm_client/`):**
- `transport.py`: add `stream_request(method, path, payload)` mirror
  of `request()`. Reads lines, opens each envelope, yields the parsed
  pydantic model. Replay window check is per-line.
- `resources/chat.py`: when `stream=True`, return the iterator
  directly instead of constructing the non-streaming response.

**Tests:**
- `server/tests/unit/test_streaming.py`: encode/decode round-trip of
  10 stream chunks; counter monotonic; tamper-any-chunk → fail.
- `server/tests/integration/test_chat_stream.py`: real SSE over
  `fastapi.testclient.TestClient` with a fake llama iterator;
  validate ordering + cancellation.

**No `PROTOCOL_VERSION` bump.** SSE is additive on the same endpoint.

### Embeddings endpoint

**Protocol (`protocol/secure_llm_protocol/schemas.py`):**
- Add `EmbeddingsRequest { model: str, input: str | list[str] }`.
- Add `EmbeddingsResponse { id, model, data: list[{embedding:
  list[float], index: int}], usage: { prompt_tokens, total_tokens }
  }`.

**Server:**
- `routers/embeddings.py` (new): POST `/v1/embeddings`, envelope as
  every other endpoint; calls `ModelManager.embed(...)`.
- `models/manager.py`: add `async def embed(self, *, model_id,
  inputs)` mirroring `chat`/`complete`. Submits an
  `_Job(kind="embed")`.
- `llm/backend.py`: add `def embed(self, *, inputs, **opts) -> Any`
  calling `Llama.create_embedding`. Note: `Llama(embedding=True)`
  must be set at construction; cache a separate `Loaded` slot keyed
  by `(model_id, mode)` so embed and chat can coexist on the same
  model.
- `models/registry.py`: add optional `supported_modes:
  list[Literal["chat", "embedding"]]` to `ModelEntry`; default
  `["chat", "embedding"]`.

**Client:**
- `resources/embeddings.py` (new): `client.embeddings.create(model=,
  input=)`.
- `cli/__main__.py`: `sllm embed --model X "text"` subcommand.

**Tests:** unit + integration with a small embedding GGUF if
available; otherwise mock the backend.

### v1.1 deliverables
- New endpoints: `/v1/chat/completions` (streaming-capable),
  `/v1/embeddings`.
- New SDK surfaces: `client.chat.completions.create(stream=True)`
  returns an iterator; `client.embeddings.create(...)`.
- New tests + `make smoke-v11` target.

---

## v1.2 — LoRA hot-swap + Multi-tenant

### LoRA hot-swap

llama-cpp-python applies LoRA at `Llama` construction via
`lora_path=`/`lora_scale=`; there is no in-place "hot swap" without
a reload. The plan reflects that constraint.

**Server:**
- `crypto/at_rest.py` already encrypts/decrypts arbitrary blobs;
  reuse for `.lora.gguf.age` files.
- `models/registry.py`: add `LoraEntry` (sibling of `ModelEntry`):
  `{id, base_model_id?, sha256, filename, bytes_ciphertext,
  scope: list[str]}`. Stored under `data/loras/<sha>.lora.gguf.age`.
- `models/downloader.py`: same HF + SHA-verify pipeline,
  parameterized on the destination directory.
- `llm/backend.py`: `LlamaBackend.__init__` gains
  `lora_paths: list[tuple[Path, float]] = []`. Passed to `Llama(...,
  lora_path=..., lora_scale=...)`.
- `models/manager.py`: extend `_Loaded` with `applied_loras:
  tuple[str, ...]`. `ensure_loaded(model_id, n_ctx, loras=())` — if
  the loaded model's `applied_loras` differ, evict and reload
  (LRU-aware). Backend reload via the same `decrypt_to_tmpfs` path.

**Admin endpoints (`routers/admin.py`):**
- `POST /v1/admin/loras/list`
- `POST /v1/admin/loras/pull` (HF repo + filename → seal at rest)
- `POST /v1/admin/loras/rm`
- `POST /v1/admin/loras/apply {base_model_id, lora_id, scale=1.0}`
  → triggers reload via `ModelManager.ensure_loaded(...,
  loras=((lora_id, scale),))`.

**Sampling request schema:** add optional `loras:
list[{id: str, scale: float}]` to `ChatCompletionRequest` and
`CompletionRequest` so callers can request a specific adapter
without an admin call.

**CLI:** `sllm loras list/pull/rm/apply` under the admin namespace.

### Multi-tenant isolation

**Concept:** every request carries a tenant id derived from the
client's allowlist entry. Per-tenant: allowlist, models, sessions,
rate limit, disk quota, audit log tag.

**Server changes:**
- `crypto/keystore.py:40-47`: add `tenant: str | None = None` to
  `AuthorizedClient`. `tenant=None` is the `"default"` tenant.
- Allowlist file layout: `data/keys/authorized_clients.toml`
  (default tenant) **plus** optional
  `data/keys/tenants/<tenant>/authorized_clients.toml`.
  `load_allowlist` is extended to read all files; entries from
  per-tenant files are forced to carry that tenant.
- `models/registry.py:23-40`: add `tenant: str` to `ModelEntry`.
  Storage path becomes `data/models/<tenant>/<sha>.gguf.age`.
  `ModelRegistry` is split into `MultiTenantRegistry`
  → `TenantRegistry` per tenant, keyed in the manager.
- `models/manager.py`: every operation gains a `tenant` parameter.
  `Loaded` slots are keyed by `(tenant, model_id)`. Per-tenant
  `max_loaded`, per-tenant `disk_quota_gb`.
- `crypto/handshake.py`: `SessionMaterial.tenant` set from the
  allowlist entry.
- `session/manager.py`: `Session.tenant` field.
- `routers/_envelope_dep.py:98-103`: bind `tenant=` into structlog
  contextvars so every log line + audit event carries it.
- `middleware/rate_limit.py`: bucket key becomes
  `f"{tenant}:{client_fp}"`.

**Admin surface:**
- A new `super_admin` scope (server-wide). Existing `admin` scope is
  now per-tenant: an admin can only see/mutate their own tenant.
- `POST /v1/admin/tenants/list` (super_admin only).
- `POST /v1/admin/tenants/quota` (super_admin only).

**Protocol:** no breaking change. `HandshakeResponse` doesn't
expose `tenant`; tenant context is server-side metadata.

**Tests:** integration tests that two clients in different tenants
cannot see each other's models, sessions, logs, or errors. A
`super_admin` can; a regular admin cannot.

### v1.2 deliverables
- LoRA pull/apply/remove + per-request LoRA selection.
- Per-tenant allowlist, models, sessions, rate limits, quotas, audit.
- `make smoke-v12` covering both flows.

---

## v1.3 — Federated routing

**Goal:** N stateless servers behind a load balancer; clients
TOFU-pin a single server identity shared across the fleet.

**Server changes:**
- `session/manager.py`: extract `SessionStore` Protocol
  (`get/put/delete/all`). Keep `InMemorySessionStore` as default;
  add `RedisSessionStore` (uses Redis with TTL). Envelope keys are
  base64-encoded in Redis values but the Redis instance is treated
  as trusted — same trust boundary as the server. Document this in
  `docs/threat-model.md`.
- `crypto/keystore.py`: introduce `KeystoreBackend` Protocol with
  `FileKeystoreBackend` (current) and `SealedKeystoreBackend` for
  v2.0 (TEE). For v1.3, the file backend is what's used; all
  instances mount the same `data/keys/` volume or sync via the
  operator's config-management tool.
- `config.py`: new `[federation]` section:
  ```toml
  [federation]
  session_store = "memory"          # or "redis"
  session_store_url = "redis://..."
  identity_replicated = true        # informational; affects rotation runbook
  ```

**Load balancer:**
- TLS termination at the LB is *forbidden*: clients verify the
  envelope identity directly, and SNI passthrough is required.
  Documented in `docs/operator-guide.md` as a hard rule.
- LB checks `/healthz` and `/readyz`.

**Operator runbook update (`docs/runbook.md`):**
- "Rolling restart with shared identity" — new section.
- "Adding a node" — copy keys + config, register with LB, done.

**Tests:**
- Integration with two servers behind a `httpx` test load balancer;
  client sessions survive failover when Redis store is used.

---

## v2.0 — TEE attestation + Multimodal

### Confidential computing / TEE attestation

**Approach:** AMD SEV-SNP first (broadest cloud support: GCP, Azure,
AWS m6i.metal); Nitro Enclaves added later as a second backend.

**Protocol bump:** `PROTOCOL_VERSION = "2.0"`. Old clients can still
talk if the server's TEE policy allows degraded sessions; default is
"attestation required".

**Schema (`protocol/secure_llm_protocol/schemas.py:30-39`):**
- `HandshakeResponse.attestation_report: str | None`. Base64 of the
  vendor-format attestation blob, signed by the TEE hardware. The
  blob's userdata is the SHA-256 of the full handshake transcript so
  it can't be detached and reused.

**Server (`server/secure_llm_server/`):**
- `crypto/attestation.py` (new):
  - `AttestationBackend` Protocol with `generate(transcript_digest:
    bytes) -> bytes`.
  - `SevSnpBackend`, `NitroEnclaveBackend`, `NoneBackend` (dev only).
- `crypto/handshake.py:183-192`: append the attestation report
  before signing; the Ed25519 sig still covers everything.
- Server identity unseal: at boot, the `age` identity is fetched
  via attestation-gated unseal — the cloud KMS only releases the
  key to a measurement that matches the expected hash of the
  running binary + config.

**Client (`client/secure_llm_client/`):**
- `crypto/attestation.py` (new): verifies SEV-SNP attestation chain
  against vendor root certs (pinned). Verifies the attestation's
  userdata is `SHA-256(transcript)`. Verifies the measurement matches
  one of the operator-pinned values in `known_servers.toml`.
- `known_hosts.py`: extended TOML schema:
  ```toml
  [[hosts]]
  host = "..."
  x25519_pk = "..."
  ed25519_pk = "..."
  measurement = "sha384-of-sealed-image"  # optional; required for TEE mode
  attestation_required = true
  ```

**Deployment changes:**
- `server/deploy/sev-snp/` (new): Terraform + cloud-init for a
  SEV-SNP-enabled VM, KMS policies, IDB binding the measurement to
  the age identity unseal.
- `server/Dockerfile`: nothing changes (the image runs inside the
  TEE VM).

**Tests:**
- CI: `MockAttestationBackend` that produces a deterministic blob;
  integration test verifies the round-trip + transcript binding.
- Pre-prod: hardware test on a SEV-SNP host; verifies the real
  attestation chain.

### Multimodal (image + audio)

**Image (Llava-style):**
- `protocol/.../schemas.py:57-60`: widen `ChatMessage.content` to
  `str | list[ChatContentPart]` where `ChatContentPart` is
  `{type: "text", text: str}` or `{type: "image", data: str}` (base64
  PNG/JPEG). OpenAI-compatible shape.
- `protocol/.../wire.py:30`: `MAX_REQUEST_BYTES` raised to 32 MiB;
  server admin still caps it lower via `[limits].max_request_bytes`.
- `llm/backend.py`: `LlamaBackend.__init__` accepts
  `clip_model_path: Path | None`. When set, `Llama(...,
  clip_model_path=...)` enables vision.
- `models/registry.py`: `ModelEntry.clip_companion: str | None`
  references the CLIP sidecar GGUF by id.

**Audio (transcription):**
- New protocol type `TranscriptionRequest { model, audio: bytes,
  language? }`, `TranscriptionResponse { text }`.
- New endpoint `/v1/audio/transcriptions` mirroring the OpenAI shape.
- Bundle `whisper-cpp-python` (or vendor `whisper.cpp` via a
  subprocess with envelope wrapping at the IPC boundary if the
  Python binding is unstable).
- `routers/audio.py` (new), `client.audio.transcribe(...)`.

**Tests:**
- Image: end-to-end with a tiny Llava GGUF + a 16×16 test PNG.
- Audio: 1-second silent WAV → expect empty text without crash.

---

## Files to create / modify (cross-phase)

**New:**
- `server/secure_llm_server/llm/streaming.py`
- `server/secure_llm_server/routers/{embeddings,audio}.py`
- `server/secure_llm_server/crypto/attestation.py`
- `server/secure_llm_server/session/redis_store.py`
- `client/secure_llm_client/resources/{embeddings,audio}.py`
- `client/secure_llm_client/crypto/attestation.py`
- `protocol/secure_llm_protocol/multimodal.py` (the
  `ChatContentPart` union)
- `server/deploy/sev-snp/` (Terraform + cloud-init)

**Modified (well-defined hooks listed above):**
- `protocol/secure_llm_protocol/{schemas,wire,version}.py`
- `server/secure_llm_server/{routers/chat,llm/backend,models/manager,
  models/registry,models/downloader,crypto/keystore,crypto/handshake,
  session/manager,config,routers/_envelope_dep,middleware/rate_limit}.py`
- `client/secure_llm_client/{transport,client,known_hosts,resources/chat,
  resources/models,cli/__main__}.py`
- `docs/{protocol,threat-model,operator-guide,runbook}.md`
- `Makefile` (add `smoke-v11`, `smoke-v12`, `smoke-v13`, `smoke-v20`)

## Reused existing utilities

- `crypto/at_rest.py:encrypt_file` + `decrypt_to_tmpfs` — also
  handles LoRA blobs; just a parameterized dest dir.
- `crypto/envelope.py:seal` / `open_envelope` — unchanged for SSE;
  one envelope per SSE event.
- `models/downloader.py:download_and_seal` — parameterize dest dir
  for LoRAs and per-tenant model dirs.
- `routers/_envelope_dep.py:decrypt_request` / `encrypt_response` —
  every new endpoint uses these unchanged.
- `crypto/handshake.py:perform_handshake` — `attestation_report` is
  added inside this function before signing; surrounding flow is
  unchanged.
- `observability/{error_tracker,ring_log,status}.py` — tenant id
  flows into existing structures via the `client_fp` adjacency.
- `Makefile` `bootstrap` / `doctor` — extended (not rewritten) to
  cover new deployment shapes (Redis health check, TEE measurement
  print).

## Verification per phase

| Phase | Verification |
|---|---|
| v1.1 | `make smoke-v11`: handshake → streaming chat (assert ordered chunks + cancellation) → `client.embeddings.create` → cosine similarity sanity. Property tests for the SSE envelope stream. |
| v1.2 | `make smoke-v12`: handshake → pull LoRA → apply → chat → verify the LoRA changes output → revoke → expect reload without it. Multi-tenant: two clients in tenants A and B; assert each cannot see the other's models or sessions; super_admin can. |
| v1.3 | Two-instance `docker-compose` with Redis; chaos test: kill instance A mid-session → assert session survives on instance B (Redis store) or fails cleanly (memory store). Pcap test still passes across instances. |
| v2.0 | Mock attestation: client refuses session if measurement doesn't match `known_servers.toml`. Image chat: round-trip a Llava prompt + tiny image; assert response is non-empty. Audio: 1 s WAV → empty transcript without exception. Real-hardware test on a SEV-SNP node before tagging the v2.0 release. |

Each phase ends with: `make lint type test sec` green, the new
smoke target green, and a CHANGELOG entry tagged with the protocol
version or scope.

## Out of scope for this roadmap

- Fine-tuning (training, not inference) — different product.
- Vector storage / RAG plumbing — the embeddings endpoint feeds it
  but storage is the caller's problem.
- A web UI — CLI + SDK only.
- Federation across mutually distrusting operators — single
  operator controls the fleet.
