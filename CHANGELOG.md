# Changelog

All notable changes to this project will be documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v2.0 foundation (TEE attestation + multimodal)
- **`AttestationBackend` Protocol** (server) + **`AttestationVerifier`
  Protocol** (client). Three server backends ship: `NoneBackend`
  (default, attestation disabled), `MockAttestationBackend`
  (deterministic HMAC-signed blob for CI), and `SevSnpBackend` /
  `NitroEnclaveBackend` stubs that raise `NotImplementedError` until
  the `server/deploy/sev-snp/` infrastructure lands. Client side:
  `NoneVerifier` and `MockAttestationVerifier`.
- **Optional `attestation_report` field** on `HandshakeResponse`. The
  report's userdata is bound to `SHA-256(full_handshake_transcript)`,
  so a captured report cannot be detached and replayed against a
  different handshake. The Ed25519 transcript signature is unchanged
  and independent — old clients still verify cleanly.
- **`known_hosts.toml` schema** extended with optional `measurement`
  and `attestation_required` per host. Honored by the SDK when the
  caller passes an `attestation_verifier` to `Transport`. Fail-closed
  semantics: an attested server without a configured verifier, or a
  measurement mismatch, raises `ServerKeyMismatch`.
- **Multimodal content parts.** `ChatMessage.content` widened from
  `str` to `str | list[ChatContentPart]` (OpenAI-shape). Parts: text
  (`{type: "text", text}`) and image_url (`{type: "image_url",
  image_url: {url, detail}}`). Only `data:` URIs are honored;
  `https://` URLs are refused to prevent egress via prompt injection.
- **`MAX_REQUEST_BYTES` raised from 8 MiB to 32 MiB.** Operators can
  still cap lower per-deployment via `[limits].max_request_bytes`.
- **`LlamaBackend.clip_model_path`** parameter for Llava-style models;
  routed via `ModelEntry.clip_companion`. Hardware test path arrives
  with a real Llava GGUF in a follow-up.
- 27 new tests: round-trip, transcript binding, measurement mismatch,
  wrong shared secret, malformed blob, wrong-type blob, `NoneVerifier`
  fail-closed on pinned measurement, stub backends raise, full
  handshake integration (success / measurement mismatch /
  required-but-omitted / no-verifier-rejected), schema tests for
  text + image_url parts, mixed-content round-trip, invalid part types.

### Added — v1.3 scope (federated routing)
- **`SessionStore` Protocol** with `InMemorySessionStore` (default)
  and `RedisSessionStore` (opt-in via `[federation].session_store =
  "redis"`). `SessionManager` delegates all backing-store ops to the
  Protocol; the hot path (`lookup`) stays sync so single-instance
  deployments pay no Redis latency.
- **Failover semantics.** `SessionManager.lookup_async` falls back to
  the backing store on cache miss, letting instance B serve a session
  created on instance A after a load-balancer failover. AEAD direction
  keys, replay watermark (`head`), counter, tenant and scopes are
  mirrored to Redis with the session's natural TTL. The 1024-bit
  replay bitmap stays per-instance — counter monotonicity makes this
  safe; documented in `docs/threat-model.md`.
- **`KeystoreBackend` Protocol + `FileKeystoreBackend`** wrapping the
  existing on-disk keystore. v2.0's TEE-sealed backend will drop into
  the same interface without touching the rest of the codebase.
- **`[federation]` config section**: `session_store`,
  `session_store_url`, `identity_replicated`. Boot fails closed if
  `session_store="redis"` is set without a URL.
- **Optional dependency**: `pip install secure-llm-server[federation]`
  brings in `redis>=5.0`. The base install is unchanged.
- **Operator-facing docs**: rolling-restart-with-shared-identity and
  add-a-node procedures (`docs/operator-guide.md`); Redis-unreachable
  and instance-identity-mismatch incidents (`docs/runbook.md`); Redis
  trust-boundary + failover-window rationale (`docs/threat-model.md`).
- 21 new tests: serialization round-trip, Redis-store put/hydrate/
  delete/reap, failover scenarios (session-on-A-visible-on-B,
  terminate-on-B-propagates), persist write-through, `InMemoryStore`
  Protocol contract, `FileKeystoreBackend` round-trip, missing-redis
  remediation message.

### Added — v1.2 scope (LoRA hot-swap + multi-tenant)
- **LoRA adapters**. New `LoraRegistry` (sibling of `ModelRegistry`),
  `download_and_seal_lora` (HF + SHA-verify + age-encrypt to
  `data/loras/<sha>.lora.gguf.age`), `LlamaBackend(lora_paths=…)`,
  `ModelManager.ensure_loaded(loras=…)` with cache-key extension so
  `(model, mode, lora-set)` triples coexist as separate LRU slots.
  Public surface: `POST /v1/admin/loras/{list,pull,rm,apply}`,
  per-request `loras: list[LoraRef]` on chat/completion, SDK
  `client.admin.loras.*`, CLI `sllm admin loras …`.
- **Multi-tenant isolation**. `AuthorizedClient.tenant` (default
  `"default"`), per-tenant allowlist files
  (`data/keys/tenants/<tenant>/authorized_clients.toml` — directory
  forces the tenant), `MultiTenantRegistry` / `MultiTenantLoraRegistry`
  factories returning per-tenant registries, `ModelManager._loaded`
  keyed by `(tenant, model_id, mode, lora-fp)`, structlog contextvars
  + audit events tagged with tenant, rate-limit bucket keyed by
  `(tenant, fingerprint)`. New `super_admin` scope; tenant-admins are
  scoped to their own tenant on `sessions/list`, `clients/list`,
  `sessions/terminate`. New `POST /v1/admin/tenants/list` (super_admin
  only) rolls up clients/sessions/models per tenant.
- `make smoke-v12` target.

### Added — v1.1 scope (streaming + embeddings)
- **SSE streaming chat completions.** `POST /v1/chat/completions` with
  `stream=true` returns `text/event-stream`; each event is a fresh
  application-layer envelope (same s2c key, monotonic counter, AAD bound
  to method+path). New `server/secure_llm_server/llm/streaming.py` does
  the encoding; `client.chat.completions.create(stream=True)` returns an
  `Iterator[ChatCompletionChunk]`. ModelManager now drains the llama
  generator off-thread so the single-inference-worker invariant survives
  streaming; cancellation propagates from `request.is_disconnected()`.
- **Embeddings.** `POST /v1/embeddings` (OpenAI-shaped). New
  `EmbeddingsRequest`/`EmbeddingsResponse` schemas, `LlamaBackend.embed`,
  `ModelManager.embed`, separate `(model_id, "embedding")` Loaded slot
  so embed/chat modes coexist without colliding. Client surface:
  `client.embeddings.create(model=, input=)`; CLI: `sllm embed`.
- `make smoke-v11` target covering both flows via integration tests.

### Changed
- Coverage gate (`[tool.coverage.report].fail_under`) lowered from 75 → 55
  and an `omit` list added for modules that can only be exercised by
  `make smoke*` (`main.py`, `lifespan.py`, `scripts_*.py`, `cli/__main__.py`,
  `llm/backend.py`, `models/{manager,downloader}.py`, `sysinfo.py`).
  Router-level integration tests for `completions`, `debug`, `models`,
  and `system` landed (16 new tests, +10 percentage points); gate now
  set to 65, measured 65.85%. Next ratchet targets `admin` (39%),
  `_envelope_dep` (62%), `session/manager` (61%), and the middleware
  trio.
- Coverage gate raised from 65 → 92 after a six-wave push (149 new
  tests, +29 percentage points): middleware deny + happy paths; admin
  endpoint sweep; registry + LoRA + multi-tenant factory; session
  manager lifecycle; StatusBuilder snapshots; six envelope error paths
  (too-short body, malformed header, unknown session, replay, AEAD
  failure, schema mismatch); session DELETE; chat non-streaming;
  embeddings ManagerError; SDK conversation/system/completions/
  embeddings/models/debug/admin surfaces; transport session-expired
  rehandshake + plain-JSON error envelope + malformed SSE base64;
  at-rest age round-trip; keystore init/load + permissions + reload;
  config path resolution; readiness check; wire framing + KDF; ring
  log; admin deny sweep (non-admin scope across every admin route);
  cross-tenant terminate denial; streaming keepalive; handshake error
  paths; replay window negative counter. **Measured 94.5%.**

### Fixed
- Client transport's `_replay` watermark persisted across rehandshakes,
  causing the first request after a session-expired rehandshake to be
  rejected as a replay (counter=1 of the new session collided with
  counter=1 of the previous session). `Transport._do_handshake` now
  installs a fresh `_ReplayClient()` on every successful handshake.
- `routers/admin.terminate_session` zeroized the caller's own s2c key
  before encrypting the goodbye envelope when the caller terminated
  their own session, leaving the client unable to decrypt the reply.
  `encrypt_response` now accepts an optional `direction=` override and
  the handler saves the s2c keys before terminating so the goodbye can
  be sealed with the saved direction.
- Session-terminate DELETE route used the default Starlette string path
  converter, which rejects `/` in path parameters. Standard base64 can
  contain `/`. The server now accepts both standard and URL-safe base64
  via the `{session_id_b64:path}` converter, and the SDK sends URL-safe
  base64 by default.
- `make sec` / CI security job now uses `scripts/sec_audit.sh`, which
  exports each workspace member's production dependency tree via
  `uv export --no-dev --no-emit-workspace` and audits that. Editable
  workspace packages (which don't exist on PyPI) no longer cause
  `pip-audit --strict` to fail.

### Security
- Accepted ignore: **CVE-2025-69872** (diskcache 5.6.3) — pulled in
  transitively by `llama-cpp-python`; no upstream fix as of pin date.
  Diskcache is used by llama.cpp's local-only inference cache inside
  the server's data dir, which is already on the trusted side of the
  threat boundary. Rationale and re-evaluation policy are in
  `scripts/sec_audit.sh`.

## [0.1.0] — 2026-05-17

### Added
- End-to-end-encrypted LLM inference server (`llama.cpp` backend) and
  OpenAI-shaped Python client SDK + `sllm` CLI.
- Static+ephemeral X25519 handshake with Ed25519 transcript signatures
  (`PROTOCOL_VERSION = 1.0`).
- Application-layer ChaCha20-Poly1305 envelope with AAD bound to
  method+path+session+counter; sliding-window replay protection.
- At-rest age (pyrage) encryption of model files; tmpfs-with-unlink
  decryption path.
- ModelManager with LRU + idle-timeout offload and per-model inference
  workers.
- `/v1/debug/*` and `/v1/admin/*` APIs for status, doctor, logs,
  errors, sessions, models, log-level, gc, shutdown.
- Structured payload-redacted logging (structlog), Prometheus metrics,
  ring log, error tracker, health probes, audit log.
- `make bootstrap`, `make doctor`, `make run`, `make smoke`,
  `make test`, `make lint type sec` — self-healing one-click flows.
- Threat model, protocol spec, operator guide, runbook, agent
  collaboration docs (`CLAUDE.md`, `AGENTS.md`, `SECURITY.md`,
  `DESIGN.md`, `MEMORY.md`, `HANDOFF.md`).
