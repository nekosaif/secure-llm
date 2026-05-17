# MEMORY.md

Append-only project journal. Newest entries at the bottom. Never delete;
only add. Dates are absolute (ISO 8601).

---

## History

### 2026-05-17 — Project bootstrapped

- Decided: Python on both sides (server + client), `llama-cpp-python`
  backend, PyNaCl crypto, FastAPI + uvicorn server, httpx + Typer + Rich
  client. Why: best ecosystem fit for GGUF + simplest path to a
  vendor-neutral E2EE pipeline.
- Decided: end-to-end encryption is TLS 1.3 transport *plus* an
  application-layer envelope (X25519 ECDH static+ephemeral → HKDF →
  ChaCha20-Poly1305-IETF). Application layer protects content even if TLS
  is terminated by a compromised proxy. AAD binds the envelope to
  method+path so captured envelopes can't be replayed against a different
  endpoint.
- Decided: pre-shared client X25519 pubkeys (allowlist) for auth, SSH-style
  TOFU pinning for the server pubkey. No API tokens / OIDC for v1.
- Decided: model files are encrypted at rest with `age` (pyrage).
  Decryption goes to tmpfs and the inode is `unlink`'d immediately after
  `Llama()` mmaps the file. Plaintext model bytes never on persistent
  disk.
- Decided: single inference worker per loaded model (asyncio queue +
  worker task). `llama_cpp.Llama` is not thread-safe; this is the only
  correct shape.
- Decided: ENV management = `uv` + `./.venv` only. Makefile refuses
  global Python. Bootstrap is self-healing (installs uv, builds venv,
  generates keys/certs, runs doctor).
- Decided: out of scope for v1 — confidential computing / TEE, multi-tenant
  isolation, fine-tuning, LoRA hot-swap, web UI, federated routing.
- Decided: streaming chat completions (SSE) deferred to v1.1. The server
  returns a clean `bad_request` if `stream=true` so clients can fall back.

### 2026-05-18 — v1.1 shipped (SSE streaming + embeddings)

- Decided: every SSE event is its own application-layer envelope sealed
  with the session's `s2c` key, sharing the session's monotonic
  `s2c_counter`. Same AAD discipline as non-streaming responses, so a
  captured chunk can't be replayed against a different endpoint. Why:
  reusing the envelope is cheap and keeps a single audit surface.
- Decided: streaming generators are drained by the **inference worker**,
  not by the router task. The worker pushes chunks onto a per-job
  `StreamHandle.queue`; the router only consumes that queue. Why: any
  call to `llama_cpp.Llama` must come from the single worker — handing
  the raw generator back to the router would have let two concurrent
  requests touch the same `Llama` from different tasks.
- Decided: drop `str_strip_whitespace=True` from the protocol's `_Strict`
  base. It was silently mangling streaming `delta.content` like `"hello "`
  → `"hello"`. Whitespace in payloads is semantically meaningful.
- Decided: `pip-audit --strict` was failing CI on workspace members.
  Replaced with `scripts/sec_audit.sh` that audits each workspace
  member's *production* dep closure via `uv export --no-dev
  --no-emit-workspace`. CVE-2025-69872 (diskcache via llama-cpp-python,
  no upstream fix) is documented and ignored with a re-evaluation policy.

### 2026-05-18 — v1.2 shipped (LoRA hot-swap + multi-tenant)

- Decided: LoRA support is a load-time concern, not a true hot-swap.
  llama-cpp-python only accepts `lora_path` + `lora_scale` at `Llama()`
  ctor time. Changing the LoRA set evicts and reloads. Why: the
  binding's multi-adapter API isn't stable; we get a useful surface
  today and upgrade composition later.
- Decided: cache key for `_loaded` is `(tenant, model_id, mode, lora_fp)`.
  Same model under different LoRA sets coexists as separate slots when
  `max_loaded > 1`. Why: callers expect deterministic outputs per LoRA
  config; mixing them in one slot would make eviction unpredictable.
- Decided: tenants are a server-side concept derived from the client's
  allowlist entry. The wire format does **not** expose a tenant header —
  the handshake encodes the tenant via the client's static pubkey. Why:
  prevents a misbehaving client from claiming a wider tenant scope.
- Decided: per-tenant allowlist files live at
  `data/keys/tenants/<tenant>/authorized_clients.toml` and the directory
  name *forces* the tenant on every entry inside it. Why: file-layout
  confines the trust boundary; a misnamed row can't escape its dir.
- Decided: default tenant keeps the legacy single-dir layout
  (`data/models/`, `data/loras/`). Named tenants live under
  `tenants/<name>/`. Why: existing v1.0/v1.1 deployments don't need to
  move any files.
- Decided: `super_admin` is a new scope. Tenant-admins are scoped to
  their own tenant on `sessions/list`, `clients/list`,
  `sessions/terminate`, models/, LoRAs/. Cross-tenant ops require
  `super_admin`. Why: the natural "admin in their own tenant" role
  shouldn't see other tenants' fingerprints or sessions.

## Active work

Next up: v1.3 — federated routing across multiple server instances
(`SessionStore` Protocol + Redis backend, shared keystore replication,
SNI-passthrough hard rule at the LB). Plan lives in `PLAN.md`.

## Learnings

- `llama_cpp.Llama` not being thread-safe was the load-bearing constraint
  that shaped the inference architecture. Don't shortcut around it.
- `uv` + workspace mode keeps the protocol package shared between server
  and client without the editable-install dance. The lockfile is a
  single source of truth.
- Putting the entire envelope AEAD AAD on `method+path+session+counter`
  was cheap and pays back the first time someone "just" copies a route
  handler.
- Stream the AEAD envelope *per chunk*, not once around the whole
  stream. Otherwise you can't verify or stop forwarding partway, and a
  truncation attack is invisible.
- pydantic config defaults that look harmless (`str_strip_whitespace`)
  can silently destroy payload semantics. Audit base-model configs
  whenever a new field type starts going through them.
- Per-tenant directory > per-tenant TOML field. The directory name is
  the policy declaration; the TOML field becomes informational.
