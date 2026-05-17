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

## Active work

Nothing in flight; v1 just landed.

## Learnings

- `llama_cpp.Llama` not being thread-safe was the load-bearing constraint
  that shaped the inference architecture. Don't shortcut around it.
- `uv` + workspace mode keeps the protocol package shared between server
  and client without the editable-install dance. The lockfile is a
  single source of truth.
- Putting the entire envelope AEAD AAD on `method+path+session+counter`
  was cheap and pays back the first time someone "just" copies a route
  handler.
