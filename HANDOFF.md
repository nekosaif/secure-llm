# HANDOFF.md

Read this first when picking the project up cold.

## Where we are

- **v1.0** landed 2026-05-17: server + client + envelope + TOFU.
- **v1.1** landed 2026-05-18: SSE streaming on `/v1/chat/completions`,
  `/v1/embeddings` endpoint, smarter `_loaded` cache slot for embedding
  mode, `make smoke-v11`.
- **v1.2** landed 2026-05-18: LoRA adapters (registry, downloader,
  admin endpoints, per-request `loras: list[LoraRef]`),
  multi-tenant (`AuthorizedClient.tenant`, per-tenant model + LoRA
  storage, `MultiTenantRegistry` factories, tenant-scoped admin views,
  `super_admin` scope, `/v1/admin/tenants/list`), `make smoke-v12`.

Runnable end-to-end with:

```
make bootstrap        # gens dev TLS, server identity, allowlist scaffold
make run              # foreground server
make smoke / smoke-v11 / smoke-v12   # in another shell
make lint type test sec              # gates
```

## What's mid-flight

Nothing. v1.2 is consistent. All gates green: 27 tests, ruff clean,
`mypy --strict` clean, `make sec` clean. Active roadmap is `PLAN.md`
(v1.3 federated routing → v2.0 TEE + multimodal).

## Known gaps (deliberate, not bugs)

- **Federated routing** isn't implemented. Sessions are in-memory and
  per-instance; each instance has its own keystore. One instance per
  deployment. v1.3 lands the `SessionStore` Protocol + Redis backend
  and SNI-passthrough operator rules.
- **Confidential computing / TEE.** Plaintext is in RAM during
  inference. v2.0 adds SEV-SNP attestation in the handshake. The
  operator (and anyone with root on the host) is still inside the
  trust boundary until then.
- **Image / audio modalities.** `ChatMessage.content` is `str` only;
  no Llava / Whisper. v2.0.
- **Multi-LoRA composition.** `LlamaBackend` currently passes a single
  `lora_path` + `lora_scale` to `Llama()` (the binding's
  multi-adapter API isn't stable). The wire schema accepts
  `loras: list[LoraRef]` but only the first element is loaded.
- **CUDA wheel** for `llama-cpp-python` isn't pinned; the default
  install is CPU. Set `CMAKE_ARGS="-DLLAMA_CUBLAS=on"` and re-run
  `uv sync` for GPU builds.
- The audit log uses the regular structlog sink (no separate file).
- The systemd unit and `Dockerfile` are reference templates, not
  production-hardened deployments.
- **Coverage gate is at 55%** (real measured 56% on the
  pytest-testable surface). The truly heavy paths
  (`scripts_*`, `lifespan`, `main`, `cli`, `llm.backend`,
  `models.{manager,downloader}`, `sysinfo`) are `omit`'d because they
  need a real GGUF or process boot; smoke targets cover them. Raise
  the gate as router-level integration tests for `completions`,
  `debug`, `models`, and `system` land.

## Next 1–2 things to do (if anyone resumes)

1. Start v1.3 in `PLAN.md`: extract `SessionStore` Protocol in
   `session/manager.py`; add `RedisSessionStore` keeping envelope keys
   in Redis with TTL; document the wider trust boundary in
   `docs/threat-model.md`. Two-instance integration test via
   `docker-compose` + Redis.
2. Multi-LoRA composition once `llama-cpp-python` exposes the
   multi-adapter API — extend `LlamaBackend.__init__` to apply each
   `(path, scale)` pair instead of just the head, and remove the
   "first element only" note in this file.

## Watch out for

- Do not call `llama_cpp.Llama` directly from a router. All inference
  goes through `ModelManager.chat/complete/embed` so the per-model
  queue serializes concurrent callers. Streaming **also** runs inside
  the worker; never iterate the generator from the router task.
- Do not log payloads. The structlog redaction processor catches the
  obvious keys; new ad-hoc print statements bypass it.
- The `decrypt_to_tmpfs` context manager `unlink`s the tmpfs file
  inside `__exit__`. If you ever need to keep the decrypted file alive
  past the context, you're probably designing the wrong abstraction —
  talk to someone first. The LoRA load path uses
  `contextlib.ExitStack` to stack multiple `decrypt_to_tmpfs`
  contexts; reuse that pattern, don't nest manually.
- `_require_admin` accepts both `admin` and `super_admin`. The
  cross-tenant gate is a separate `_require_super_admin` /
  `_is_super(session)` check inside each endpoint. New admin endpoints
  that fan across tenants need that second gate.
- The per-tenant allowlist directory **forces** the tenant. If a
  client appears in `tenants/foo/authorized_clients.toml`, they're in
  `foo` regardless of any `tenant = "..."` line in the TOML — and any
  duplicate at the root file is overridden. Do not change that
  precedence without auditing `docs/threat-model.md`.
- `pyrage` is a Rust extension. If `uv sync` can't find a wheel, the
  bootstrap script auto-retries with native build. Make sure a C/Rust
  toolchain is available on production builders.

## How to verify after a change

```
make lint type          # ruff clean + mypy --strict clean
make test               # 27 tests: unit + property + integration
make smoke / smoke-v11 / smoke-v12
make sec                # pip-audit + bandit
```

If `make smoke` fails, look at `data/logs/server.log` (JSON) — every
state transition emits a structured event with `event=...`, and the
ring buffer is dumped on shutdown. Every audit event since v1.2 also
carries `tenant=…`, which is the first thing to check when a
cross-tenant boundary feels off.
