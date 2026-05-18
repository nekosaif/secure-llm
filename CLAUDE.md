# CLAUDE.md

This file is auto-loaded by Claude Code at session start. Keep it crisp.

## What this repo is

`secure-llm` is a self-hosted, end-to-end-encrypted LLM inference service.
The server runs `llama.cpp` over GGUF models; the client is an OpenAI-shaped
Python SDK + `sllm` CLI. The defining requirement is that prompts and
responses are unreadable to anyone with disk, log, network, or backup access
to the server. Plaintext exists only in server RAM during inference.

## How to operate

Everything runs inside `./.venv` via `uv` — never the global Python.

```
make bootstrap      # idempotent setup; safe to re-run
make doctor         # diagnostic report (mirrors /v1/debug/doctor)
make run / run-bg / stop / logs
make smoke          # end-to-end (boots server, runs client checks)
make test           # unit + property + integration
make lint type sec  # ruff, mypy --strict, pip-audit + bandit
```

See `Makefile` for the full target list; `make help` prints it.

## Non-obvious architectural invariants (do not violate)

1. **`protocol/` is the single source of wire truth.** Both `server/` and
   `client/` import from it. Don't fork the schemas; bump
   `PROTOCOL_VERSION` and update both sides together.
2. **One inference worker per loaded model.** `llama_cpp.Llama` is not
   thread-safe. All inference goes through `ModelManager`'s per-model
   `asyncio.Queue` served by exactly one worker task. Never call `Llama`
   directly from a router.
3. **Plaintext never on persistent disk.** Models are encrypted with `age`
   (`pyrage`) at rest. On load they decrypt into a tmpfs file that is
   `unlink()`ed immediately after `Llama()` mmaps it. No hooks should add a
   path that writes plaintext model bytes elsewhere.
4. **AEAD AAD binds method + path.** A captured envelope cannot be replayed
   against a different endpoint. If you add a new router, the
   `decrypt_request` helper in `routers/_envelope_dep.py` is what enforces
   this — don't bypass it.
5. **Logs are payload-redacted at the structlog processor layer.** Don't
   add an ad-hoc print/log of `messages`, `prompt`, `content`, `delta`,
   `completion`, `text`. A test (`tests/unit/test_log_redaction.py`)
   enforces this — keep it green.
6. **Auth is by client X25519 pubkey on an allowlist**, plus an `admin`
   scope for the control-plane endpoints. The `_require_admin` helper in
   `routers/admin.py` is the only gate; new admin endpoints must use it.
7. **Server stays stateless about conversation content** by default.
   `chat.clear` is a client-side reset of message history; the SDK doesn't
   ship a server-side persistent-conversation path.
8. **SessionStore Protocol is the boundary** (v1.3). Never reach into
   `_by_id` from a router; treat `SessionManager.lookup` as cache-only
   (sync) and `lookup_async` as the rehydrating path that survives
   federated failover. Redis (when enabled) is **inside** the trust
   boundary — it stores AEAD direction keys. Never expose it to a
   wider network and never log its contents.
9. **Attestation userdata = `SHA-256(full_transcript)`** (v2.0). The
   Ed25519 transcript signature is *independent* of the attestation
   report — never sign different bytes when attestation is on vs off.
   Never weaken the userdata binding; the report's whole value comes
   from being non-detachable. `MockAttestationBackend` /
   `MockAttestationVerifier` are CI-only — never ship in production.
10. **Image content parts honor only `data:` URIs.** The router refuses
    `https://` URLs in `ImageUrlPayload.url` so a malicious prompt
    cannot trigger outbound egress (DNS / GET / SSRF). Never relax
    this without an explicit, documented threat-model exception.

## Where things live

- `protocol/secure_llm_protocol/` — pydantic schemas, wire format, errors.
- `server/secure_llm_server/crypto/` — handshake, envelope, replay, keystore, at-rest.
- `server/secure_llm_server/models/` — model manager, downloader, registry, inference worker.
- `server/secure_llm_server/routers/` — FastAPI routes; one file per endpoint group.
- `server/secure_llm_server/observability/` — ring log, error tracker, status snapshot.
- `client/secure_llm_client/` — SDK + `sllm` CLI.
- `docs/` — protocol spec, threat model, operator guide, runbook.

## Pointers

- Threat model and what's explicitly out of scope: `docs/threat-model.md`.
- Byte-for-byte wire format: `docs/protocol.md`.
- Standing security rules (no payload logging, no AEAD weakening, etc.):
  `SECURITY.md`.
- CLI/TUI style: `DESIGN.md`.
- Project history + active work: `MEMORY.md`.
- Picking up after someone (or yourself) stepped away: read `HANDOFF.md` first.

`CLAUDE.md` and `AGENTS.md` are generated from `docs/_agent-context.md`. To
update either, edit the source and run `make agent-docs`.
