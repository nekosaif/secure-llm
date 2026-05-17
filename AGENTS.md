# AGENTS.md

Vendor-neutral counterpart to `CLAUDE.md` for Cursor, Windsurf, Aider, Cline, and
similar tools. Same project context, written to the [agents.md](https://agents.md)
open standard.

## Project

`secure-llm` is an end-to-end-encrypted self-hosted LLM inference service:
`llama.cpp`-backed server + OpenAI-shaped Python SDK + `sllm` CLI. Goal:
prompts/responses unreadable to anyone with disk, log, network, or backup
access to the server.

## Setup and run

```
make bootstrap     # one-click setup (uv, venv, deps, keys, certs, doctor)
make run / run-bg / stop / logs
make smoke         # end-to-end check
make test lint type sec
```

Everything runs in `./.venv` via `uv run`. The Makefile refuses to use the
global Python. `make help` lists every target.

## Architectural rules

1. `protocol/` is the only place wire schemas live. Both sides depend on it.
2. `llama_cpp.Llama` isn't thread-safe — one `InferenceWorker` per model,
   fed by an asyncio queue; never call `Llama` from a router directly.
3. Decrypted model bytes never touch persistent disk — they go to tmpfs and
   the file is `unlink`'d after mmap.
4. AEAD AAD binds `method + path + session + counter`. Use
   `routers/_envelope_dep.py` helpers for every encrypted endpoint.
5. Logs are payload-redacted at the structlog processor layer
   (`server/secure_llm_server/logging.py`). Don't print prompts/messages.
6. Admin endpoints gate on the `admin` scope via `_require_admin`. Don't
   skip this on new admin routes.

## Tree

```
protocol/                    shared wire schemas
server/secure_llm_server/
  crypto/                    handshake, envelope, replay, keystore, at-rest
  session/                   in-memory session table
  models/                    manager, downloader, registry, inference worker
  routers/                   FastAPI endpoints
  observability/             ring log, errors, status snapshot
client/secure_llm_client/    SDK + sllm CLI
docs/                        threat model, protocol, operator guide, runbook
```

## Tests

`make test` runs pytest with unit, property (hypothesis), and in-process
integration tests. The integration test wires the real client SDK against an
ASGI in-process server without booting llama.cpp — fast and catches every
framing/AEAD/AAD bug.

## Pointers

- Standing security rules: `SECURITY.md`.
- Threat model: `docs/threat-model.md`.
- Wire format byte-for-byte: `docs/protocol.md`.
- Picking up after a context reset: `HANDOFF.md`.
- Project journal: `MEMORY.md`.

## Generated file

This file and `CLAUDE.md` are generated from `docs/_agent-context.md` by
`make agent-docs`. Edit the source, not this file.
