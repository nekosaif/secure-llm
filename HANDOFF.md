# HANDOFF.md

Read this first when picking the project up cold.

## Where we are

v1 of the secure-llm server + client landed on 2026-05-17. The system is
intended to be runnable end-to-end with:

```
make bootstrap   # generates dev TLS, server identity, allowlist scaffold
make run         # foreground server
make smoke       # in another shell — boots a separate test server + client
```

## What's mid-flight

Nothing. v1 is consistent. There are intentional gaps (see "Known gaps").

## Known gaps (deliberate, not bugs)

- SSE streaming on `/v1/chat/completions` is not implemented. The server
  returns `bad_request: streaming not implemented in v1` if the client
  sets `stream=true`. Clients fall back to non-streaming.
- A CUDA wheel for `llama-cpp-python` isn't pinned; the default install
  is CPU. Set `CMAKE_ARGS="-DLLAMA_CUBLAS=on"` and re-run `uv sync` for
  GPU builds.
- Rate-limit defaults are loose (120 rpm/client). Tune per deployment.
- The audit log uses the regular structlog sink (no separate file). A
  dedicated audit sink + rotation policy is a one-day add.
- The systemd unit and Docker `Dockerfile` are placeholders meant to be
  reviewed before production.

## Next 1-2 things to do (if anyone resumes)

1. Wire SSE streaming end-to-end: server emits `text/event-stream` with
   per-event envelopes; client SDK exposes an iterator. The hook points
   are `routers/chat.py` and `transport.py`.
2. Replace the toy `_require_admin` gate with a richer scope/permission
   model — the allowlist already stores `scopes: list[str]`, just plumb
   per-route scope requirements through a dependency.

## Watch out for

- Do not call `llama_cpp.Llama` directly from a router. Always go through
  `ModelManager.chat/complete` so the per-model queue serializes
  concurrent callers.
- Do not log payloads. The structlog redaction processor catches the
  obvious keys; new ad-hoc print statements bypass it.
- The `decrypt_to_tmpfs` context manager `unlink`s the tmpfs file inside
  `__exit__`. If you ever need to keep the decrypted file alive past the
  context, you're probably designing the wrong abstraction — talk to
  someone first.
- `pyrage` is a Rust extension. If `uv sync` can't find a wheel, the
  bootstrap script auto-retries with native build. Make sure a C/Rust
  toolchain is available on production builders.

## How to verify after a change

```
make lint type          # zero ruff/mypy errors
make test               # all unit/property/integration green
make smoke              # boots a server, runs end-to-end client flow
```

If `make smoke` fails, look at `data/logs/server.log` (JSON) — every
state transition emits a structured event with `event=...`, and the ring
buffer is dumped on shutdown.
