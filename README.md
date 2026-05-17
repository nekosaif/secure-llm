# secure-llm

Self-hostable, end-to-end-encrypted LLM inference. A `llama.cpp`-backed server
that loads GGUF models on demand and unloads them after an idle timeout, plus a
Python SDK + `sllm` CLI with an OpenAI-compatible surface.

**Confidentiality model.** Prompts, responses, and conversation history are
encrypted in transit (TLS 1.3) **and** under an application-layer envelope
(X25519 ECDH → ChaCha20-Poly1305-IETF) so a network observer or someone with
disk/log/backup access to the server cannot read them. Model files on disk are
encrypted with age. Plaintext exists only in server RAM during inference.

## Quick start

```bash
git clone <this repo> && cd secure-llm
make bootstrap          # installs uv to ~/.local/bin, builds .venv, generates dev keys
make run                # foreground; ctrl-c to stop
# or
make run-bg && make logs
```

In another shell:

```bash
make smoke              # pulls TinyLlama, runs handshake + chat + admin + idle-offload checks
```

Everything runs inside `./.venv` via `uv`. Targets refuse to use the global
Python.

## Make targets

```
make help               # full list with descriptions
make bootstrap          # idempotent setup; safe to re-run
make doctor             # diagnostic report
make run / run-bg / stop / logs
make test               # unit + property + integration
make lint type sec      # ruff, mypy --strict, pip-audit + bandit
make smoke              # end-to-end
make container          # build server image
make clean / make nuke  # remove .venv / wipe everything (with confirm)
```

## Layout

```
protocol/       shared wire schemas (pydantic)
server/         FastAPI app, crypto, model manager, inference workers, admin/debug APIs
client/         SDK + `sllm` CLI
docs/           threat-model, protocol spec, operator guide, runbook
```

## Docs

- [`docs/threat-model.md`](docs/threat-model.md)
- [`docs/protocol.md`](docs/protocol.md)
- [`docs/operator-guide.md`](docs/operator-guide.md)
- [`docs/runbook.md`](docs/runbook.md)
- [`SECURITY.md`](SECURITY.md) — disclosure policy + standing rules
- [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) — context for AI coding agents
- [`HANDOFF.md`](HANDOFF.md) — read first if you're picking the project back up

## License

Apache-2.0.
