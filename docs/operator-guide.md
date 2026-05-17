# Operator guide

End-to-end checklist for running secure-llm in production. For a
quick-start, see `README.md`; this document is the deeper version.

## Install

```
git clone <repo> && cd secure-llm
make bootstrap
```

`bootstrap` installs `uv` to `~/.local/bin` if missing, builds the venv,
syncs dependencies, generates a self-signed dev TLS cert, generates the
server X25519+Ed25519 identity, scaffolds `authorized_clients.toml`, and
runs `make doctor`. It's idempotent — safe to re-run.

For production, replace the self-signed cert with a real one (Let's
Encrypt or your CA) and put paths into `data/config.toml`.

## Configuration

`data/config.toml` is the single config file. Env vars override anything
inside (`SECURE_LLM_SERVER__PORT=9000`, etc.).

Important sections:

- `[server]` — host, port, graceful-shutdown grace.
- `[tls]` — cert/key paths, min version (default TLSv1.3).
- `[crypto]` — key dir, allowlist path, session TTLs, handshake skew.
- `[models]` — storage_dir, tmpfs_dir, max_loaded, idle_timeout_seconds,
  disk_quota_gb, allowed_repo_prefixes.
- `[inference]` — `n_gpu_layers`, `n_threads`, `n_ctx_default`, queue
  depth, hard max_tokens cap.
- `[limits]` — request size, rate-limit RPM per client, slowloris timeouts.
- `[observability]` — log level/format/dir, metrics bind, ring/error
  buffer sizes.

## Add a client

1. On the client machine: `sllm keygen`. Copy the printed allowlist block.
2. On the server: append the block to `authorized_clients.toml`. Set
   `scopes = ["chat"]` for normal users, `["chat", "admin"]` for
   operators.
3. Reload: `sllm admin clients reload --server https://your-host` from an
   admin-scoped client, or `kill -HUP <pid>` on the server.

## Pin the server

On the client machine:

```
sllm trust your-host:8443 <server_x25519_pubkey_base64>
```

The pubkey is the file `data/keys/server.x25519.key.pub` on the server
(base64-encoded). Distribute it over a separate channel from the API
endpoint — that's the whole point of pinning.

## Rotation

- **Server static key.** `sllm-admin rotate-server-key --grace 24h` (TODO
  in v1.1). Until then: rename the existing keys, run `bootstrap` to
  generate new ones, distribute the new pubkey, have clients re-trust.
- **Client keys.** Generate new keys with `sllm keygen`, add to
  allowlist, revoke the old entry (`revoked = true`), reload allowlist.
- **TLS cert.** Standard ACME flow; reload server (it doesn't watch the
  file — restart is required in v1).

## Backup and recovery

- **Encrypted models** (`data/models/*.gguf.age`) are safe to back up; the
  age identity is required to decrypt.
- **Server identity keys** (`data/keys/server.*`) must be backed up
  separately, in a way at least as secure as your TLS cert.
- **Sessions** are in-memory only — never backed up, never restored.
- **Allowlist** is plaintext TOML; back it up however you back up config.

## Monitoring

- Prometheus on `[observability].metrics_bind` (default `127.0.0.1:9090`).
- Useful alerts:
  - `secure_llm_handshake_total{result!="ok"}` rate spike → attack or
    misconfig.
  - `secure_llm_envelope_failures_total` non-zero → tampered traffic or
    bug.
  - `secure_llm_inference_queue_depth` saturated → capacity issue.
  - `secure_llm_disk_free_bytes` low → models dir running out.
- `/v1/debug/status` is the live JSON snapshot — use it from a control
  client or curl through a TLS-terminating proxy with envelope plumbing.

## Common admin operations

```
sllm admin sessions list
sllm admin sessions terminate <session_id_b64>
sllm admin models preload <id>
sllm admin models unload <id>
sllm admin clients list
sllm admin clients reload
sllm admin log-level set secure_llm_server.crypto DEBUG --ttl 600
sllm admin shutdown --grace 60
```

All admin actions are recorded in the audit log
(`event="admin.<action>"`).

## Hardening

The provided `server/deploy/systemd/secure-llm.service` runs with
`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp=yes`, and a minimal capability set. Review before deploying.

The container image (`server/Dockerfile`) is distroless and runs as UID
10001. The only writable paths are `${MODELS_DIR}` and `${TMPFS_DIR}`.
