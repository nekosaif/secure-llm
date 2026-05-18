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
- `[federation]` — multi-instance / load-balanced deployments. See
  "Federation" below.

## Add a client

1. On the client machine: `sllm keygen`. Copy the printed allowlist block.
2. On the server: append the block to one of:
   - `data/keys/authorized_clients.toml` for the default tenant, or
   - `data/keys/tenants/<tenant>/authorized_clients.toml` for a named
     tenant (the directory name **forces** the tenant — any
     `tenant = "..."` line inside that file is ignored). Create the
     subdir if it doesn't exist; the directory itself is the trust
     declaration.
3. Set `scopes = ["chat"]` for normal users, `["chat", "admin"]` for
   a tenant-admin (sees their own tenant only), or `["chat", "admin",
   "super_admin"]` for a server-wide admin who can manage all tenants.
4. Reload: `sllm admin clients reload --server https://your-host` from
   an admin-scoped client, or `kill -HUP <pid>` on the server.

## Tenants (v1.2)

Tenants partition every per-customer artifact: allowlist, models,
LoRAs, sessions, audit log, rate-limit bucket. The wire never carries
a tenant — the server derives it from the client's allowlist entry
during the handshake.

Directory layout:

```
data/keys/authorized_clients.toml                # default tenant
data/keys/tenants/<tenant>/authorized_clients.toml
data/models/                                     # default tenant
data/models/tenants/<tenant>/
data/loras/                                      # default tenant
data/loras/tenants/<tenant>/
```

Tenant-admins (`scopes = ["chat", "admin"]`) only see their own
tenant in `sessions/list`, `clients/list`, `models/*`, and `loras/*`.
A `super_admin` can call `/v1/admin/tenants/list` to roll up every
tenant's clients/sessions/models counts, and can terminate sessions
across tenants.

**Trust boundary caveat.** Tenant isolation is policy enforced by the
server process. Anyone with root on the host (including the operator)
can still read RAM or the at-rest age identity. Tenants that distrust
the operator need separate instances or wait for the v2.0 TEE work.

## LoRA adapters (v1.2)

```
sllm admin loras pull TheBloke/Mistral-7B-LoRA:my.lora.gguf \
  --base-model Mistral-7B.Q4_K_M [--sha256 …]
sllm admin loras list
sllm admin loras apply Mistral-7B.Q4_K_M my-lora@0.8
sllm admin loras rm my-lora
```

Adapters are SHA-verified at pull time and sealed with the server's
age identity into `data/loras/.../<sha>.lora.gguf.age`. Applying a
LoRA *reloads* the base model with the adapter (llama.cpp does not
expose a true hot-swap), so plan max_loaded accordingly. Callers can
also pin per-request via the SDK:

```python
client.chat.completions.create(
    model="Mistral-7B.Q4_K_M",
    messages=[{"role": "user", "content": "…"}],
    loras=[{"id": "my-lora", "scale": 0.8}],
)
```

Same LoRA set + base model = same cache slot. Different LoRA scales
or different LoRAs = a fresh slot subject to LRU eviction.

## Federation (v1.3)

For a fleet of stateless server instances behind a single load balancer:

```toml
[federation]
session_store = "redis"
session_store_url = "redis://10.0.0.5:6379/0"
identity_replicated = true
```

Install the federation extras on every instance:

```
uv sync --extra federation     # pulls in redis>=5.0
```

Operational rules — these are not optional:

1. **All instances share one X25519/Ed25519 server identity.** Copy
   `data/keys/server.*.key{,.pub}` and `data/keys/server.age.key` from
   the first instance to every other; never let `bootstrap` generate
   a per-instance identity. Clients TOFU-pin one public key for the
   whole fleet.
2. **TLS terminates on each instance, not the LB.** Clients verify
   the envelope identity directly. The LB must run in SNI-passthrough
   / TCP mode. A TLS-terminating LB breaks the threat model and the
   handshake will fail.
3. **LB health checks point at `/healthz` and `/readyz`** (plaintext,
   no envelope) — those endpoints are explicitly safe to expose.
4. **Redis is inside the trust boundary.** Bind to localhost or a
   private VPC reachable only by the fleet, require auth
   (`requirepass`), and use TLS if it crosses any network. A
   reachable-and-unauthenticated Redis equals total compromise.
5. **Prefer session-affinity LB routing** (e.g. consistent hash on a
   client identifier). Failover is supported but causes a one-time
   counter-out-of-order rejection on the client, which triggers a
   transparent rehandshake. Affinity makes that the exception.

### Rolling restart with shared identity

```
# Drain one instance at a time.
sllm admin shutdown --grace 60 --server https://instance-a:8443
# Wait for LB to mark it unhealthy and stop sending traffic.
systemctl restart secure-llm   # on instance A
# Repeat for B, C, ...
```

Sessions pinned to the draining instance survive: the client's next
request lands on a peer instance, which hydrates the session from
Redis and continues. AEAD keys never leave the trust boundary.

### Adding a node

```
# On a new host:
make bootstrap                      # generates identity — discard.
rm -rf data/keys/server.*           # remove the per-host identity.
# Copy the shared identity from an existing instance:
scp existing:/var/lib/secure-llm/keys/server.* data/keys/
chmod 0600 data/keys/server.*.key data/keys/server.age.key
# Same data/config.toml as the rest of the fleet (incl. [federation]).
make run-bg
# Register with the LB and you're done.
```

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
