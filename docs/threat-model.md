# Threat model

Single-tenant, self-hosted, end-to-end-encrypted LLM inference. The
defining property: prompts/responses unreadable to anyone with disk,
log, network, or backup access to the server.

## In scope (we defend against)

| Threat | Mitigation |
|---|---|
| Passive network observer | TLS 1.3 *and* application-layer AEAD envelope. TLS protects metadata; envelope protects content even from a compromised TLS terminator. |
| Active MITM | Server pubkey is pinned client-side (SSH-style TOFU). Mismatch is a hard refusal. Client static pubkey is in the server allowlist + Ed25519 signature over the handshake transcript. |
| Replay of recorded traffic | Per-direction nonce = `prefix(4) || counter(8)`, monotonic, with a 1024-bit sliding window on the receive side. Handshake timestamps must be within 30s skew. |
| Cold-storage / backup access to disk | Models on disk are `age`-encrypted. Logs are payload-redacted at the structlog processor layer. No plaintext model bytes on persistent disk (tmpfs + unlink-after-open). |
| Stolen client key | Allowlist entry can be revoked (flag, not delete) via `authorized_clients.toml` + admin reload. Server keeps no per-session secret on disk. |
| Stolen server key | Operator rotates server identity (`sllm-admin rotate-server-key --grace`); clients re-pin. Existing sessions stay valid until TTL. |
| Resource DoS (slowloris, oversized bodies, body-flood) | uvicorn slowloris timeouts, request size limit, per-`(tenant, client)` token-bucket rate limit. |
| Tenant-A reading tenant-B's data (v1.2) | `AuthorizedClient.tenant` is derived server-side from the allowlist (never client-asserted on the wire). The directory layout `data/keys/tenants/<t>/` *forces* the tenant on entries inside it. Models, LoRAs, sessions, audit events, structlog contextvars, and rate-limit buckets are all keyed by `(tenant, …)`. Admin endpoints filter to the caller's tenant; cross-tenant ops require `super_admin`. |
| Session loss on instance failover (v1.3) | Optional `[federation].session_store = "redis"` mirrors session state (AEAD keys, replay watermark, counter, tenant) to Redis. Instance B can hydrate a session created on instance A after a failover. Redis is **inside** the server trust boundary — see "Out of scope" below for the constraint. |

## Out of scope (we do **not** defend against — by design)

| Threat | Reason |
|---|---|
| Root on the running server | Plaintext is in RAM during inference. Only a TEE defends against this. Planned for v2.0 via SEV-SNP attestation in the handshake. |
| Tenant-vs-operator distrust | v1.2's tenant isolation is policy enforced by the server. The operator (anyone with root on the host) is still inside the trust boundary — they can read RAM, log payloads, or read the at-rest age identity. Tenants that distrust the operator (not just each other) need separate instances or a TEE. |
| DoS via legitimate-looking encrypted requests | Rate limit + queue caps mitigate but don't eliminate. |
| Side channels in `llama.cpp` | We trust the inference backend. |
| Cryptographic novelty | All primitives via libsodium (PyNaCl) and age (pyrage). No custom curves, ciphers, or MACs. |
| Network access to the Redis broker (v1.3) | Redis (when federation is enabled) sits inside the trust boundary alongside the server processes — it stores AEAD direction keys, replay watermarks, and counters. **Constraint:** Redis must be bound to localhost or a private VPC reachable only by the server fleet, and authenticated with `requirepass` + TLS if it crosses any network. A reachable-and-unauthenticated Redis is a complete compromise. Documented in `docs/operator-guide.md` under "Adding a node". |
| Failover within the 1024-counter window | The replay-bitmap is per-instance; only `head` is mirrored to Redis. On failover the new instance accepts any counter > persisted `head`. Because client counters are strictly monotonic per direction, the only loss is duplicate-detection for the old instance's in-flight envelopes (a malicious replay would still need to know c2s key material, which is in Redis — i.e. compromise of Redis = compromise of the server). |
| `s2c_counter` lag on failover (v1.3) | The s2c counter is persisted on the next `decrypt_request`, not on response sealing. After failover, the new instance may resend a counter the old instance just used. The client surfaces this as a counter-out-of-order envelope rejection and triggers a rehandshake. Mitigation: prefer session-affinity LB routing so failover is the exceptional case. |

## STRIDE per component

| Component | Threat | Mitigation |
|---|---|---|
| Handshake router | Spoofing | Ed25519 transcript signature on both sides, allowlist lookup. |
| Envelope layer | Tampering | AEAD with AAD bound to method+path+session+counter. |
| Session store | Repudiation | Audit log records handshake, revocation, admin actions. |
| Logging | Info disclosure | Structlog processor strips `prompt`, `messages`, `content`, etc. Refuses raw bytes. |
| ModelManager | DoS | Bounded queue per model; 503 + Retry-After on overflow. |
| Admin API | Elevation of privilege | `_require_admin` gate, every mutation audited. |
| At-rest models | Disclosure | `age` encryption. Tmpfs decryption with `unlink`-after-open. |

## Key management

- Server static identity (X25519 + Ed25519): files mode `0600`, owned by
  the service user, optional Vault/`systemd-creds` backend.
- Client identities: each client generates its own keypair with
  `sllm keygen`; only public keys land in the server allowlist.
- Session keys: derived per handshake, never written to disk, zeroized on
  session termination.

## Versioning

`PROTOCOL_VERSION` (in `protocol/secure_llm_protocol/version.py`) is
semver. Wire-incompatible changes bump major. Both server and client
refuse to talk to a peer with an incompatible major.
