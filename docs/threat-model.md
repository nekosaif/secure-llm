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
| Resource DoS (slowloris, oversized bodies, body-flood) | uvicorn slowloris timeouts, request size limit, per-client-fingerprint token-bucket rate limit. |

## Out of scope (we do **not** defend against — by design)

| Threat | Reason |
|---|---|
| Root on the running server | Plaintext is in RAM during inference. Only a TEE defends against this. TEE is explicitly out of scope. |
| Multi-tenant mutual distrust | One allowlist, one server identity. Mutually distrusting clients should run separate instances. |
| DoS via legitimate-looking encrypted requests | Rate limit + queue caps mitigate but don't eliminate. |
| Side channels in `llama.cpp` | We trust the inference backend. |
| Cryptographic novelty | All primitives via libsodium (PyNaCl) and age (pyrage). No custom curves, ciphers, or MACs. |

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
