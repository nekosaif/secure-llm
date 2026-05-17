# SECURITY.md

This file has two roles. Read both.

## Standing rules (binding on every PR + every AI agent)

These rules exist to keep the system's confidentiality property
intact through refactors. They are not suggestions.

1. **No payload logging.** Never log, print, or otherwise emit the contents
   of: `prompt`, `messages`, `content`, `delta`, `completion`, `text`,
   `plaintext`, `ciphertext`, `session_key`, `private_key`, or anything that
   carries a user's data. The structlog redaction processor catches some of
   this — don't rely on it; don't *add* call-sites that depend on it.
2. **No AEAD weakening.** Don't change `ChaCha20-Poly1305-IETF` to anything
   else without writing a protocol-version bump and an audit doc. Don't
   compute or accept nonces that aren't `prefix(4) || counter(8)`. Don't
   strip the AAD method+path binding.
3. **No allowlist softening.** Don't accept an unknown client static
   pubkey. Don't accept a revoked one. Don't widen scopes implicitly on
   new endpoints.
4. **No decrypted model bytes on persistent disk.** Stay on the
   `decrypt_to_tmpfs + unlink-after-open` path in `crypto/at_rest.py`.
5. **No TLS downgrade.** Minimum is TLS 1.3. The `--no-tls` flag exists
   for local dev only and never for an exposed deployment.
6. **No untrusted deserialization.** Never call `pickle.loads`, `yaml.load`
   without `SafeLoader`, `marshal.loads`, or `eval` on untrusted bytes.
7. **No new network dependencies without a threat-model entry.** If you
   add an outbound call (telemetry, model registry, etc.), update
   `docs/threat-model.md` first and justify it.
8. **No `random.*`.** Use `secrets`, `os.urandom`, or `nacl.utils.random`.
   A ruff rule will flag stdlib `random` outside tests.
9. **Admin endpoints must call `_require_admin`.** No exceptions.
10. **Don't disable hooks, signing, or pre-commit** to push code past
    failing checks. Fix the underlying issue.

If a change *must* break one of these rules, it requires a written
exception in the PR description with the rule number and the reason.

## Threat model summary

In-scope (we defend against):
- Network attacker who can observe or modify HTTPS traffic.
- Attacker with on-disk access to the server (cold-storage,
  backup-restore, post-mortem disk image).
- Compromised operator-level read access to logs and metrics.
- Replay of recorded traffic.

Out-of-scope (we do **not** defend against — by design):
- Root-on-running-server: plaintext is in RAM during inference; only a TEE
  defends against this and TEE is out of scope.
- Multi-tenant mutual distrust on one server.
- DoS through legitimate-looking encrypted requests (rate limit per
  client mitigates but doesn't eliminate).
- Side-channels in `llama.cpp` itself.

The full STRIDE table is in `docs/threat-model.md`.

## Reporting a vulnerability

Email **security@example.com** (replace with your real address before
deploying). Please include:

- A clear description of the issue.
- A proof of concept or reproducer.
- Affected version (commit SHA).
- Your preferred disclosure timeline.

We aim to acknowledge within 2 business days and ship a fix or
mitigation within 14 days for issues that affect confidentiality.

## Supported versions

Only the latest minor release is supported. Older releases get
patches at maintainer discretion.

## Cryptography

- TLS 1.3 transport (server-side cert validation, optional self-signed for
  LAN dev).
- X25519 ECDH (static + ephemeral) handshake, Ed25519 signatures on
  transcript.
- HKDF-SHA-256 for session-key derivation.
- ChaCha20-Poly1305-IETF for envelope AEAD; nonce = `prefix(4) ||
  counter(8)`; AAD = `magic || version || session_id || counter || method
  || path`.
- Sliding-window replay protection (`server/.../crypto/replay.py`).
- age (`pyrage`) for at-rest model encryption.

All primitives come from libsodium (PyNaCl) and age (pyrage). We do not
implement our own ciphers, MACs, or curves.
