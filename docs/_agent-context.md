# Agent context source

Single source rendered to `CLAUDE.md` and `AGENTS.md` by `make agent-docs`.
Edit this file; the generated files will be overwritten.

(For v1 the generator script is a TODO — the two derived files are
hand-curated for now and kept in sync manually. When the script lands,
move shared content here and have it emit both.)

## Current invariants summary (mirror in CLAUDE.md / AGENTS.md)

1. `protocol/` is the single source of wire truth.
2. One inference worker per loaded model (`llama_cpp.Llama` not thread-safe).
3. Plaintext model bytes never on persistent disk — tmpfs + unlink-after-mmap.
4. AEAD AAD binds method + path + session + counter.
5. Logs payload-redacted at the structlog processor layer.
6. Admin endpoints gate via `_require_admin`; tenant-admin vs `super_admin`.
7. Server stateless about conversation content; `chat.clear` is client-side.
8. **v1.3** — `SessionStore` Protocol is the boundary; `lookup` is sync
   cache-only, `lookup_async` rehydrates from Redis. Redis is *inside*
   the trust boundary.
9. **v2.0** — attestation `userdata = SHA-256(full_transcript)`;
   Ed25519 transcript sig is independent of attestation. `Mock*` is
   CI-only.
10. **v2.0** — image content parts honor only `data:` URIs; `https://`
    URLs are refused server-side to prevent prompt-driven egress.
