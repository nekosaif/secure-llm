# Architecture diagrams

Open any of these HTML files in a browser. Each has a built-in
Copy / PNG / PDF export toolbar (click the `⋯` in the header).

- [secure-llm — Component Map](component-map.html) — End-to-end-encrypted LLM inference: client SDK ↔ TLS + AEAD envelope ↔ FastAPI server, with at-rest model encryption and decrypted-bytes-only-in-RAM
- [secure-llm — Request Lifecycle](request-lifecycle.html) — From plaintext handshake to encrypted chat completion and back, with replay + AAD-binding protections
- [secure-llm — Cryptographic Flow](crypto-flow.html) — Static + ephemeral X25519 → HKDF-SHA-256 → ChaCha20-Poly1305-IETF, with AAD bound to method+path
- [secure-llm — Model Lifecycle](model-lifecycle.html) — State machine + per-loaded internals: how a GGUF goes from absent → loaded → idle-offload

Regenerate with `uv run python scripts/render_diagrams.py`.