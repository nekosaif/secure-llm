# Architecture diagrams

Each diagram ships in two forms:

- **`<slug>.html`** — self-contained dark-themed page with a
  Copy / PNG / PDF export toolbar (open in any browser).
- **`<slug>.svg`** — standalone SVG for embedding in
  markdown / docs / slides (renders inline on GitHub).

## secure-llm — Component Map

_End-to-end-encrypted LLM inference: client SDK ↔ TLS + AEAD envelope ↔ FastAPI server, with at-rest model encryption and decrypted-bytes-only-in-RAM_

![secure-llm — Component Map](component-map.svg)

Open the interactive version: [`component-map.html`](component-map.html).

## secure-llm — Request Lifecycle

_From plaintext handshake to encrypted chat completion and back, with replay + AAD-binding protections_

![secure-llm — Request Lifecycle](request-lifecycle.svg)

Open the interactive version: [`request-lifecycle.html`](request-lifecycle.html).

## secure-llm — Cryptographic Flow

_Static + ephemeral X25519 → HKDF-SHA-256 → ChaCha20-Poly1305-IETF, with AAD bound to method+path_

![secure-llm — Cryptographic Flow](crypto-flow.svg)

Open the interactive version: [`crypto-flow.html`](crypto-flow.html).

## secure-llm — Model Lifecycle

_State machine + per-loaded internals: how a GGUF goes from absent → loaded → idle-offload_

![secure-llm — Model Lifecycle](model-lifecycle.svg)

Open the interactive version: [`model-lifecycle.html`](model-lifecycle.html).

---

Regenerate with `make diagrams` (or `uv run python scripts/render_diagrams.py`).