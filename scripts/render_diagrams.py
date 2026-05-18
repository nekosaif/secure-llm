#!/usr/bin/env python3
"""Render architecture diagrams for secure-llm.

Uses the Cocoon-AI architecture-diagram skill (installed at
``.claude/skills/architecture-diagram/``) — reads ``resources/template.html``,
substitutes title/subtitle/SVG/cards/footer per diagram, writes each to
``docs/diagrams/<slug>.html``.

Each output is a single self-contained HTML file with inline SVG and the
built-in Copy / PNG / PDF export toolbar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / ".claude/skills/architecture-diagram/resources/template.html"
OUT_DIR = REPO / "docs/diagrams"


@dataclass(frozen=True)
class Diagram:
    slug: str
    title: str  # used in <title>, header h1, and footer
    subtitle: str
    viewbox: str  # e.g. "0 0 1200 900"
    svg_body: str  # SVG children between <defs> closing and </svg>
    cards: list[tuple[str, str, list[str]]]  # (color, title, bullets)
    footer: str


# ---------------------------------------------------------------------------
# Diagram 1 — Component map
# ---------------------------------------------------------------------------

COMPONENT_MAP_SVG = r"""
<!-- ============================================================
     CLIENT SIDE (cyan)
     ============================================================ -->
<rect x="40" y="40" width="380" height="640" rx="12"
      fill="rgba(8, 51, 68, 0.10)" stroke="#22d3ee"
      stroke-width="1" stroke-dasharray="8,4"/>
<text x="60" y="62" fill="#22d3ee" font-size="11" font-weight="600">CLIENT</text>

<!-- sllm CLI -->
<rect x="80" y="100" width="120" height="50" rx="6" fill="rgba(8, 51, 68, 0.4)"
      stroke="#22d3ee" stroke-width="1.5"/>
<text x="140" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">sllm CLI</text>
<text x="140" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">Typer + Rich</text>

<!-- SecureLLMClient -->
<rect x="240" y="100" width="160" height="50" rx="6" fill="rgba(8, 51, 68, 0.4)"
      stroke="#22d3ee" stroke-width="1.5"/>
<text x="320" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">SecureLLMClient</text>
<text x="320" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">resources/{chat, models, ...}</text>

<line x1="200" y1="125" x2="238" y2="125" stroke="#22d3ee" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Transport -->
<rect x="80" y="200" width="320" height="90" rx="6" fill="rgba(8, 51, 68, 0.4)"
      stroke="#22d3ee" stroke-width="1.5"/>
<text x="240" y="222" fill="white" font-size="11" font-weight="600" text-anchor="middle">Transport (httpx)</text>
<text x="240" y="240" fill="#94a3b8" font-size="9" text-anchor="middle">• handshake on first request</text>
<text x="240" y="254" fill="#94a3b8" font-size="9" text-anchor="middle">• envelope wrap/unwrap</text>
<text x="240" y="268" fill="#94a3b8" font-size="9" text-anchor="middle">• s2c replay window</text>
<text x="240" y="282" fill="#22d3ee" font-size="8" text-anchor="middle">known_hosts pinning (TOFU)</text>

<line x1="320" y1="150" x2="320" y2="198" stroke="#22d3ee" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Client crypto + known_hosts -->
<rect x="80" y="340" width="150" height="80" rx="6" fill="rgba(136, 19, 55, 0.4)"
      stroke="#fb7185" stroke-width="1.5"/>
<text x="155" y="360" fill="white" font-size="11" font-weight="600" text-anchor="middle">crypto/</text>
<text x="155" y="376" fill="#94a3b8" font-size="9" text-anchor="middle">handshake</text>
<text x="155" y="390" fill="#94a3b8" font-size="9" text-anchor="middle">envelope</text>
<text x="155" y="404" fill="#94a3b8" font-size="9" text-anchor="middle">kdf</text>

<rect x="250" y="340" width="150" height="80" rx="6" fill="rgba(136, 19, 55, 0.4)"
      stroke="#fb7185" stroke-width="1.5"/>
<text x="325" y="360" fill="white" font-size="11" font-weight="600" text-anchor="middle">known_hosts</text>
<text x="325" y="376" fill="#94a3b8" font-size="9" text-anchor="middle">SSH-style TOFU</text>
<text x="325" y="390" fill="#94a3b8" font-size="9" text-anchor="middle">pinned server</text>
<text x="325" y="404" fill="#94a3b8" font-size="9" text-anchor="middle">X25519 pubkeys</text>

<line x1="155" y1="290" x2="155" y2="338" stroke="#fb7185" stroke-width="1.5" stroke-dasharray="3,3" marker-end="url(#arrowhead)"/>
<line x1="325" y1="290" x2="325" y2="338" stroke="#fb7185" stroke-width="1.5" stroke-dasharray="3,3" marker-end="url(#arrowhead)"/>

<!-- ============================================================
     CHANNEL
     ============================================================ -->
<rect x="450" y="280" width="120" height="120" rx="8"
      fill="rgba(251, 191, 36, 0.10)" stroke="#fbbf24" stroke-width="1.5" stroke-dasharray="4,4"/>
<text x="510" y="304" fill="#fbbf24" font-size="10" font-weight="600" text-anchor="middle">TLS 1.3</text>
<text x="510" y="320" fill="#fbbf24" font-size="10" font-weight="600" text-anchor="middle">+</text>
<text x="510" y="338" fill="#fbbf24" font-size="10" font-weight="600" text-anchor="middle">AEAD Envelope</text>
<text x="510" y="360" fill="#94a3b8" font-size="8" text-anchor="middle">ChaCha20-Poly1305</text>
<text x="510" y="375" fill="#94a3b8" font-size="8" text-anchor="middle">AAD = method+path</text>
<text x="510" y="390" fill="#94a3b8" font-size="8" text-anchor="middle">+ session + counter</text>

<line x1="400" y1="245" x2="448" y2="320" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="572" y1="320" x2="620" y2="245" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- ============================================================
     SERVER SIDE (emerald)
     ============================================================ -->
<rect x="600" y="40" width="560" height="640" rx="12"
      fill="rgba(6, 78, 59, 0.07)" stroke="#34d399"
      stroke-width="1" stroke-dasharray="8,4"/>
<text x="620" y="62" fill="#34d399" font-size="11" font-weight="600">SERVER</text>

<!-- uvicorn -->
<rect x="640" y="100" width="120" height="50" rx="6" fill="rgba(6, 78, 59, 0.4)"
      stroke="#34d399" stroke-width="1.5"/>
<text x="700" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">uvicorn</text>
<text x="700" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">TLS termination</text>

<!-- Middleware chain -->
<rect x="780" y="100" width="350" height="50" rx="6" fill="rgba(6, 78, 59, 0.4)"
      stroke="#34d399" stroke-width="1.5"/>
<text x="955" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">Middleware chain</text>
<text x="955" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">security_headers → rate_limit → size_limit → req_id</text>

<line x1="760" y1="125" x2="778" y2="125" stroke="#34d399" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Routers -->
<rect x="640" y="180" width="490" height="110" rx="6" fill="rgba(6, 78, 59, 0.4)"
      stroke="#34d399" stroke-width="1.5"/>
<text x="885" y="200" fill="white" font-size="12" font-weight="600" text-anchor="middle">FastAPI routers</text>
<text x="660" y="222" fill="#94a3b8" font-size="9">/v1/session  (plaintext handshake)</text>
<text x="660" y="238" fill="#94a3b8" font-size="9">/v1/models/* · /v1/chat/completions · /v1/completions · /v1/system</text>
<text x="660" y="254" fill="#94a3b8" font-size="9">/v1/debug/{status, doctor, version, logs, errors}</text>
<text x="660" y="270" fill="#fb7185" font-size="9">/v1/admin/* — requires admin scope</text>
<text x="885" y="284" fill="#34d399" font-size="8" text-anchor="middle">_envelope_dep: decrypt_request → handler → encrypt_response</text>

<line x1="700" y1="150" x2="700" y2="178" stroke="#34d399" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- crypto/ -->
<rect x="640" y="330" width="150" height="100" rx="6" fill="rgba(136, 19, 55, 0.4)"
      stroke="#fb7185" stroke-width="1.5"/>
<text x="715" y="352" fill="white" font-size="11" font-weight="600" text-anchor="middle">crypto/</text>
<text x="715" y="368" fill="#94a3b8" font-size="9" text-anchor="middle">handshake</text>
<text x="715" y="382" fill="#94a3b8" font-size="9" text-anchor="middle">envelope · replay</text>
<text x="715" y="396" fill="#94a3b8" font-size="9" text-anchor="middle">keystore</text>
<text x="715" y="410" fill="#94a3b8" font-size="9" text-anchor="middle">at_rest · kdf</text>

<!-- session -->
<rect x="810" y="330" width="150" height="100" rx="6" fill="rgba(136, 19, 55, 0.4)"
      stroke="#fb7185" stroke-width="1.5"/>
<text x="885" y="352" fill="white" font-size="11" font-weight="600" text-anchor="middle">session/</text>
<text x="885" y="368" fill="#94a3b8" font-size="9" text-anchor="middle">SessionManager</text>
<text x="885" y="382" fill="#94a3b8" font-size="9" text-anchor="middle">TTL + LRU</text>
<text x="885" y="396" fill="#94a3b8" font-size="9" text-anchor="middle">replay window</text>
<text x="885" y="410" fill="#94a3b8" font-size="9" text-anchor="middle">zeroize on close</text>

<!-- models/ -->
<rect x="980" y="330" width="150" height="100" rx="6" fill="rgba(6, 78, 59, 0.4)"
      stroke="#34d399" stroke-width="1.5"/>
<text x="1055" y="352" fill="white" font-size="11" font-weight="600" text-anchor="middle">models/</text>
<text x="1055" y="368" fill="#94a3b8" font-size="9" text-anchor="middle">ModelManager</text>
<text x="1055" y="382" fill="#94a3b8" font-size="9" text-anchor="middle">LRU + idle offload</text>
<text x="1055" y="396" fill="#94a3b8" font-size="9" text-anchor="middle">per-model worker</text>
<text x="1055" y="410" fill="#34d399" font-size="8" text-anchor="middle">llama.cpp not thread-safe</text>

<line x1="715" y1="290" x2="715" y2="328" stroke="#94a3b8" stroke-width="1" marker-end="url(#arrowhead)"/>
<line x1="885" y1="290" x2="885" y2="328" stroke="#94a3b8" stroke-width="1" marker-end="url(#arrowhead)"/>
<line x1="1055" y1="290" x2="1055" y2="328" stroke="#94a3b8" stroke-width="1" marker-end="url(#arrowhead)"/>

<!-- Keystore + allowlist -->
<rect x="640" y="460" width="150" height="80" rx="6" fill="rgba(136, 19, 55, 0.4)"
      stroke="#fb7185" stroke-width="1.5"/>
<text x="715" y="480" fill="white" font-size="11" font-weight="600" text-anchor="middle">Keystore</text>
<text x="715" y="496" fill="#94a3b8" font-size="9" text-anchor="middle">server X25519+Ed25519</text>
<text x="715" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">age identity</text>
<text x="715" y="524" fill="#94a3b8" font-size="9" text-anchor="middle">authorized_clients</text>

<line x1="715" y1="430" x2="715" y2="458" stroke="#fb7185" stroke-width="1.5" stroke-dasharray="3,3" marker-end="url(#arrowhead)"/>

<!-- Downloader -->
<rect x="980" y="460" width="150" height="80" rx="6" fill="rgba(6, 78, 59, 0.4)"
      stroke="#34d399" stroke-width="1.5"/>
<text x="1055" y="480" fill="white" font-size="11" font-weight="600" text-anchor="middle">downloader</text>
<text x="1055" y="496" fill="#94a3b8" font-size="9" text-anchor="middle">HF fetch</text>
<text x="1055" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">SHA-256 verify</text>
<text x="1055" y="524" fill="#94a3b8" font-size="9" text-anchor="middle">→ age encrypt</text>

<line x1="1055" y1="430" x2="1055" y2="458" stroke="#34d399" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Storage at-rest -->
<rect x="980" y="570" width="150" height="50" rx="6" fill="rgba(76, 29, 149, 0.4)"
      stroke="#a78bfa" stroke-width="1.5"/>
<text x="1055" y="590" fill="white" font-size="11" font-weight="600" text-anchor="middle">data/models</text>
<text x="1055" y="606" fill="#94a3b8" font-size="9" text-anchor="middle">*.gguf.age (sealed)</text>

<line x1="1055" y1="540" x2="1055" y2="568" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- tmpfs decrypt -->
<rect x="810" y="570" width="150" height="50" rx="6" fill="rgba(120, 53, 15, 0.3)"
      stroke="#fbbf24" stroke-width="1.5"/>
<text x="885" y="590" fill="white" font-size="11" font-weight="600" text-anchor="middle">/dev/shm/secure-llm</text>
<text x="885" y="606" fill="#94a3b8" font-size="9" text-anchor="middle">decrypt → mmap → unlink</text>

<line x1="978" y1="595" x2="962" y2="595" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Observability column -->
<rect x="40" y="460" width="380" height="160" rx="6" fill="rgba(30, 41, 59, 0.5)"
      stroke="#94a3b8" stroke-width="1.5"/>
<text x="230" y="482" fill="white" font-size="11" font-weight="600" text-anchor="middle">observability/</text>
<text x="60" y="504" fill="#94a3b8" font-size="9">• RingLog       — in-memory bounded log buffer</text>
<text x="60" y="520" fill="#94a3b8" font-size="9">• ErrorTracker  — error_id → sanitized stacks</text>
<text x="60" y="536" fill="#94a3b8" font-size="9">• StatusBuilder — snapshot for /v1/debug/status</text>
<text x="60" y="556" fill="white" font-size="10" font-weight="600">metrics/</text>
<text x="60" y="572" fill="#94a3b8" font-size="9">• Prometheus on /metrics (loopback)</text>
<text x="60" y="588" fill="white" font-size="10" font-weight="600">logging.py</text>
<text x="60" y="604" fill="#94a3b8" font-size="9">• structlog JSON, payload-redacted</text>

<!-- ============================================================
     LEGEND
     ============================================================ -->
<text x="40" y="700" fill="white" font-size="10" font-weight="600">Legend</text>
<rect x="100" y="691" width="14" height="10" rx="2" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1"/>
<text x="120" y="700" fill="#94a3b8" font-size="8">Client</text>
<rect x="170" y="691" width="14" height="10" rx="2" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1"/>
<text x="190" y="700" fill="#94a3b8" font-size="8">Server / Backend</text>
<rect x="290" y="691" width="14" height="10" rx="2" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1"/>
<text x="310" y="700" fill="#94a3b8" font-size="8">Crypto / Security</text>
<rect x="420" y="691" width="14" height="10" rx="2" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1"/>
<text x="440" y="700" fill="#94a3b8" font-size="8">Ephemeral / Encrypted channel</text>
<rect x="600" y="691" width="14" height="10" rx="2" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1"/>
<text x="620" y="700" fill="#94a3b8" font-size="8">Storage (at-rest sealed)</text>
<rect x="760" y="691" width="14" height="10" rx="2" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1"/>
<text x="780" y="700" fill="#94a3b8" font-size="8">Observability</text>
"""


COMPONENT_MAP = Diagram(
    slug="component-map",
    title="secure-llm — Component Map",
    subtitle="End-to-end-encrypted LLM inference: client SDK ↔ TLS + AEAD envelope ↔ FastAPI server, "
    "with per-tenant model + LoRA storage, federated session state, and TEE-attestable handshake (v2.0)",
    viewbox="0 0 1200 720",
    svg_body=COMPONENT_MAP_SVG,
    cards=[
        (
            "cyan",
            "Client",
            [
                "• sllm CLI (Typer + Rich)",
                "• SecureLLMClient — OpenAI-shape SDK",
                "• Transport: handshake on first call,",
                "  envelope wrap/unwrap, replay protection",
                "• known_hosts (SSH-style TOFU pinning)",
            ],
        ),
        (
            "emerald",
            "Server",
            [
                "• FastAPI + uvicorn (TLS 1.3)",
                "• Middleware: req_id, rate_limit, size_limit",
                "• Routers: session, models, chat,",
                "  completions, system, debug, admin",
                "• ModelManager: LRU + idle-offload,",
                "  one inference worker per loaded model",
            ],
        ),
        (
            "rose",
            "Confidentiality",
            [
                "• X25519 ECDH (static + ephemeral)",
                "• Ed25519 transcript signatures",
                "• ChaCha20-Poly1305-IETF envelope",
                "• AAD = method + path + session + counter",
                "• age at-rest for *.gguf.age files",
                "• decrypt → tmpfs → unlink-after-mmap",
            ],
        ),
        (
            "violet",
            "Tenants + LoRA (v1.2)",
            [
                "• AuthorizedClient.tenant (default + named)",
                "• per-tenant data/{models,loras}/tenants/<t>/",
                "• ModelManager._loaded keyed by",
                "  (tenant, model_id, mode, lora-fp)",
                "• super_admin scope for cross-tenant ops",
                "• SSE streaming + /v1/embeddings (v1.1)",
            ],
        ),
        (
            "amber",
            "Federation + TEE (v1.3 + v2.0)",
            [
                "• SessionStore Protocol",
                "  InMemory (default) | Redis-backed",
                "• Shared identity across fleet,",
                "  SNI-passthrough LB, failover via hydrate",
                "• AttestationBackend + Verifier (Mock/None,",
                "  SEV-SNP/Nitro stubs)",
                "• Multimodal ChatContentPart (text+image_url)",
            ],
        ),
    ],
    footer="secure-llm · protocol/1.0 · v2.0 foundation (TEE attestation + multimodal + federation) · Apache-2.0",
)


# ---------------------------------------------------------------------------
# Diagram 2 — Request lifecycle
# ---------------------------------------------------------------------------

REQUEST_LIFECYCLE_SVG = r"""
<!-- swimlanes -->
<line x1="280" y1="60" x2="280" y2="900" stroke="#1e293b" stroke-width="1"/>
<line x1="920" y1="60" x2="920" y2="900" stroke="#1e293b" stroke-width="1"/>

<rect x="40" y="40" width="240" height="30" rx="6" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1.5"/>
<text x="160" y="60" fill="white" font-size="12" font-weight="600" text-anchor="middle">Client</text>

<rect x="280" y="40" width="640" height="30" rx="6" fill="rgba(251, 191, 36, 0.10)" stroke="#fbbf24" stroke-width="1.5" stroke-dasharray="4,4"/>
<text x="600" y="60" fill="#fbbf24" font-size="12" font-weight="600" text-anchor="middle">Wire (TLS 1.3 + AEAD Envelope)</text>

<rect x="920" y="40" width="240" height="30" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="1040" y="60" fill="white" font-size="12" font-weight="600" text-anchor="middle">Server</text>

<!-- Boot note -->
<rect x="920" y="90" width="240" height="60" rx="6" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="1040" y="110" fill="white" font-size="10" font-weight="600" text-anchor="middle">boot</text>
<text x="1040" y="126" fill="#94a3b8" font-size="9" text-anchor="middle">load identity + allowlist</text>
<text x="1040" y="140" fill="#94a3b8" font-size="9" text-anchor="middle">start lifespan + reaper</text>

<!-- ============================================================
     STEP 1 — Handshake
     ============================================================ -->
<rect x="40" y="180" width="240" height="80" rx="6" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1.5"/>
<text x="160" y="200" fill="white" font-size="11" font-weight="600" text-anchor="middle">1. Build HandshakeRequest</text>
<text x="160" y="218" fill="#94a3b8" font-size="9" text-anchor="middle">client_static_pk, client_eph_pk</text>
<text x="160" y="232" fill="#94a3b8" font-size="9" text-anchor="middle">timestamp</text>
<text x="160" y="250" fill="#fb7185" font-size="9" text-anchor="middle">Ed25519 sign(transcript)</text>

<!-- arrow + envelope label -->
<line x1="280" y1="220" x2="918" y2="220" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="600" y="212" fill="#fbbf24" font-size="9" text-anchor="middle">POST /v1/session  (plaintext JSON — only endpoint that is)</text>

<rect x="920" y="180" width="240" height="160" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="1040" y="200" fill="white" font-size="11" font-weight="600" text-anchor="middle">2. perform_handshake()</text>
<text x="940" y="220" fill="#94a3b8" font-size="9">• check protocol version</text>
<text x="940" y="234" fill="#94a3b8" font-size="9">• |now − ts| ≤ 30 s</text>
<text x="940" y="248" fill="#94a3b8" font-size="9">• allowlist lookup</text>
<text x="940" y="262" fill="#fb7185" font-size="9">• Ed25519 verify sig</text>
<text x="940" y="276" fill="#94a3b8" font-size="9">• generate server_eph</text>
<text x="940" y="290" fill="#fbbf24" font-size="9">• dh1 = X25519(srv_eph, cli_eph)</text>
<text x="940" y="304" fill="#fbbf24" font-size="9">• dh2 = X25519(srv_stat, cli_stat)</text>
<text x="940" y="318" fill="#a78bfa" font-size="9">• HKDF(dh1‖dh2, T) → keys</text>
<text x="940" y="332" fill="#94a3b8" font-size="9">• SessionManager.create</text>

<line x1="918" y1="380" x2="282" y2="380" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="600" y="372" fill="#fbbf24" font-size="9" text-anchor="middle">HandshakeResponse: session_id, eph_pk, ttl, server_sig, nonce prefixes</text>

<rect x="40" y="380" width="240" height="100" rx="6" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1.5"/>
<text x="160" y="400" fill="white" font-size="11" font-weight="600" text-anchor="middle">3. derive_session()</text>
<text x="60" y="420" fill="#94a3b8" font-size="9">• verify pinned server_pk</text>
<text x="60" y="434" fill="#fb7185" font-size="9">• verify Ed25519 sig</text>
<text x="60" y="448" fill="#a78bfa" font-size="9">• derive same c2s/s2c keys</text>
<text x="60" y="462" fill="#94a3b8" font-size="9">• stash _SessionState in Transport</text>

<!-- ============================================================
     STEP 2 — Encrypted request
     ============================================================ -->
<rect x="40" y="520" width="240" height="140" rx="6" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1.5"/>
<text x="160" y="540" fill="white" font-size="11" font-weight="600" text-anchor="middle">4. seal() request body</text>
<text x="60" y="560" fill="#94a3b8" font-size="9">plaintext = {model, messages, ...}</text>
<text x="60" y="574" fill="#94a3b8" font-size="9">c2s_counter += 1</text>
<text x="60" y="588" fill="#94a3b8" font-size="9">nonce = prefix(4) ‖ counter(8)</text>
<text x="60" y="602" fill="#fb7185" font-size="9">aad = magic‖ver‖sid‖ctr‖</text>
<text x="60" y="616" fill="#fb7185" font-size="9">      "POST"‖"/v1/chat/completions"</text>
<text x="60" y="634" fill="#a78bfa" font-size="9">ct = ChaCha20-Poly1305(pt, aad, n, k)</text>
<text x="60" y="652" fill="#94a3b8" font-size="9">body = pack_envelope(sid, ctr, n, ct)</text>

<line x1="280" y1="590" x2="918" y2="590" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="600" y="582" fill="#a78bfa" font-size="9" text-anchor="middle">POST /v1/chat/completions  (envelope-encrypted)</text>

<rect x="920" y="520" width="240" height="280" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="1040" y="540" fill="white" font-size="11" font-weight="600" text-anchor="middle">5. decrypt_request()</text>
<text x="940" y="560" fill="#94a3b8" font-size="9">• parse envelope header</text>
<text x="940" y="574" fill="#94a3b8" font-size="9">• SessionManager.lookup</text>
<text x="940" y="588" fill="#fb7185" font-size="9">• replay window check</text>
<text x="940" y="602" fill="#fb7185" font-size="9">• rebuild AAD with method+path</text>
<text x="940" y="616" fill="#a78bfa" font-size="9">• AEAD decrypt → JSON</text>
<text x="940" y="630" fill="#94a3b8" font-size="9">• pydantic validate → schema</text>
<text x="940" y="650" fill="white" font-size="10" font-weight="600">6. ModelManager.chat()</text>
<text x="940" y="668" fill="#94a3b8" font-size="9">• ensure_loaded(model)</text>
<text x="940" y="682" fill="#fbbf24" font-size="9">  → decrypt_to_tmpfs</text>
<text x="940" y="696" fill="#fbbf24" font-size="9">  → Llama(mmap)</text>
<text x="940" y="710" fill="#fbbf24" font-size="9">  → unlink tmpfs file</text>
<text x="940" y="724" fill="#94a3b8" font-size="9">• submit job to per-model queue</text>
<text x="940" y="738" fill="#94a3b8" font-size="9">• worker → create_chat_completion</text>
<text x="940" y="758" fill="white" font-size="10" font-weight="600">7. encrypt_response()</text>
<text x="940" y="776" fill="#94a3b8" font-size="9">• bump s2c_counter</text>
<text x="940" y="790" fill="#a78bfa" font-size="9">• AEAD encrypt response JSON</text>

<line x1="918" y1="730" x2="282" y2="730" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="600" y="722" fill="#a78bfa" font-size="9" text-anchor="middle">ChatCompletionResponse  (envelope-encrypted)</text>

<rect x="40" y="710" width="240" height="100" rx="6" fill="rgba(8, 51, 68, 0.4)" stroke="#22d3ee" stroke-width="1.5"/>
<text x="160" y="730" fill="white" font-size="11" font-weight="600" text-anchor="middle">8. open_envelope()</text>
<text x="60" y="750" fill="#94a3b8" font-size="9">• AEAD decrypt with s2c.key</text>
<text x="60" y="764" fill="#fb7185" font-size="9">• client-side replay check</text>
<text x="60" y="778" fill="#94a3b8" font-size="9">• pydantic parse</text>
<text x="60" y="792" fill="#34d399" font-size="9">  → ChatCompletionResponse</text>

<!-- Note -->
<rect x="320" y="830" width="560" height="50" rx="6" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="600" y="850" fill="white" font-size="10" font-weight="600" text-anchor="middle">Session keys never touch disk.</text>
<text x="600" y="866" fill="#94a3b8" font-size="9" text-anchor="middle">Subsequent requests reuse the session up to TTL; counter is monotonic per direction.</text>
"""


REQUEST_LIFECYCLE = Diagram(
    slug="request-lifecycle",
    title="secure-llm — Request Lifecycle",
    subtitle="From plaintext handshake to encrypted chat completion and back, with replay + AAD-binding protections",
    viewbox="0 0 1200 920",
    svg_body=REQUEST_LIFECYCLE_SVG,
    cards=[
        (
            "rose",
            "Identity & auth",
            [
                "• Client X25519 + Ed25519 (allowlist)",
                "• Server X25519 + Ed25519 (TOFU-pinned)",
                "• Ed25519 sig over handshake transcript",
                "• Skew check ≤ 30 s",
                "• Scopes & revocation flags",
            ],
        ),
        (
            "violet",
            "Per-session keys",
            [
                "• ikm = X25519(eph, eph) ‖ X25519(stat, stat)",
                "• HKDF-SHA-256 → c2s_key, s2c_key",
                "  + 4-byte nonce prefix per direction",
                "• Live only in SessionManager (RAM)",
                "• Zeroized on TTL or DELETE",
            ],
        ),
        (
            "amber",
            "Envelope per call",
            [
                "• AAD = method + path + session + counter",
                "• Nonce = prefix ‖ counter (monotonic)",
                "• ChaCha20-Poly1305-IETF",
                "• 1024-bit sliding replay window",
                "• Uniform ~200 ms latency floor on auth",
            ],
        ),
    ],
    footer="secure-llm · /v1/session is the only plaintext endpoint",
)


# ---------------------------------------------------------------------------
# Diagram 3 — Cryptographic flow
# ---------------------------------------------------------------------------

CRYPTO_FLOW_SVG = r"""
<!-- ============================================================
     IDENTITIES (top row)
     ============================================================ -->
<rect x="40" y="60" width="320" height="120" rx="8"
      fill="rgba(136, 19, 55, 0.10)" stroke="#fb7185" stroke-width="1" stroke-dasharray="4,4"/>
<text x="200" y="80" fill="#fb7185" font-size="10" font-weight="600" text-anchor="middle">CLIENT IDENTITY (long-lived)</text>

<rect x="60" y="100" width="130" height="60" rx="6" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1.5"/>
<text x="125" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">X25519</text>
<text x="125" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">static_sk / static_pk</text>
<text x="125" y="150" fill="#94a3b8" font-size="9" text-anchor="middle">for ECDH</text>

<rect x="210" y="100" width="130" height="60" rx="6" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1.5"/>
<text x="275" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">Ed25519</text>
<text x="275" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">signing_sk / pk</text>
<text x="275" y="150" fill="#94a3b8" font-size="9" text-anchor="middle">for transcript sig</text>

<rect x="440" y="60" width="320" height="120" rx="8"
      fill="rgba(136, 19, 55, 0.10)" stroke="#fb7185" stroke-width="1" stroke-dasharray="4,4"/>
<text x="600" y="80" fill="#fb7185" font-size="10" font-weight="600" text-anchor="middle">SERVER IDENTITY (long-lived)</text>

<rect x="460" y="100" width="130" height="60" rx="6" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1.5"/>
<text x="525" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">X25519</text>
<text x="525" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">static_sk / static_pk</text>
<text x="525" y="150" fill="#22d3ee" font-size="9" text-anchor="middle">TOFU-pinned client side</text>

<rect x="610" y="100" width="130" height="60" rx="6" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1.5"/>
<text x="675" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">Ed25519</text>
<text x="675" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">signing_sk / pk</text>
<text x="675" y="150" fill="#94a3b8" font-size="9" text-anchor="middle">in response</text>

<rect x="800" y="60" width="360" height="120" rx="8"
      fill="rgba(76, 29, 149, 0.10)" stroke="#a78bfa" stroke-width="1" stroke-dasharray="4,4"/>
<text x="980" y="80" fill="#a78bfa" font-size="10" font-weight="600" text-anchor="middle">AT-REST KEY (server-only)</text>

<rect x="820" y="100" width="320" height="60" rx="6" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1.5"/>
<text x="980" y="120" fill="white" font-size="11" font-weight="600" text-anchor="middle">age X25519 identity (pyrage)</text>
<text x="980" y="136" fill="#94a3b8" font-size="9" text-anchor="middle">encrypts data/models/*.gguf.age</text>
<text x="980" y="150" fill="#94a3b8" font-size="9" text-anchor="middle">decrypts on every load</text>

<!-- ============================================================
     TRANSCRIPT
     ============================================================ -->
<rect x="240" y="220" width="720" height="120" rx="8"
      fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="600" y="240" fill="white" font-size="11" font-weight="600" text-anchor="middle">Transcript T</text>
<text x="260" y="262" fill="#94a3b8" font-size="10">  T = "secure-llm/1.0"  ‖</text>
<text x="260" y="278" fill="#94a3b8" font-size="10">      client_static_pk  ‖</text>
<text x="260" y="294" fill="#94a3b8" font-size="10">      client_eph_pk    ‖   server_host  ‖   timestamp</text>
<text x="260" y="316" fill="#fb7185" font-size="10">  client signs T with its Ed25519 → server verifies against allowlist</text>

<line x1="200" y1="180" x2="450" y2="218" stroke="#fb7185" stroke-width="1" stroke-dasharray="3,3"/>
<line x1="600" y1="180" x2="700" y2="218" stroke="#fb7185" stroke-width="1" stroke-dasharray="3,3"/>

<!-- ============================================================
     ECDH SHARES
     ============================================================ -->
<rect x="60" y="380" width="500" height="100" rx="6" fill="rgba(251, 191, 36, 0.10)"
      stroke="#fbbf24" stroke-width="1.5" stroke-dasharray="4,4"/>
<text x="310" y="402" fill="#fbbf24" font-size="11" font-weight="600" text-anchor="middle">Ephemeral × Ephemeral</text>
<text x="310" y="424" fill="white" font-size="11" text-anchor="middle">dh1 = X25519(server_eph_sk, client_eph_pk)</text>
<text x="310" y="446" fill="#94a3b8" font-size="9" text-anchor="middle">forward secrecy: compromise of ephemeral keys</text>
<text x="310" y="460" fill="#94a3b8" font-size="9" text-anchor="middle">doesn't reveal past or future sessions</text>

<rect x="640" y="380" width="500" height="100" rx="6" fill="rgba(251, 191, 36, 0.10)"
      stroke="#fbbf24" stroke-width="1.5" stroke-dasharray="4,4"/>
<text x="890" y="402" fill="#fbbf24" font-size="11" font-weight="600" text-anchor="middle">Static × Static</text>
<text x="890" y="424" fill="white" font-size="11" text-anchor="middle">dh2 = X25519(server_static_sk, client_static_pk)</text>
<text x="890" y="446" fill="#94a3b8" font-size="9" text-anchor="middle">mutual authentication — only the real client</text>
<text x="890" y="460" fill="#94a3b8" font-size="9" text-anchor="middle">and real server can produce dh2</text>

<!-- HKDF -->
<rect x="300" y="520" width="600" height="100" rx="8" fill="rgba(76, 29, 149, 0.4)"
      stroke="#a78bfa" stroke-width="1.5"/>
<text x="600" y="544" fill="white" font-size="12" font-weight="600" text-anchor="middle">HKDF-SHA-256</text>
<text x="600" y="566" fill="#a78bfa" font-size="10" text-anchor="middle">ikm  = dh1 ‖ dh2</text>
<text x="600" y="582" fill="#a78bfa" font-size="10" text-anchor="middle">salt = full_transcript (binds keys to identities + session_id)</text>
<text x="600" y="598" fill="#a78bfa" font-size="10" text-anchor="middle">info = b"secure-llm session keys v1"   →   72 bytes out</text>

<line x1="310" y1="478" x2="500" y2="520" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="890" y1="478" x2="700" y2="520" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- session keys -->
<rect x="60" y="660" width="240" height="80" rx="6" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1.5"/>
<text x="180" y="682" fill="white" font-size="11" font-weight="600" text-anchor="middle">c2s_key  (32 bytes)</text>
<text x="180" y="700" fill="#94a3b8" font-size="9" text-anchor="middle">c2s_nonce_prefix (4 bytes)</text>
<text x="180" y="720" fill="#a78bfa" font-size="9" text-anchor="middle">client → server direction</text>

<rect x="900" y="660" width="240" height="80" rx="6" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1.5"/>
<text x="1020" y="682" fill="white" font-size="11" font-weight="600" text-anchor="middle">s2c_key  (32 bytes)</text>
<text x="1020" y="700" fill="#94a3b8" font-size="9" text-anchor="middle">s2c_nonce_prefix (4 bytes)</text>
<text x="1020" y="720" fill="#a78bfa" font-size="9" text-anchor="middle">server → client direction</text>

<line x1="500" y1="620" x2="200" y2="658" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="700" y1="620" x2="1000" y2="658" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- Envelope use -->
<rect x="350" y="780" width="500" height="120" rx="6" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1.5"/>
<text x="600" y="802" fill="white" font-size="11" font-weight="600" text-anchor="middle">Envelope wraps every body</text>
<text x="600" y="822" fill="#fbbf24" font-size="10" text-anchor="middle">nonce  = prefix(4) ‖ counter(8)   — monotonic per direction</text>
<text x="600" y="838" fill="#fbbf24" font-size="10" text-anchor="middle">aad    = magic ‖ ver ‖ session_id ‖ counter ‖ METHOD ‖ PATH</text>
<text x="600" y="854" fill="#fbbf24" font-size="10" text-anchor="middle">ct,tag = ChaCha20-Poly1305-IETF(plaintext, aad, nonce, key)</text>
<text x="600" y="876" fill="#fb7185" font-size="10" text-anchor="middle">Replay protection: 1024-bit sliding window on counter, per session</text>

<line x1="180" y1="740" x2="450" y2="778" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="1020" y1="740" x2="750" y2="778" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>

<!-- properties legend -->
<text x="40" y="940" fill="white" font-size="10" font-weight="600">Properties</text>
<rect x="120" y="930" width="14" height="10" rx="2" fill="rgba(251, 191, 36, 0.10)" stroke="#fbbf24" stroke-width="1" stroke-dasharray="3,3"/>
<text x="140" y="939" fill="#94a3b8" font-size="8">Ephemeral / DH</text>
<rect x="240" y="930" width="14" height="10" rx="2" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1"/>
<text x="260" y="939" fill="#94a3b8" font-size="8">Derived session material (RAM only)</text>
<rect x="450" y="930" width="14" height="10" rx="2" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1"/>
<text x="470" y="939" fill="#94a3b8" font-size="8">Long-lived identity / pin</text>
<rect x="650" y="930" width="14" height="10" rx="2" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1"/>
<text x="670" y="939" fill="#94a3b8" font-size="8">Symmetric AEAD on wire</text>
"""


CRYPTO_FLOW = Diagram(
    slug="crypto-flow",
    title="secure-llm — Cryptographic Flow",
    subtitle="Static + ephemeral X25519 → HKDF-SHA-256 → ChaCha20-Poly1305-IETF, with AAD bound to method+path",
    viewbox="0 0 1200 960",
    svg_body=CRYPTO_FLOW_SVG,
    cards=[
        (
            "rose",
            "Identities (long-lived)",
            [
                "• Client: X25519 + Ed25519 keypairs",
                "• Server: X25519 + Ed25519 keypairs",
                "• Server age identity (pyrage)",
                "• File mode 0600 in data/keys/",
                "• Client pubkeys in allowlist;",
                "  server pubkey TOFU-pinned",
            ],
        ),
        (
            "amber",
            "Key derivation",
            [
                "• Ed25519 sig over full transcript",
                "• dh1 = ephemeral × ephemeral (FS)",
                "• dh2 = static × static (mutual auth)",
                "• HKDF-SHA-256(ikm, transcript, info)",
                "• → c2s/s2c keys + nonce prefixes",
                "• Session keys never leave RAM",
            ],
        ),
        (
            "violet",
            "On-the-wire envelope",
            [
                "• ChaCha20-Poly1305-IETF",
                "• Nonce = prefix(4) ‖ counter(8)",
                "• AAD binds method + path + session",
                "• 1024-bit sliding replay window",
                "• AEAD failure → uniform error,",
                "  ~200 ms latency floor",
            ],
        ),
        (
            "cyan",
            "TEE attestation (v2.0)",
            [
                "• Optional attestation_report on handshake",
                "• userdata = SHA-256(full transcript)",
                "  — binds report to *this* handshake",
                "• Backends: None | Mock | SEV-SNP (stub)",
                "  | Nitro (stub)",
                "• Client pins `measurement` in",
                "  known_hosts.toml; attestation_required",
                "  fails closed when omitted",
            ],
        ),
    ],
    footer="See docs/protocol.md for the byte-for-byte spec · v2.0 foundation",
)


# ---------------------------------------------------------------------------
# Diagram 4 — Model lifecycle
# ---------------------------------------------------------------------------

MODEL_LIFECYCLE_SVG = r"""
<!-- states -->
<rect x="60" y="100" width="140" height="60" rx="6" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="130" y="124" fill="white" font-size="12" font-weight="600" text-anchor="middle">absent</text>
<text x="130" y="142" fill="#94a3b8" font-size="9" text-anchor="middle">not on disk</text>

<rect x="280" y="100" width="160" height="60" rx="6" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1.5"/>
<text x="360" y="124" fill="white" font-size="12" font-weight="600" text-anchor="middle">downloading</text>
<text x="360" y="142" fill="#94a3b8" font-size="9" text-anchor="middle">HF + SHA-256 verify</text>

<rect x="520" y="100" width="140" height="60" rx="6" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1.5"/>
<text x="590" y="124" fill="white" font-size="12" font-weight="600" text-anchor="middle">present</text>
<text x="590" y="142" fill="#94a3b8" font-size="9" text-anchor="middle">*.gguf.age sealed</text>

<rect x="740" y="100" width="160" height="60" rx="6" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1.5"/>
<text x="820" y="124" fill="white" font-size="12" font-weight="600" text-anchor="middle">loading</text>
<text x="820" y="142" fill="#94a3b8" font-size="9" text-anchor="middle">decrypt → mmap → unlink</text>

<rect x="980" y="100" width="160" height="60" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="1060" y="124" fill="white" font-size="12" font-weight="600" text-anchor="middle">loaded</text>
<text x="1060" y="142" fill="#94a3b8" font-size="9" text-anchor="middle">serving inference</text>

<rect x="740" y="240" width="160" height="60" rx="6" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="820" y="264" fill="white" font-size="12" font-weight="600" text-anchor="middle">unloading</text>
<text x="820" y="282" fill="#94a3b8" font-size="9" text-anchor="middle">drain queue, drop Llama</text>

<rect x="60" y="240" width="220" height="60" rx="6" fill="rgba(136, 19, 55, 0.4)" stroke="#fb7185" stroke-width="1.5"/>
<text x="170" y="264" fill="white" font-size="12" font-weight="600" text-anchor="middle">error</text>
<text x="170" y="282" fill="#94a3b8" font-size="9" text-anchor="middle">last_error surfaced via /v1/models</text>

<!-- transitions -->
<line x1="200" y1="130" x2="278" y2="130" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="239" y="120" fill="#fbbf24" font-size="9" text-anchor="middle">pull</text>

<line x1="440" y1="130" x2="518" y2="130" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="479" y="120" fill="#a78bfa" font-size="9" text-anchor="middle">age encrypt</text>

<line x1="660" y1="130" x2="738" y2="130" stroke="#fbbf24" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="699" y="120" fill="#fbbf24" font-size="9" text-anchor="middle">first call</text>

<line x1="900" y1="130" x2="978" y2="130" stroke="#34d399" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="939" y="120" fill="#34d399" font-size="9" text-anchor="middle">ready</text>

<line x1="1060" y1="160" x2="820" y2="238" stroke="#94a3b8" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="975" y="195" fill="#94a3b8" font-size="9">idle / LRU evict</text>

<line x1="740" y1="270" x2="660" y2="160" stroke="#a78bfa" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="660" y="220" fill="#a78bfa" font-size="9">unloaded</text>

<line x1="280" y1="240" x2="200" y2="160" stroke="#fb7185" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<text x="222" y="210" fill="#fb7185" font-size="9">download fail / corrupt</text>

<line x1="820" y1="160" x2="820" y2="238" stroke="#fb7185" stroke-width="1" stroke-dasharray="3,3" marker-end="url(#arrowhead)"/>
<text x="833" y="200" fill="#fb7185" font-size="9">load fail</text>

<!-- ============================================================
     INTERNALS: Loaded[id]
     ============================================================ -->
<rect x="60" y="380" width="1100" height="220" rx="12" fill="rgba(6, 78, 59, 0.10)" stroke="#34d399" stroke-width="1" stroke-dasharray="6,6"/>
<text x="80" y="402" fill="#34d399" font-size="11" font-weight="600">Internals — Loaded[id] (one per loaded model)</text>

<rect x="100" y="430" width="220" height="140" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="210" y="454" fill="white" font-size="11" font-weight="600" text-anchor="middle">Llama instance</text>
<text x="210" y="474" fill="#94a3b8" font-size="9" text-anchor="middle">llama_cpp.Llama</text>
<text x="210" y="490" fill="#fb7185" font-size="9" text-anchor="middle">NOT thread-safe</text>
<text x="210" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">mmap-backed by</text>
<text x="210" y="524" fill="#94a3b8" font-size="9" text-anchor="middle">/dev/shm/secure-llm/&lt;uuid&gt;</text>
<text x="210" y="544" fill="#fbbf24" font-size="9" text-anchor="middle">tmpfs file already unlinked</text>

<rect x="360" y="430" width="220" height="140" rx="6" fill="rgba(251, 146, 60, 0.30)" stroke="#fb923c" stroke-width="1.5"/>
<text x="470" y="454" fill="white" font-size="11" font-weight="600" text-anchor="middle">asyncio.Queue</text>
<text x="470" y="476" fill="#94a3b8" font-size="9" text-anchor="middle">maxsize = queue_depth_per_model</text>
<text x="470" y="496" fill="#94a3b8" font-size="9" text-anchor="middle">FIFO of _Job{kind, payload,</text>
<text x="470" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">stream, future, cancel_event}</text>
<text x="470" y="532" fill="#fb923c" font-size="9" text-anchor="middle">overflow → HTTP 503</text>
<text x="470" y="546" fill="#fb923c" font-size="9" text-anchor="middle">+ Retry-After</text>

<rect x="620" y="430" width="220" height="140" rx="6" fill="rgba(6, 78, 59, 0.4)" stroke="#34d399" stroke-width="1.5"/>
<text x="730" y="454" fill="white" font-size="11" font-weight="600" text-anchor="middle">InferenceWorker</text>
<text x="730" y="476" fill="#94a3b8" font-size="9" text-anchor="middle">single asyncio.Task per model</text>
<text x="730" y="496" fill="#94a3b8" font-size="9" text-anchor="middle">consumes queue, calls</text>
<text x="730" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">Llama.create_chat_completion</text>
<text x="730" y="532" fill="#34d399" font-size="9" text-anchor="middle">serializes all callers; safe</text>
<text x="730" y="546" fill="#34d399" font-size="9" text-anchor="middle">use of the un-shared backend</text>

<rect x="880" y="430" width="240" height="140" rx="6" fill="rgba(120, 53, 15, 0.3)" stroke="#fbbf24" stroke-width="1.5"/>
<text x="1000" y="454" fill="white" font-size="11" font-weight="600" text-anchor="middle">Idle timer</text>
<text x="1000" y="476" fill="#94a3b8" font-size="9" text-anchor="middle">asyncio.TimerHandle</text>
<text x="1000" y="490" fill="#94a3b8" font-size="9" text-anchor="middle">idle_timeout_seconds (300s)</text>
<text x="1000" y="510" fill="#94a3b8" font-size="9" text-anchor="middle">reset on every job</text>
<text x="1000" y="530" fill="#fbbf24" font-size="9" text-anchor="middle">on fire → graceful unload</text>
<text x="1000" y="546" fill="#fbbf24" font-size="9" text-anchor="middle">→ gc + cuda.empty_cache</text>

<line x1="320" y1="500" x2="358" y2="500" stroke="#fb923c" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="580" y1="500" x2="618" y2="500" stroke="#fb923c" stroke-width="1.5" marker-end="url(#arrowhead)"/>
<line x1="840" y1="500" x2="878" y2="500" stroke="#34d399" stroke-width="1.5" marker-end="url(#arrowhead)" stroke-dasharray="3,3"/>
<text x="858" y="490" fill="#34d399" font-size="9" text-anchor="middle">touch</text>

<!-- ============================================================
     LRU + max_loaded note
     ============================================================ -->
<rect x="60" y="640" width="1100" height="100" rx="6" fill="rgba(30, 41, 59, 0.5)" stroke="#94a3b8" stroke-width="1.5"/>
<text x="80" y="662" fill="white" font-size="11" font-weight="600">LRU eviction policy</text>
<text x="80" y="682" fill="#94a3b8" font-size="9">• ModelManager keeps an OrderedDict[model_id, Loaded] capped at max_loaded (default 1).</text>
<text x="80" y="698" fill="#94a3b8" font-size="9">• ensure_loaded() evicts the head of the OrderedDict when the cap is reached, before loading the new model.</text>
<text x="80" y="714" fill="#94a3b8" font-size="9">• Eviction reason is emitted as a metric / log event; the evicted entry transitions present ◄── loaded.</text>
<text x="80" y="730" fill="#fb7185" font-size="9">• Decrypted bytes are only ever in /dev/shm; on process exit the mmap is dropped and the bytes are gone.</text>

<!-- v1.2 cache key callout -->
<rect x="60" y="760" width="1100" height="40" rx="6" fill="rgba(76, 29, 149, 0.4)" stroke="#a78bfa" stroke-width="1.5"/>
<text x="80" y="780" fill="white" font-size="11" font-weight="600">v1.2 cache key: (tenant, model_id, mode, lora-fp)</text>
<text x="80" y="794" fill="#94a3b8" font-size="9">Changing LoRA set → reload into a fresh slot; same tuple → reuse. Per-tenant model + LoRA dirs are mounted by tenant_subdir().</text>
"""


MODEL_LIFECYCLE = Diagram(
    slug="model-lifecycle",
    title="secure-llm — Model Lifecycle",
    subtitle="State machine + per-loaded internals: how a (tenant, model, mode, LoRA-set) tuple "
    "goes from absent → loaded → idle-offload (v1.2)",
    viewbox="0 0 1200 820",
    svg_body=MODEL_LIFECYCLE_SVG,
    cards=[
        (
            "amber",
            "Disk → RAM (load)",
            [
                "• Read *.gguf.age (age-encrypted)",
                "• pyrage.decrypt → /dev/shm/<uuid>",
                "• Stack each *.lora.gguf.age via ExitStack",
                "• Llama(mmap-only) opens path + lora_path",
                "• os.unlink each tmpfs file immediately",
            ],
        ),
        (
            "emerald",
            "Concurrency",
            [
                "• One InferenceWorker per model",
                "• Bounded asyncio.Queue",
                "• Concurrent callers serialize",
                "• Overflow → 503 + Retry-After",
                "• llama_cpp.Llama isn't thread-safe",
            ],
        ),
        (
            "violet",
            "Lifecycle controls",
            [
                "• max_loaded (LRU cap, default 1)",
                "• idle_timeout_seconds (default 300)",
                "• Reset on each completed job",
                "• admin.preload / admin.unload",
                "• Graceful drain on shutdown",
            ],
        ),
    ],
    footer="ModelManager: see server/secure_llm_server/models/manager.py",
)


DIAGRAMS: list[Diagram] = [
    COMPONENT_MAP,
    REQUEST_LIFECYCLE,
    CRYPTO_FLOW,
    MODEL_LIFECYCLE,
]


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def render(diagram: Diagram, template: str) -> str:
    out = template
    # Title (head + h1 share the same placeholder)
    out = out.replace(
        "[PROJECT NAME] Architecture Diagram", f"{diagram.title} — Architecture Diagram"
    )
    out = out.replace("[PROJECT NAME] Architecture", diagram.title)
    out = out.replace("[Subtitle description]", diagram.subtitle)

    # SVG: replace the entire <svg ...> ... </svg> block in the diagram
    # container with our viewBox + body.
    svg_open = re.compile(r'<svg viewBox="[^"]*">[\s\S]*?</svg>', re.MULTILINE)
    new_svg = (
        f'<svg viewBox="{diagram.viewbox}">\n'
        f"        <defs>\n"
        f'          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">\n'
        f'            <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />\n'
        f"          </marker>\n"
        f'          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">\n'
        f'            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" stroke-width="0.5"/>\n'
        f"          </pattern>\n"
        f"        </defs>\n"
        f'        <rect width="100%" height="100%" fill="url(#grid)" />\n'
        f"{diagram.svg_body}\n"
        f"      </svg>"
    )
    out, n = svg_open.subn(new_svg, out, count=1)
    if n != 1:
        raise RuntimeError("could not splice SVG into template")

    # Replace the cards block.
    cards_html = []
    for color, title, bullets in diagram.cards:
        items = "\n          ".join(f"<li>• {b.lstrip('•').lstrip()}</li>" for b in bullets)
        cards_html.append(f"""      <div class="card">
        <div class="card-header">
          <div class="card-dot {color}"></div>
          <h3>{title}</h3>
        </div>
        <ul>
          {items}
        </ul>
      </div>""")
    cards_block = "\n\n".join(cards_html)

    cards_re = re.compile(r'<div class="cards">[\s\S]*?</div>\s*\n\s*<!-- Footer -->', re.MULTILINE)
    out, n = cards_re.subn(
        f'<div class="cards">\n{cards_block}\n    </div>\n\n    <!-- Footer -->',
        out,
        count=1,
    )
    if n != 1:
        raise RuntimeError("could not splice cards block")

    # Footer text
    footer_re = re.compile(r'<p class="footer">[\s\S]*?</p>', re.MULTILINE)
    out, n = footer_re.subn(f'<p class="footer">\n      {diagram.footer}\n    </p>', out, count=1)
    if n != 1:
        raise RuntimeError("could not splice footer")
    return out


def render_svg(diagram: Diagram) -> str:
    """Standalone SVG suitable for embedding in markdown (GitHub renders inline SVG).

    Includes the xmlns declaration, the same defs (arrow marker + grid) the HTML
    template uses, an opaque dark background so the dark theme survives on a
    light page, and the per-diagram svg_body.
    """
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{diagram.viewbox}" '
        f'font-family="JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace">\n'
        f"  <defs>\n"
        f'    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">\n'
        f'      <polygon points="0 0, 10 3.5, 0 7" fill="#64748b"/>\n'
        f"    </marker>\n"
        f'    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">\n'
        f'      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" stroke-width="0.5"/>\n'
        f"    </pattern>\n"
        f"  </defs>\n"
        f'  <rect width="100%" height="100%" fill="#020617"/>\n'
        f'  <rect width="100%" height="100%" fill="url(#grid)"/>\n'
        f"{diagram.svg_body}\n"
        f"</svg>\n"
    )


def main() -> int:
    template = TEMPLATE.read_text(encoding="utf-8")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for d in DIAGRAMS:
        html = render(d, template)
        html_path = OUT_DIR / f"{d.slug}.html"
        html_path.write_text(html, encoding="utf-8")
        print(f"wrote {html_path}  ({len(html)} bytes)")

        svg = render_svg(d)
        svg_path = OUT_DIR / f"{d.slug}.svg"
        svg_path.write_text(svg, encoding="utf-8")
        print(f"wrote {svg_path}  ({len(svg)} bytes)")

    index = OUT_DIR / "index.md"
    lines = [
        "# Architecture diagrams",
        "",
        "Each diagram ships in two forms:",
        "",
        "- **`<slug>.html`** — self-contained dark-themed page with a",
        "  Copy / PNG / PDF export toolbar (open in any browser).",
        "- **`<slug>.svg`** — standalone SVG for embedding in",
        "  markdown / docs / slides (renders inline on GitHub).",
        "",
    ]
    for d in DIAGRAMS:
        lines.append(f"## {d.title}")
        lines.append("")
        lines.append(f"_{d.subtitle}_")
        lines.append("")
        lines.append(f"![{d.title}]({d.slug}.svg)")
        lines.append("")
        lines.append(f"Open the interactive version: [`{d.slug}.html`]({d.slug}.html).")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Regenerate with `make diagrams` (or `uv run python scripts/render_diagrams.py`).")
    index.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
