"""Client-side mirror of the server's crypto primitives.

Same algorithms, same wire format. Lives in its own package so the client can
ship without server dependencies (no FastAPI, no llama.cpp).
"""

from secure_llm_client.crypto.envelope import (
    DirectionKeys,
    EnvelopeAuthError,
    open_envelope,
    seal,
)
from secure_llm_client.crypto.handshake import (
    ClientIdentity,
    HandshakeOutcome,
    build_handshake_request,
    derive_session,
)

__all__ = [
    "ClientIdentity",
    "DirectionKeys",
    "EnvelopeAuthError",
    "HandshakeOutcome",
    "build_handshake_request",
    "derive_session",
    "open_envelope",
    "seal",
]
