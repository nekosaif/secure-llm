"""Cryptographic primitives for the secure-llm server.

All long-lived secrets live in :mod:`.keystore`. Per-session derivation and the
mutual-auth handshake live in :mod:`.handshake`. Envelope AEAD wrap/unwrap is
in :mod:`.envelope`. At-rest encryption of model files is in :mod:`.at_rest`.

No module here imports anything from :mod:`secure_llm_server.routers` — the
crypto layer must remain usable in isolation (so it can be unit/property tested
without spinning up the HTTP stack).
"""
