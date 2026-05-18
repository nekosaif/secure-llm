"""SecureLLMClient construction with explicit ``server_pubkey`` + close + context-manager."""

from __future__ import annotations

import secrets
from pathlib import Path

from secure_llm_client import SecureLLMClient
from secure_llm_client.crypto.handshake import ClientIdentity


def test_construct_with_pinned_pk_no_known_hosts(tmp_path: Path):
    """Passing ``server_pubkey`` directly avoids the known_hosts lookup branch."""
    ClientIdentity.generate_and_save(tmp_path / "client")
    client = SecureLLMClient(
        base_url="https://nope:1",
        client_key_path=str(tmp_path / "client"),
        server_pubkey=secrets.token_bytes(32),
        insecure_skip_tls_verify=True,
    )
    # We never call any endpoint — just exercise construction and the
    # close-via-context-manager path.
    with client as c:
        assert c.models is not None
        assert c.chat is not None
        assert c.embeddings is not None
        assert c.completions is not None
        assert c.system is not None
        assert c.debug is not None
        assert c.admin is not None


def test_close_is_idempotent(tmp_path: Path):
    ClientIdentity.generate_and_save(tmp_path / "client")
    c = SecureLLMClient(
        base_url="https://nope:1",
        client_key_path=str(tmp_path / "client"),
        server_pubkey=secrets.token_bytes(32),
        insecure_skip_tls_verify=True,
    )
    c.close()
    # A second close goes through Transport.close → reset_session early-return
    # (session is None) → close httpx client (already closed). Should not raise.
    c.close()
