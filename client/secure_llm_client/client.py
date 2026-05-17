"""Main client surface. Designed to be drop-in-similar to the OpenAI SDK."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import ServerKeyMismatch
from secure_llm_client.known_hosts import lookup
from secure_llm_client.resources.admin import AdminResource
from secure_llm_client.resources.chat import ChatResource
from secure_llm_client.resources.completions import CompletionsResource
from secure_llm_client.resources.debug import DebugResource
from secure_llm_client.resources.models import ModelsResource
from secure_llm_client.resources.system import SystemResource
from secure_llm_client.transport import Transport


class SecureLLMClient:
    """End-to-end-encrypted LLM client.

    Parameters
    ----------
    base_url
        ``https://host:port`` of the server.
    client_key_path
        Base path of the client keypair (sans ``.x25519.key`` / ``.ed25519.key``).
    server_pubkey
        Pinned X25519 public key of the server (32 raw bytes). If omitted,
        looked up in ``known_hosts_path`` by base_url host:port.
    known_hosts_path
        TOML file storing trusted server pubkeys.
    insecure_skip_tls_verify
        Dev only — accept self-signed TLS certs.
    """

    def __init__(
        self,
        *,
        base_url: str,
        client_key_path: str | os.PathLike[str],
        server_pubkey: bytes | None = None,
        known_hosts_path: str | os.PathLike[str] | None = None,
        timeout: Any | None = None,
        insecure_skip_tls_verify: bool = False,
    ) -> None:
        identity = ClientIdentity.load(Path(client_key_path))

        pinned = server_pubkey
        if pinned is None:
            if known_hosts_path is None:
                raise ServerKeyMismatch(
                    "no pinned server_pubkey and no known_hosts_path; "
                    "use `sllm trust <host> <pubkey>` first"
                )
            host = base_url.split("://", 1)[-1]
            entry = lookup(Path(known_hosts_path), host)
            if entry is None:
                raise ServerKeyMismatch(f"host {host!r} not in {known_hosts_path}; trust it first")
            pinned = entry.x25519_pk

        self._transport = Transport(
            base_url=base_url,
            identity=identity,
            pinned_server_pk=pinned,
            timeout=timeout,
            verify=not insecure_skip_tls_verify,
        )

        self.models = ModelsResource(self._transport)
        self.chat = ChatResource(self._transport)
        self.completions = CompletionsResource(self._transport)
        self.system = SystemResource(self._transport)
        self.debug = DebugResource(self._transport)
        self.admin = AdminResource(self._transport)

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> SecureLLMClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
