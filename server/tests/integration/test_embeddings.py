"""Embeddings endpoint over the encrypted envelope, in-process FastAPI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.transport import Transport
from secure_llm_protocol.schemas import EmbeddingsResponse
from secure_llm_server.crypto.keystore import (
    AuthorizedClient,
    Keystore,
    init_server_identity,
)
from secure_llm_server.routers.embeddings import router as embeddings_router
from secure_llm_server.routers.session import router as session_router
from secure_llm_server.session.manager import SessionManager


class _StubModels:
    async def embed(self, *, model_id: str, inputs: list[str], tenant: str = "default") -> Any:
        # Deterministic 4-d "embedding" derived from string length.
        return {
            "data": [
                {"index": i, "embedding": [float(len(s)), 0.5, -0.5, float(i)]}
                for i, s in enumerate(inputs)
            ],
            "usage": {"prompt_tokens": sum(len(s) for s in inputs)},
        }


def _build_app(tmp_path: Path) -> tuple[FastAPI, Keystore, Path]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_dir.chmod(0o700)
    server_id = init_server_identity(key_dir)
    client_id = ClientIdentity.generate_and_save(tmp_path / "client")
    keystore = Keystore(
        server=server_id,
        allowlist={
            client_id.x25519_pk: AuthorizedClient(
                name="t",
                x25519_pk=client_id.x25519_pk,
                ed25519_pk=client_id.ed25519_pk,
                scopes=("chat",),
            )
        },
    )
    sm = SessionManager(ttl_seconds=3600, max_lifetime_seconds=86400)

    app = FastAPI()
    app.state.keystore = keystore
    app.state.session_manager = sm
    app.state.models = _StubModels()
    app.state.settings = type(
        "S",
        (),
        {
            "crypto": type(
                "C",
                (),
                {
                    "handshake_skew_seconds": 30,
                    "session_ttl_seconds": 3600,
                },
            )()
        },
    )()
    app.include_router(session_router)
    app.include_router(embeddings_router)
    return app, keystore, tmp_path / "client"


def test_embeddings_roundtrip(tmp_path: Path):
    app, keystore, client_key_base = _build_app(tmp_path)
    base = "http://testserver"
    http = TestClient(app, base_url=base)
    identity = ClientIdentity.load(client_key_base)
    t = Transport(
        base_url=base,
        identity=identity,
        pinned_server_pk=keystore.server.x25519_pk,
        verify=False,
    )
    t._client = http  # type: ignore[attr-defined]

    data = t.request(
        "POST",
        "/v1/embeddings",
        payload={"model": "stub", "input": ["hello", "embeddings world!"]},
    )
    resp = EmbeddingsResponse.model_validate(data)
    assert resp.model == "stub"
    assert [d.index for d in resp.data] == [0, 1]
    assert resp.data[0].embedding == [5.0, 0.5, -0.5, 0.0]  # len("hello")
    assert resp.data[1].embedding == [17.0, 0.5, -0.5, 1.0]  # len("embeddings world!")
    assert resp.usage.prompt_tokens == 5 + 17
