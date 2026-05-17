"""SSH-style host-pubkey pinning. TOFU + manual edits.

File format (TOML)::

    [[hosts]]
    host = "llm.example.com:8443"
    x25519_pk = "<base64>"
    added_at = 1734567890
    note = "production"

Mismatch is fatal — the SDK raises :class:`secure_llm_client.errors.ServerKeyMismatch`.
"""

from __future__ import annotations

import base64
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

try:  # python 3.11 has tomllib; tomli_w is third-party
    import tomli_w  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover — only used by write paths
    tomli_w = None


@dataclass(frozen=True, slots=True)
class HostEntry:
    host: str
    x25519_pk: bytes


def load(path: Path) -> dict[str, HostEntry]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    out: dict[str, HostEntry] = {}
    for entry in data.get("hosts", []):
        out[entry["host"]] = HostEntry(
            host=entry["host"],
            x25519_pk=base64.b64decode(entry["x25519_pk"]),
        )
    return out


def lookup(path: Path, host: str) -> HostEntry | None:
    return load(path).get(host)


def trust(path: Path, host: str, pubkey: bytes, note: str = "") -> None:
    if tomli_w is None:  # pragma: no cover
        raise RuntimeError("install tomli-w to write known_hosts")
    existing = load(path)
    existing[host] = HostEntry(host=host, x25519_pk=pubkey)
    data = {
        "hosts": [
            {
                "host": e.host,
                "x25519_pk": base64.b64encode(e.x25519_pk).decode("ascii"),
                "added_at": int(time.time()),
                "note": note if e.host == host else "",
            }
            for e in existing.values()
        ]
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(tomli_w.dumps(data).encode("utf-8"))
