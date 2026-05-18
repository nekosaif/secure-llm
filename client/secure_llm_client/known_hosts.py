"""SSH-style host-pubkey pinning. TOFU + manual edits.

File format (TOML)::

    [[hosts]]
    host = "llm.example.com:8443"
    x25519_pk = "<base64>"
    added_at = 1734567890
    note = "production"
    # v2.0: optional TEE measurement pinning.
    measurement = "sha384-of-sealed-image"
    attestation_required = true

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
    measurement: str | None = None
    attestation_required: bool = False


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
            measurement=entry.get("measurement"),
            attestation_required=bool(entry.get("attestation_required", False)),
        )
    return out


def lookup(path: Path, host: str) -> HostEntry | None:
    return load(path).get(host)


def trust(
    path: Path,
    host: str,
    pubkey: bytes,
    note: str = "",
    *,
    measurement: str | None = None,
    attestation_required: bool = False,
) -> None:
    if tomli_w is None:  # pragma: no cover
        raise RuntimeError("install tomli-w to write known_hosts")
    existing = load(path)
    existing[host] = HostEntry(
        host=host,
        x25519_pk=pubkey,
        measurement=measurement,
        attestation_required=attestation_required,
    )
    rows: list[dict[str, object]] = []
    for e in existing.values():
        row: dict[str, object] = {
            "host": e.host,
            "x25519_pk": base64.b64encode(e.x25519_pk).decode("ascii"),
            "added_at": int(time.time()),
            "note": note if e.host == host else "",
        }
        if e.measurement is not None:
            row["measurement"] = e.measurement
        if e.attestation_required:
            row["attestation_required"] = True
        rows.append(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(tomli_w.dumps({"hosts": rows}).encode("utf-8"))
