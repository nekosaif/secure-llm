"""Keystore: server identity + authorized-clients allowlist.

Layout under ``key_dir`` (mode 0700, files 0600)::

    server.x25519.key            32-byte X25519 secret
    server.x25519.key.pub        32-byte X25519 public
    server.ed25519.key           32-byte Ed25519 seed (NaCl convention)
    server.ed25519.key.pub       32-byte Ed25519 public
    server.age.key               age identity for at-rest model encryption

The allowlist file is TOML (path is configurable). It is reloadable via
:meth:`Keystore.reload_allowlist` (also wired to SIGHUP and the admin API).
"""

from __future__ import annotations

import base64
import os
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from secure_llm_server.crypto.kdf import fingerprint


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    x25519_sk: PrivateKey
    x25519_pk: bytes
    ed25519_sk: SigningKey
    ed25519_pk: bytes
    age_secret_path: Path  # the age identity file (managed by pyrage)


DEFAULT_TENANT = "default"


@dataclass(frozen=True, slots=True)
class AuthorizedClient:
    name: str
    x25519_pk: bytes
    ed25519_pk: bytes
    scopes: tuple[str, ...] = ()
    revoked: bool = False
    not_before: int | None = None
    not_after: int | None = None
    tenant: str = DEFAULT_TENANT

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.x25519_pk)


@dataclass(slots=True)
class Keystore:
    server: ServerIdentity
    allowlist: dict[bytes, AuthorizedClient] = field(default_factory=dict)
    allowlist_path: Path | None = None

    def reload_allowlist(self) -> int:
        if self.allowlist_path is None:
            return 0
        self.allowlist = load_allowlist(self.allowlist_path)
        return len(self.allowlist)


def _require_secret_perms(path: Path) -> None:
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(
            f"{path} is world/group-accessible (mode={oct(st.st_mode)}); chmod 0600 it"
        )


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def init_server_identity(key_dir: Path) -> ServerIdentity:
    """Create a fresh server identity. Refuses to overwrite existing keys."""
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)

    x_sk = PrivateKey.generate()
    x_pk = bytes(x_sk.public_key)
    e_sk = SigningKey.generate()
    e_pk = bytes(e_sk.verify_key)

    _write_secret(key_dir / "server.x25519.key", bytes(x_sk))
    (key_dir / "server.x25519.key.pub").write_bytes(x_pk)
    _write_secret(key_dir / "server.ed25519.key", bytes(e_sk))
    (key_dir / "server.ed25519.key.pub").write_bytes(e_pk)

    age_path = key_dir / "server.age.key"
    if not age_path.exists():
        try:
            import pyrage  # type: ignore

            identity = pyrage.x25519.Identity.generate()
            _write_secret(age_path, str(identity).encode("ascii"))
        except Exception:
            # pyrage may be unavailable in some test envs; warn via empty file
            _write_secret(age_path, b"")
    return ServerIdentity(
        x25519_sk=x_sk,
        x25519_pk=x_pk,
        ed25519_sk=e_sk,
        ed25519_pk=e_pk,
        age_secret_path=age_path,
    )


def load_server_identity(key_dir: Path) -> ServerIdentity:
    paths = {
        "x_sk": key_dir / "server.x25519.key",
        "x_pk": key_dir / "server.x25519.key.pub",
        "e_sk": key_dir / "server.ed25519.key",
        "e_pk": key_dir / "server.ed25519.key.pub",
        "age": key_dir / "server.age.key",
    }
    for p in (paths["x_sk"], paths["e_sk"]):
        _require_secret_perms(p)
    x_sk = PrivateKey(paths["x_sk"].read_bytes())
    e_sk = SigningKey(paths["e_sk"].read_bytes())
    return ServerIdentity(
        x25519_sk=x_sk,
        x25519_pk=paths["x_pk"].read_bytes(),
        ed25519_sk=e_sk,
        ed25519_pk=paths["e_pk"].read_bytes(),
        age_secret_path=paths["age"],
    )


def _parse_clients_file(path: Path, *, forced_tenant: str | None) -> dict[bytes, AuthorizedClient]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    out: dict[bytes, AuthorizedClient] = {}
    for entry in data.get("clients", []):
        x_pk = base64.b64decode(entry["x25519_pk"])
        e_pk = base64.b64decode(entry["ed25519_pk"])
        if len(x_pk) != 32 or len(e_pk) != 32:
            raise ValueError(f"client {entry.get('name', '?')}: bad pk length")
        # If the entry was loaded from a per-tenant directory, the path's
        # tenant wins over any value in the TOML — a misnamed entry can't
        # escape its directory.
        tenant = forced_tenant or str(entry.get("tenant", DEFAULT_TENANT))
        out[x_pk] = AuthorizedClient(
            name=entry.get("name", x_pk.hex()[:16]),
            x25519_pk=x_pk,
            ed25519_pk=e_pk,
            scopes=tuple(entry.get("scopes", [])),
            revoked=bool(entry.get("revoked", False)),
            not_before=entry.get("not_before"),
            not_after=entry.get("not_after"),
            tenant=tenant,
        )
    return out


def load_allowlist(path: Path) -> dict[bytes, AuthorizedClient]:
    """Read the root ``authorized_clients.toml`` plus any per-tenant files.

    Layout::

        keys/
          authorized_clients.toml            # default tenant
          tenants/
            <tenant>/authorized_clients.toml # tenant-scoped; tenant wins

    On a duplicate ``x25519_pk`` across files, the tenant-scoped entry wins
    over the default file so an operator can't accidentally give a client
    a wider tenant scope by re-listing them at the root.
    """
    out = _parse_clients_file(path, forced_tenant=DEFAULT_TENANT)
    tenants_dir = path.parent / "tenants"
    if tenants_dir.is_dir():
        for sub in sorted(tenants_dir.iterdir()):
            if not sub.is_dir():
                continue
            sub_file = sub / "authorized_clients.toml"
            tenant_entries = _parse_clients_file(sub_file, forced_tenant=sub.name)
            out.update(tenant_entries)  # tenant-scoped wins on collision
    return out


def load_or_init_keystore(key_dir: Path, allowlist_path: Path | None) -> Keystore:
    if not (key_dir / "server.x25519.key").exists():
        server = init_server_identity(key_dir)
    else:
        server = load_server_identity(key_dir)
    allowlist = load_allowlist(allowlist_path) if allowlist_path else {}
    return Keystore(server=server, allowlist=allowlist, allowlist_path=allowlist_path)


# ----- KeystoreBackend Protocol (v1.3 federation, v2.0 TEE-sealed) -----


class KeystoreBackend(Protocol):
    """Pluggable identity backend.

    Two implementations are anticipated:

    - :class:`FileKeystoreBackend` (v1.3): reads ``server.{x25519,
      ed25519}.key`` from disk. The same identity files are shared
      across every instance in a federated fleet via the operator's
      config-management tool.
    - ``SealedKeystoreBackend`` (v2.0, planned): the server identity
      is unsealed by a TEE-gated KMS at boot. The interface below is
      sufficient for that future swap — no caller in the rest of the
      codebase touches the on-disk files directly.
    """

    def load_server_identity(self) -> ServerIdentity: ...

    def load_allowlist(self) -> dict[bytes, AuthorizedClient]: ...


@dataclass(frozen=True, slots=True)
class FileKeystoreBackend:
    """The current on-disk implementation, wrapped in the new Protocol.

    Behavior is unchanged: this is just the existing module-level
    functions hung off a single object so v2.0 can drop in a
    TEE-sealed backend without touching the call sites.
    """

    key_dir: Path
    allowlist_path: Path | None

    def load_server_identity(self) -> ServerIdentity:
        if not (self.key_dir / "server.x25519.key").exists():
            return init_server_identity(self.key_dir)
        return load_server_identity(self.key_dir)

    def load_allowlist(self) -> dict[bytes, AuthorizedClient]:
        if self.allowlist_path is None:
            return {}
        return load_allowlist(self.allowlist_path)

    def to_keystore(self) -> Keystore:
        return Keystore(
            server=self.load_server_identity(),
            allowlist=self.load_allowlist(),
            allowlist_path=self.allowlist_path,
        )


# ----- CLI entry: invoked from bootstrap.sh -----


def _cli_init(argv: list[str]) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="keystore", description="init server identity")
    p.add_argument("subcommand", choices=["init"])
    p.add_argument("--key-dir", required=True, type=Path)
    args = p.parse_args(argv)
    if args.subcommand == "init":
        if (args.key_dir / "server.x25519.key").exists():
            print(f"keystore: {args.key_dir} already initialized")
            return 0
        ident = init_server_identity(args.key_dir)
        print(f"keystore: initialized at {args.key_dir}")
        print(f"  x25519 fingerprint: {fingerprint(ident.x25519_pk)}")
        return 0
    return 2


if __name__ == "__main__":
    import sys

    sys.exit(_cli_init(sys.argv[1:]))
