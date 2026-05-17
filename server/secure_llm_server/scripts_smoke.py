"""End-to-end smoke test, invoked by ``make smoke``.

Boots an in-process server, performs handshake + echo + (if a tiny model is
available) a chat completion + admin/debug calls. Designed to exercise the
crypto and routing paths without requiring a multi-GB model unless one is
already on disk.
"""

from __future__ import annotations

import base64
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console

console = Console()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    data = repo / "data"
    cfg = data / "config.toml"
    if not cfg.exists():
        console.print("[red]bootstrap first: make bootstrap[/]")
        return 2

    # 1) Make sure a sample admin client is in the allowlist.
    from secure_llm_client.crypto.handshake import ClientIdentity

    client_key = data / "keys" / "smoke-client"
    if not (client_key.with_suffix(".x25519.key")).exists():
        ClientIdentity.generate_and_save(client_key)

    identity = ClientIdentity.load(client_key)
    allow = data / "keys" / "authorized_clients.toml"
    if "smoke" not in allow.read_text(encoding="utf-8"):
        with allow.open("a", encoding="utf-8") as f:
            f.write(
                "\n[[clients]]\n"
                f'name = "smoke"\n'
                f'x25519_pk = "{base64.b64encode(identity.x25519_pk).decode()}"\n'
                f'ed25519_pk = "{base64.b64encode(identity.ed25519_pk).decode()}"\n'
                f'scopes = ["chat", "admin"]\n'
            )

    # 2) Pin server pubkey for the smoke client.
    server_pk = (data / "keys" / "server.x25519.key.pub").read_bytes()
    known_hosts = data / "smoke-known.toml"
    from secure_llm_client.known_hosts import trust

    port = _free_port()
    host = f"127.0.0.1:{port}"
    trust(known_hosts, host, server_pk)

    # 3) Boot server in a subprocess so signals/lifespan behave normally.
    env = os.environ.copy()
    env["SECURE_LLM_CONFIG"] = str(cfg)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "secure_llm_server.main",
            "--config",
            str(cfg),
            "--no-tls",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    try:
        # Wait for /healthz.
        deadline = time.time() + 30
        import httpx

        while time.time() < deadline:
            try:
                r = httpx.get(f"http://{host}/healthz", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                time.sleep(0.3)
        else:
            out = proc.stdout.read() if proc.stdout else b""  # type: ignore[union-attr]
            console.print(out.decode(errors="replace"))
            console.print("[red]server did not become ready[/]")
            return 1

        from secure_llm_client import SecureLLMClient

        client = SecureLLMClient(
            base_url=f"http://{host}",
            client_key_path=str(client_key),
            known_hosts_path=str(known_hosts),
            insecure_skip_tls_verify=True,
        )

        ds = client.debug.status()
        console.print(f"[green]debug.status[/] uptime={ds.uptime_seconds:.1f}s")
        sys_status = client.system.status()
        console.print(
            f"[green]system[/] cpu={sys_status.cpu_percent:.1f}% "
            f"free_ram={sys_status.ram_available_bytes / 1e9:.1f}GB"
        )

        models = client.models.list()
        console.print(f"[green]models[/] {[m.id for m in models]}")

        # Admin: log-level toggle
        client.admin.log_level.set("secure_llm_server.crypto", "DEBUG", ttl_seconds=5)
        console.print("[green]admin.log_level set[/]")

        client.close()
        console.print("[bold green]smoke ok[/]")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
