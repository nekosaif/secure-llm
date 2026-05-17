"""sllm — secure-llm CLI."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from secure_llm_client import SecureLLMClient
from secure_llm_client.crypto.handshake import ClientIdentity
from secure_llm_client.errors import SecureLLMError
from secure_llm_client.known_hosts import trust

app = typer.Typer(help="secure-llm command-line client", no_args_is_help=True)
console = Console()

models_app = typer.Typer(help="model management")
debug_app = typer.Typer(help="debug introspection")
admin_app = typer.Typer(help="admin / control plane (requires admin scope)")
admin_models_app = typer.Typer(help="admin model controls")
admin_sessions_app = typer.Typer(help="admin session controls")
admin_log_app = typer.Typer(help="admin log-level controls")
app.add_typer(models_app, name="models")
app.add_typer(debug_app, name="debug")
app.add_typer(admin_app, name="admin")
admin_app.add_typer(admin_models_app, name="models")
admin_app.add_typer(admin_sessions_app, name="sessions")
admin_app.add_typer(admin_log_app, name="log-level")


def _config_dir() -> Path:
    return Path(os.environ.get("SECURE_LLM_HOME", str(Path.home() / ".secure-llm")))


def _client(base_url: str, *, insecure: bool) -> SecureLLMClient:
    home = _config_dir()
    key_base = home / "client"
    if not (key_base.with_suffix(".x25519.key")).exists():
        console.print("[red]no client identity[/] — run `sllm keygen` first")
        raise typer.Exit(2)
    return SecureLLMClient(
        base_url=base_url,
        client_key_path=str(key_base),
        known_hosts_path=str(home / "known_servers.toml"),
        insecure_skip_tls_verify=insecure,
    )


# ---------------- top-level ----------------


@app.command()
def keygen(
    out: Path = typer.Option(None, help="base path (default: ~/.secure-llm/client)"),
) -> None:
    """Generate a fresh client identity (X25519 + Ed25519)."""
    base = out or (_config_dir() / "client")
    ident = ClientIdentity.generate_and_save(base)
    console.print(
        f"keys written under [bold]{base}[/]\n"
        f"  x25519 pk (base64): [cyan]{base64.b64encode(ident.x25519_pk).decode()}[/]\n"
        f"  ed25519 pk (base64): [cyan]{base64.b64encode(ident.ed25519_pk).decode()}[/]\n"
        f"\nAdd this to the server's authorized_clients.toml:\n"
        f"  [[clients]]\n"
        f'  name = "me"\n'
        f'  x25519_pk = "{base64.b64encode(ident.x25519_pk).decode()}"\n'
        f'  ed25519_pk = "{base64.b64encode(ident.ed25519_pk).decode()}"\n'
        f'  scopes = ["chat"]'
    )


@app.command("trust")
def trust_cmd(
    host: str = typer.Argument(...),
    pubkey_b64: str = typer.Argument(..., help="server X25519 public key (base64)"),
) -> None:
    """Pin a server's public key (SSH-style TOFU)."""
    pk = base64.b64decode(pubkey_b64)
    if len(pk) != 32:
        console.print("[red]invalid pubkey length[/]")
        raise typer.Exit(2)
    path = _config_dir() / "known_servers.toml"
    trust(path, host, pk)
    console.print(f"trusted [bold]{host}[/] → {pubkey_b64}")


@app.command()
def chat(
    model: str = typer.Option(..., "--model", "-m"),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    system: str | None = typer.Option(None, "--system"),
    insecure: bool = typer.Option(False, "--insecure", help="skip TLS verification (dev)"),
) -> None:
    """Interactive chat REPL."""
    client = _client(base_url, insecure=insecure)
    conv = client.chat.conversation(model=model, system=system)
    console.print("[dim]Ctrl-D or /exit to quit, /clear to reset[/]\n")
    while True:
        try:
            line = typer.prompt(">>", default="", show_default=False)
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            continue
        if line.strip() in {"/exit", "/quit"}:
            break
        if line.strip() == "/clear":
            conv.clear()
            console.print("[dim]history cleared[/]")
            continue
        try:
            reply = conv.send(line)
        except SecureLLMError as e:
            console.print(f"[red]error[/] [yellow]{e.code.value}[/]: {e}")
            continue
        console.print(reply)


@app.command()
def complete(
    model: str = typer.Option(..., "--model", "-m"),
    prompt: str = typer.Option(..., "--prompt", "-p"),
    max_tokens: int = typer.Option(256, "--max-tokens"),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    resp = client.completions.create(model=model, prompt=prompt, max_tokens=max_tokens)
    console.print(resp.text)


@app.command()
def system(
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    """Show server system status."""
    client = _client(base_url, insecure=insecure)
    s = client.system.status()
    t = Table(title="server status")
    t.add_column("metric")
    t.add_column("value")
    t.add_row("cpu %", f"{s.cpu_percent:.1f}")
    t.add_row("ram total", f"{s.ram_total_bytes / 1e9:.1f} GB")
    t.add_row("ram free", f"{s.ram_available_bytes / 1e9:.1f} GB")
    t.add_row("disk free", f"{s.disk_free_bytes / 1e9:.1f} GB")
    t.add_row("loaded", ", ".join(s.loaded_models) or "-")
    t.add_row("uptime", f"{s.uptime_seconds:.0f} s")
    console.print(t)


# ---------------- models ----------------


@models_app.command("list")
def models_list(
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    t = Table(title="models")
    for col in ("id", "state", "size", "queue", "repo"):
        t.add_column(col)
    for m in client.models.list():
        t.add_row(
            m.id, m.state, f"{m.bytes_on_disk / 1e9:.2f} GB", str(m.queue_depth), m.repo_id or "-"
        )
    console.print(t)


@models_app.command("pull")
def models_pull(
    spec: str = typer.Argument(..., help="repo:filename"),
    sha256: str | None = typer.Option(None, "--sha256"),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    if ":" not in spec:
        console.print("[red]use repo:filename[/]")
        raise typer.Exit(2)
    repo, filename = spec.split(":", 1)
    client = _client(base_url, insecure=insecure)
    client.models.download(repo, filename=filename, sha256=sha256)
    console.print(f"[green]ok[/] pulled {repo}/{filename}")


@models_app.command("rm")
def models_rm(
    model_id: str = typer.Argument(...),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    client.models.remove(model_id)
    console.print(f"[green]ok[/] removed {model_id}")


# ---------------- debug ----------------


@debug_app.command("status")
def debug_status(
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    s = client.debug.status()
    console.print_json(s.model_dump_json(indent=2))


@debug_app.command("doctor")
def debug_doctor(
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    r = client.debug.doctor()
    console.print(f"[bold]overall:[/] {r.overall}")
    for s in r.steps:
        color = {"ok": "green", "warn": "yellow", "fail": "red"}.get(s.status, "white")
        console.print(f"  [{color}]{s.status:>4}[/] {s.name:<14} {s.detail}")


@debug_app.command("logs")
def debug_logs(
    level: str | None = typer.Option(None),
    limit: int = typer.Option(100),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    for e in client.debug.logs(level=level, limit=limit):
        console.print(f"{e['ts']:.3f}  {e['level']:<5}  {e['component']:<35}  {e['event']}")


@debug_app.command("errors")
def debug_errors(
    limit: int = typer.Option(20),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    for e in client.debug.errors(limit=limit):
        console.print(f"[red]{e['error_id']}[/] {e['code']} — {e['message']}")


# ---------------- admin ----------------


@admin_sessions_app.command("list")
def admin_sessions_list(
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    for s in client.admin.sessions.list():
        console.print(s)


@admin_models_app.command("preload")
def admin_models_preload(
    model_id: str = typer.Argument(...),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    client.admin.models.preload(model_id)
    console.print(f"[green]ok[/] preloaded {model_id}")


@admin_models_app.command("unload")
def admin_models_unload(
    model_id: str = typer.Argument(...),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    was = client.admin.models.unload(model_id)
    console.print(f"unloaded={was}")


@admin_log_app.command("set")
def admin_log_set(
    component: str = typer.Argument(...),
    level: str = typer.Argument(...),
    ttl: int | None = typer.Option(None, "--ttl"),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    client.admin.log_level.set(component, level, ttl_seconds=ttl)
    console.print(f"[green]ok[/] {component} → {level}")


@admin_app.command("shutdown")
def admin_shutdown(
    grace: int = typer.Option(30, "--grace"),
    base_url: str = typer.Option("https://127.0.0.1:8443", "--server", "-s"),
    insecure: bool = typer.Option(False, "--insecure"),
) -> None:
    client = _client(base_url, insecure=insecure)
    client.admin.shutdown(grace_seconds=grace)
    console.print(f"[yellow]shutdown requested ({grace}s grace)[/]")


def main() -> None:  # pragma: no cover
    try:
        app()
    except SecureLLMError as e:
        console.print(f"[red]error[/] [yellow]{e.code.value}[/]: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
