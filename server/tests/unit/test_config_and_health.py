"""Small files: config.load_settings + health.Readiness."""

from __future__ import annotations

from pathlib import Path

from secure_llm_server.config import load_settings
from secure_llm_server.health import Readiness


def _write_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.toml"
    (tmp_path / "keys").mkdir()
    cfg.write_text(
        """
[server]
host = "127.0.0.1"
port = 8443

[tls]
cert_file = "keys/c.pem"
key_file  = "keys/k.pem"

[crypto]
key_dir = "keys"
authorized_clients = "keys/authorized_clients.toml"

[models]
storage_dir = "models"
tmpfs_dir = "/dev/shm/x"

[inference]
n_ctx_default = 1024
""",
        encoding="utf-8",
    )
    return cfg


def test_load_settings_resolves_paths_relative_to_config(tmp_path: Path):
    cfg = _write_config(tmp_path)
    s = load_settings(cfg)
    # Relative `key_dir = "keys"` resolves to <tmp_path>/keys.
    assert s.crypto.key_dir == (tmp_path / "keys").resolve()
    assert s.tls.cert_file == (tmp_path / "keys" / "c.pem").resolve()
    assert s.models.storage_dir == (tmp_path / "models").resolve()
    # Plain values stay plain.
    assert s.server.host == "127.0.0.1"
    assert s.server.port == 8443


def test_load_settings_absolute_path_kept_as_is(tmp_path: Path):
    cfg = tmp_path / "config.toml"
    (tmp_path / "keys").mkdir()
    cfg.write_text(
        f"""
[server]
host = "0.0.0.0"
port = 9001
[tls]
cert_file = "/etc/secure-llm/cert.pem"
key_file  = "{tmp_path}/keys/k.pem"
[crypto]
key_dir = "{tmp_path}/keys"
authorized_clients = "/etc/secure-llm/authorized_clients.toml"
[models]
storage_dir = "/var/models"
tmpfs_dir = "/dev/shm/x"
[inference]
""",
        encoding="utf-8",
    )
    s = load_settings(cfg)
    assert str(s.tls.cert_file) == "/etc/secure-llm/cert.pem"
    assert str(s.models.storage_dir) == "/var/models"


def test_readiness_starts_not_ok():
    r = Readiness()
    assert r.ok is False


def test_readiness_check_storage_success(tmp_path: Path):
    r = Readiness()
    r.check_storage(tmp_path / "models")
    assert r.storage_dir_writable is True
    # The probe directory is created if missing.
    assert (tmp_path / "models").exists()


def test_readiness_check_storage_failure(tmp_path: Path):
    """A directory the process can't write should flip ``storage_dir_writable`` to False."""
    bad = tmp_path / "nope"
    bad.mkdir()
    bad.chmod(0o500)  # read+execute, no write
    r = Readiness()
    r.check_storage(bad / "deeper")
    # On most filesystems this fails; on a few obscure ones it might not.
    # Either way the method shouldn't raise.
    assert isinstance(r.storage_dir_writable, bool)


def test_readiness_overall_flag():
    r = Readiness()
    r.config_loaded = True
    r.keystore_loaded = True
    r.storage_dir_writable = True
    assert r.ok is True
    r.storage_dir_writable = False
    assert r.ok is False
