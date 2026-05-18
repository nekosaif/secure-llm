"""ModelRegistry, LoraRegistry, and the MultiTenant factories."""

from __future__ import annotations

from pathlib import Path

from secure_llm_server.models.registry import (
    DEFAULT_TENANT,
    LoraEntry,
    LoraRegistry,
    ModelEntry,
    ModelRegistry,
    MultiTenantLoraRegistry,
    MultiTenantRegistry,
    normalize_id,
    read_lora_meta,
    read_meta,
    sha256_file,
    tenant_subdir,
    write_lora_meta,
    write_meta,
)


def _model_entry(model_id: str = "stub") -> ModelEntry:
    return ModelEntry(
        id=model_id,
        sha256_plaintext="ab" * 32,
        repo_id="r/" + model_id,
        filename=model_id + ".gguf",
        bytes_plaintext=10,
        bytes_ciphertext=20,
        n_ctx_max=4096,
    )


def _lora_entry(lora_id: str = "adapter") -> LoraEntry:
    return LoraEntry(
        id=lora_id,
        sha256_plaintext="cd" * 32,
        repo_id="r/" + lora_id,
        filename=lora_id + ".lora.gguf",
        bytes_plaintext=5,
        bytes_ciphertext=8,
        base_model_id="base",
    )


def test_normalize_id():
    assert normalize_id("foo bar.gguf") == "foo_bar"
    assert normalize_id("/dir/Mistral-7B.Q4_K_M.gguf") == "Mistral-7B.Q4_K_M"


def test_sha256_file(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello")
    # known SHA-256 of "hello"
    assert sha256_file(p) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_tenant_subdir():
    base = Path("/data/models")
    assert tenant_subdir(base, DEFAULT_TENANT) == base
    assert tenant_subdir(base, "alpha") == base / "tenants" / "alpha"


def test_model_meta_roundtrip(tmp_path: Path):
    e = _model_entry()
    write_meta(tmp_path, e)
    back = read_meta(tmp_path / e.meta_path)
    assert back.id == e.id
    assert back.sha256_plaintext == e.sha256_plaintext
    assert back.bytes_ciphertext == e.bytes_ciphertext


def test_lora_meta_roundtrip(tmp_path: Path):
    e = _lora_entry()
    write_lora_meta(tmp_path, e)
    back = read_lora_meta(tmp_path / e.meta_path)
    assert back.id == e.id
    assert back.base_model_id == "base"


def test_model_registry_add_get_remove(tmp_path: Path):
    reg = ModelRegistry(tmp_path)
    assert reg.all() == []
    assert reg.get("nope") is None
    e = _model_entry()
    reg.add(e)
    assert reg.get(e.id) is not None
    assert [x.id for x in reg.all()] == [e.id]
    # The ciphertext file is referenced relative to storage_dir; create it
    # so remove() actually deletes something (also covers FileNotFoundError
    # branch when not present).
    (tmp_path / e.ciphertext_path).write_bytes(b"sealed")
    assert reg.remove(e.id) is True
    assert reg.get(e.id) is None
    # second remove returns False
    assert reg.remove(e.id) is False


def test_model_registry_reload_skips_corrupt(tmp_path: Path):
    # A real entry + a corrupt sidecar — the corrupt one is skipped.
    good = _model_entry("good")
    write_meta(tmp_path, good)
    (tmp_path / "999.meta.json").write_text("not-json", encoding="utf-8")
    reg = ModelRegistry(tmp_path)
    assert [e.id for e in reg.all()] == ["good"]


def test_model_registry_remove_when_ciphertext_missing(tmp_path: Path):
    reg = ModelRegistry(tmp_path)
    e = _model_entry()
    reg.add(e)
    # Don't create the ciphertext file — remove() handles FileNotFoundError.
    assert reg.remove(e.id) is True


def test_lora_registry_add_get_remove(tmp_path: Path):
    reg = LoraRegistry(tmp_path)
    e = _lora_entry()
    reg.add(e)
    assert reg.get(e.id) == e
    (tmp_path / e.ciphertext_path).write_bytes(b"sealed")
    assert reg.remove(e.id) is True
    assert reg.remove(e.id) is False


def test_lora_registry_reload_skips_corrupt(tmp_path: Path):
    write_lora_meta(tmp_path, _lora_entry("good"))
    (tmp_path / "999.lora.meta.json").write_text("not-json", encoding="utf-8")
    reg = LoraRegistry(tmp_path)
    assert [e.id for e in reg.all()] == ["good"]


def test_multitenant_registry_per_tenant_isolation(tmp_path: Path):
    base = tmp_path / "models"
    mt = MultiTenantRegistry(base)
    # Same tenant call returns same instance.
    assert mt.for_tenant("alpha") is mt.for_tenant("alpha")
    # Default tenant lives at the root.
    assert mt.for_tenant(DEFAULT_TENANT).storage_dir == base
    # Named tenants under tenants/<name>/.
    alpha = mt.for_tenant("alpha")
    assert alpha.storage_dir == base / "tenants" / "alpha"
    # An entry in alpha doesn't leak to beta.
    alpha.add(_model_entry("only-in-alpha"))
    beta = mt.for_tenant("beta")
    assert beta.get("only-in-alpha") is None


def test_multitenant_registry_known_tenants(tmp_path: Path):
    base = tmp_path / "models"
    mt = MultiTenantRegistry(base)
    # Nothing yet.
    assert mt.known_tenants() == []
    # Add a default-tenant entry.
    mt.for_tenant(DEFAULT_TENANT).add(_model_entry("d"))
    assert DEFAULT_TENANT in mt.known_tenants()
    # Add a named tenant.
    mt.for_tenant("beta").add(_model_entry("b"))
    assert {DEFAULT_TENANT, "beta"} <= set(mt.known_tenants())


def test_multitenant_lora_factory(tmp_path: Path):
    mt = MultiTenantLoraRegistry(tmp_path)
    a = mt.for_tenant("a")
    b = mt.for_tenant("b")
    assert a is not b
    assert mt.for_tenant("a") is a
    a.add(_lora_entry("only-a"))
    assert b.get("only-a") is None
