"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_keys(tmp_path: Path) -> Path:
    d = tmp_path / "keys"
    d.mkdir()
    d.chmod(0o700)
    return d
