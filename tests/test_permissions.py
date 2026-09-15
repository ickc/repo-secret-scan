from __future__ import annotations

import stat
from pathlib import Path

from repo_secret_scan.pipeline import is_shared, lock_down, private_dir


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_private_dir_creates_owner_only_parents(tmp_path: Path):
    target = private_dir(tmp_path / "a" / "b")
    assert _mode(target) == 0o700
    assert _mode(tmp_path / "a") == 0o700


def test_lock_down_tightens_existing_directory(tmp_path: Path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    scratch.chmod(0o755)
    assert is_shared(scratch)
    assert lock_down(scratch) is True
    assert _mode(scratch) == 0o700
    assert lock_down(scratch) is False  # idempotent


def test_lock_down_creates_missing_directory(tmp_path: Path):
    scratch = tmp_path / "new" / "scratch"
    assert lock_down(scratch) is False
    assert _mode(scratch) == 0o700
