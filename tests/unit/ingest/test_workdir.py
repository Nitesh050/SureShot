from pathlib import Path

import pytest

from sureshot.engine.ingest.workdir import Workdir


def test_creates_isolated_tree(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path) as wd:
        assert wd.root.is_dir()
        assert wd.source.is_dir()
        assert wd.output.is_dir()
        assert "sc_01" in wd.root.name


def test_removed_on_exit(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path) as wd:
        root = wd.root
        (wd.source / "a.py").write_text("x")
    assert not root.exists()


def test_removed_even_when_body_raises(tmp_path: Path):
    captured: list[Path] = []
    with pytest.raises(RuntimeError):
        with Workdir(scan_id="sc_01", base=tmp_path) as wd:
            captured.append(wd.root)
            raise RuntimeError("boom")
    assert not captured[0].exists()


def test_keep_preserves_tree_for_debugging(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path, keep=True) as wd:
        root = wd.root
    assert root.exists()


def test_relative_returns_repo_relative_path(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path) as wd:
        assert wd.relative(wd.source / "backend" / "users.py") == "backend/users.py"


def test_relative_rejects_paths_outside_source(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path) as wd:
        with pytest.raises(ValueError):
            wd.relative(tmp_path / "elsewhere.py")


def test_teardown_survives_readonly_directories(tmp_path: Path):
    with Workdir(scan_id="sc_01", base=tmp_path) as wd:
        root = wd.root
        locked = wd.source / "locked"
        locked.mkdir()
        (locked / "f.py").write_text("x")
        locked.chmod(0o500)
    assert not root.exists()