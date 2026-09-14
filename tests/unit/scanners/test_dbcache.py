import json
from pathlib import Path

from sureshot.engine.scanners.trivy.dbcache import check_db


def test_missing_cache_reports_absent(tmp_path: Path):
    status = check_db(cache_dir=tmp_path / "nope")
    assert status.present is False
    assert status.stale is True


def test_fresh_db_is_not_stale(tmp_path: Path):
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "metadata.json").write_text(json.dumps({
        "UpdatedAt": "2026-01-01T00:00:00Z",
        "NextUpdate": "2099-01-01T00:00:00Z",
    }))
    status = check_db(cache_dir=tmp_path)
    assert status.present is True
    assert status.stale is False


def test_overdue_db_is_stale(tmp_path: Path):
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "metadata.json").write_text(json.dumps({
        "UpdatedAt": "2000-01-01T00:00:00Z",
        "NextUpdate": "2000-01-02T00:00:00Z",
    }))
    status = check_db(cache_dir=tmp_path)
    assert status.stale is True


def test_malformed_metadata_is_treated_as_stale(tmp_path: Path):
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "metadata.json").write_text("not json")
    status = check_db(cache_dir=tmp_path)
    assert status.present is True
    assert status.stale is True
