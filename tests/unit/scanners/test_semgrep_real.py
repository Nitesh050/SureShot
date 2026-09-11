import shutil
from pathlib import Path

import pytest

from sureshot.domain.enums import Coverage, Domain
from sureshot.domain.repository import CoverageNote, LanguageStat, RepositoryProfile
from sureshot.engine.scanners.base import ScanRequest
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed"
)

VULNERABLE = '''\
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
'''


def _profile() -> RepositoryProfile:
    return RepositoryProfile(
        total_files=1, scanned_files=1, skipped_files=0, total_bytes=len(VULNERABLE),
        languages=(LanguageStat(name="Python", files=1, bytes=len(VULNERABLE)),),
        coverage=(CoverageNote(domain=Domain.SAST, coverage=Coverage.FULL, reason="ok"),),
    )


def test_version_is_reported():
    record = SemgrepScanner().version()
    assert record.name == "semgrep"
    assert record.version[0].isdigit()


def test_real_scan_finds_sql_injection(tmp_path: Path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "users.py").write_text(VULNERABLE)

    scanner = SemgrepScanner(profile=_profile())
    outcome = scanner.scan(
        ScanRequest(source=source.resolve(), output=output.resolve(), timeout_seconds=300)
    )
    assert outcome.tool.ruleset_hash is not None
    assert len(outcome.raw_results) > 0