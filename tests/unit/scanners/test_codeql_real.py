import shutil
from pathlib import Path

import pytest

from sureshot.domain.repository import LanguageStat, RepositoryProfile
from sureshot.engine.scanners.base import ScanRequest
from sureshot.engine.scanners.codeql.scanner import CodeQLScanner

pytestmark = pytest.mark.skipif(shutil.which("codeql") is None, reason="codeql not installed")

VULNERABLE = '''\
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
'''


def _profile() -> RepositoryProfile:
    return RepositoryProfile(
        total_files=1, scanned_files=1, skipped_files=0, total_bytes=len(VULNERABLE),
        languages=(LanguageStat(name="Python", files=1, bytes=len(VULNERABLE)),),
    )


def test_version_is_reported():
    record = CodeQLScanner().version()
    assert record.name == "codeql"
    assert record.version[0].isdigit()


def test_real_scan_finds_sql_injection(tmp_path: Path):
    """Requires the codeql/python-queries pack (`codeql pack download codeql/python-queries`)."""
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "app.py").write_text(VULNERABLE)

    scanner = CodeQLScanner(profile=_profile())
    outcome = scanner.scan(
        ScanRequest(source=source.resolve(), output=output.resolve(), timeout_seconds=300)
    )
    assert not outcome.degraded
    assert outcome.tool.ruleset_hash is not None
    assert any(f.rule_id == "py/sql-injection" for f in outcome.findings)
