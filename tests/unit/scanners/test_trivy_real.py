import shutil
from pathlib import Path

import pytest

from sureshot.engine.scanners.base import ScanRequest
from sureshot.engine.scanners.trivy.scanner import TrivyScanner

pytestmark = pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy not installed")


def test_version_is_reported():
    record = TrivyScanner().version()
    assert record.name == "trivy"
    assert record.version[0].isdigit()


def test_real_scan_finds_vulnerable_dependency(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")

    outcome = TrivyScanner().scan(
        ScanRequest(source=tmp_path.resolve(), output=tmp_path.resolve(), timeout_seconds=120)
    )
    assert not outcome.degraded
    assert len(outcome.findings) > 0
    assert all(f.domain.value == "sca" for f in outcome.findings)


def test_real_scan_finds_secret(tmp_path: Path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAZZZZZZZZZZZZZZZZ"\n')

    outcome = TrivyScanner().scan(
        ScanRequest(source=tmp_path.resolve(), output=tmp_path.resolve(), timeout_seconds=120)
    )
    assert not outcome.degraded
    assert any(f.domain.value == "secret" for f in outcome.findings)
