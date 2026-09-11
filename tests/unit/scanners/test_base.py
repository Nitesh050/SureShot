from datetime import UTC, datetime
from pathlib import Path

import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.base import ScanRequest, ScanOutcome, Scanner


class FakeScanner:
    name = "fake"
    domains = (Domain.SAST,)

    def version(self) -> ToolRecord:
        return ToolRecord(name="fake", version="1.0.0")

    def scan(self, request: ScanRequest) -> ScanOutcome:
        finding = SecurityFinding(
            tool="fake",
            tool_version="1.0.0",
            rule_id="fake.rule",
            domain=Domain.SAST,
            title="Test finding",
            severity=Severity.HIGH,
            location=Location(file_path="a.py", line_start=1, line_end=1),
        )
        return ScanOutcome(findings=(finding,), tool=self.version(), duration_ms=1)


def test_fake_scanner_satisfies_protocol():
    assert isinstance(FakeScanner(), Scanner)


def test_scan_request_rejects_relative_source(tmp_path: Path):
    with pytest.raises(ValueError):
        ScanRequest(source=Path("relative/path"), output=tmp_path)


def test_outcome_degraded_when_partial(tmp_path: Path):
    outcome = ScanOutcome(
        findings=(), tool=ToolRecord(name="f", version="1"),
        duration_ms=1, partial_reason="hit timeout",
    )
    assert outcome.degraded is True


def test_outcome_not_degraded_by_default():
    outcome = ScanOutcome(
        findings=(), tool=ToolRecord(name="f", version="1"), duration_ms=1
    )
    assert outcome.degraded is False


def test_scanner_produces_findings(tmp_path: Path):
    request = ScanRequest(source=tmp_path.resolve(), output=tmp_path.resolve())
    outcome = FakeScanner().scan(request)
    assert len(outcome.findings) == 1
    assert outcome.degraded is False