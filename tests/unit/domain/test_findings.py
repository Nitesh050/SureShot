import pytest
from pydantic import ValidationError

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding


def _sast(**overrides) -> dict:
    base = dict(
        tool="semgrep",
        tool_version="1.90.0",
        rule_id="python.lang.security.sqli",
        domain=Domain.SAST,
        title="SQL injection",
        severity=Severity.HIGH,
        cwe_ids=("CWE-89",),
        location=Location(file_path="backend/users.py", line_start=42, line_end=42),
    )
    return base | overrides


def test_valid_sast_finding():
    finding = _sast()
    assert SecurityFinding(**finding).severity.rank == 3


def test_absolute_path_rejected():
    with pytest.raises(ValidationError):
        Location(file_path="/tmp/aegis-x7f2/repo/users.py", line_start=1, line_end=1)


def test_parent_traversal_rejected():
    with pytest.raises(ValidationError):
        Location(file_path="../../etc/passwd", line_start=1, line_end=1)


def test_findings_are_immutable():
    finding = SecurityFinding(**_sast())
    with pytest.raises(ValidationError):
        finding.severity = Severity.LOW


def test_secret_finding_may_not_retain_raw_output():
    with pytest.raises(ValidationError):
        SecurityFinding(
            **_sast(
                domain=Domain.SECRET,
                raw={"Match": "AKIAIOSFODNN7EXAMPLE"},
            )
        )


def test_sca_finding_requires_package():
    with pytest.raises(ValidationError):
        SecurityFinding(**_sast(domain=Domain.SCA))


def test_malformed_cwe_rejected():
    with pytest.raises(ValidationError):
        SecurityFinding(**_sast(cwe_ids=("89",)))