from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, Package, SecurityFinding
from sureshot.domain.result import TriagedFinding
from sureshot.engine.normalize.dedupe import dedupe
from sureshot.engine.normalize.grouping import group_by_domain, group_by_file, group_by_severity


def _finding(issue_id, instance_id, path="app.py", line=1, domain=Domain.SAST, severity=Severity.HIGH) -> SecurityFinding:
    package = Package(name="flask", installed_version="1.0") if domain is Domain.SCA else None
    return SecurityFinding(
        instance_id=instance_id, issue_id=issue_id,
        tool="semgrep", tool_version="1.0", rule_id="r1",
        domain=domain, title="t", severity=severity, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=line, line_end=line),
        package=package,
    )


def _issues(*findings: SecurityFinding):
    return dedupe(tuple(TriagedFinding(finding=f, score=50.0) for f in findings))


def test_group_by_domain_separates_domains():
    issues = _issues(
        _finding("is_1", "in_1", domain=Domain.SAST),
        _finding("is_2", "in_2", domain=Domain.SCA),
    )
    groups = group_by_domain(issues)
    assert set(groups) == {Domain.SAST, Domain.SCA}
    assert len(groups[Domain.SAST]) == 1


def test_group_by_severity_separates_severities():
    issues = _issues(
        _finding("is_1", "in_1", line=1, severity=Severity.CRITICAL),
        _finding("is_2", "in_2", line=100, severity=Severity.LOW),
    )
    groups = group_by_severity(issues)
    assert set(groups) == {Severity.CRITICAL, Severity.LOW}


def test_group_by_file_separates_files():
    issues = _issues(
        _finding("is_1", "in_1", path="a.py"),
        _finding("is_2", "in_2", path="b.py"),
    )
    groups = group_by_file(issues)
    assert set(groups) == {"a.py", "b.py"}


def test_same_group_key_collects_multiple_issues():
    issues = _issues(
        _finding("is_1", "in_1", path="a.py", line=1),
        _finding("is_2", "in_2", path="a.py", line=100),
    )
    groups = group_by_file(issues)
    assert len(groups["a.py"]) == 2


def test_empty_issues_produces_empty_groups():
    assert group_by_domain(()) == {}
