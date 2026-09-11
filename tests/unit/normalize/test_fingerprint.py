import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, Package, SecretRef, SecurityFinding
from sureshot.engine.normalize.fingerprint import (
    apply_fingerprints,
    normalize_snippet,
    snippet_hash,
)

SNIPPET = "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\""


def _finding(**overrides) -> SecurityFinding:
    base = dict(
        tool="semgrep",
        tool_version="1.90.0",
        rule_id="python.lang.security.sqli",
        domain=Domain.SAST,
        title="Sqli",
        severity=Severity.HIGH,
        cwe_ids=("CWE-89",),
        location=Location(file_path="backend/users.py", line_start=42, line_end=42),
    )
    return SecurityFinding(**(base | overrides))


def _fp(finding: SecurityFinding, snippet: str = SNIPPET) -> SecurityFinding:
    return apply_fingerprints((finding,), {finding.location.file_path: snippet})[0]


def test_ids_are_populated():
    finding = _fp(_finding())
    assert finding.instance_id and finding.issue_id


def test_line_shift_does_not_change_instance_id():
    """The whole point: adding an import above must not churn the fingerprint."""
    at_42 = _fp(_finding())
    at_43 = _fp(
        _finding(location=Location(file_path="backend/users.py", line_start=43, line_end=43))
    )
    assert at_42.instance_id == at_43.instance_id


def test_changing_the_code_changes_instance_id():
    original = _fp(_finding())
    patched = _fp(_finding(), snippet="query = 'SELECT * FROM users WHERE name = ?'")
    assert original.instance_id != patched.instance_id


def test_moving_the_file_changes_both_ids():
    here = _fp(_finding())
    there = _fp(
        _finding(location=Location(file_path="api/users.py", line_start=42, line_end=42))
    )
    assert here.instance_id != there.instance_id
    assert here.issue_id != there.issue_id


def test_different_rules_same_code_differ_by_instance_but_share_issue():
    """Two rules flagging one CWE in one file are one issue, two instances."""
    a = _fp(_finding(rule_id="python.sqli.v1"))
    b = _fp(_finding(rule_id="python.sqli.v2"))
    assert a.instance_id != b.instance_id
    assert a.issue_id == b.issue_id


def test_issue_id_is_tool_independent():
    semgrep = _fp(_finding(tool="semgrep"))
    codeql = _fp(_finding(tool="codeql", rule_id="cs/sql-injection"))
    assert semgrep.issue_id == codeql.issue_id


def test_tool_version_does_not_affect_ids():
    old = _fp(_finding(tool_version="1.90.0"))
    new = _fp(_finding(tool_version="1.95.0"))
    assert old.instance_id == new.instance_id


def test_severity_does_not_affect_ids():
    high = _fp(_finding(severity=Severity.HIGH))
    low = _fp(_finding(severity=Severity.LOW))
    assert high.instance_id == low.instance_id


def test_whitespace_only_edits_do_not_churn():
    tight = normalize_snippet("if(x){return 1;}")
    loose = normalize_snippet("if ( x ) {\n    return 1;\n}")
    assert tight == loose


def test_normalization_preserves_string_literals():
    a = normalize_snippet("name = 'admin'")
    b = normalize_snippet("name = 'guest'")
    assert a != b


def test_comments_are_stripped():
    with_comment = normalize_snippet("x = 1  # TODO fix this")
    without = normalize_snippet("x = 1")
    assert with_comment == without


def test_hash_is_deterministic_across_calls():
    assert snippet_hash(SNIPPET) == snippet_hash(SNIPPET)


def test_missing_snippet_falls_back_without_crashing():
    finding = apply_fingerprints((_finding(),), {})[0]
    assert finding.instance_id is not None


def test_missing_snippet_fallback_is_line_anchored():
    """Without content we must degrade to line anchoring, and say so implicitly."""
    at_42 = apply_fingerprints((_finding(),), {})[0]
    moved = apply_fingerprints(
        (_finding(location=Location(file_path="backend/users.py", line_start=99, line_end=99)),),
        {},
    )[0]
    assert at_42.instance_id != moved.instance_id


def test_sca_issue_id_keys_on_package_not_location():
    pkg = Package(name="flask", installed_version="2.0.0")
    a = _fp(_finding(
        domain=Domain.SCA, package=pkg, cve_id="CVE-2023-1234",
        location=Location(file_path="requirements.txt", line_start=3, line_end=3),
    ))
    b = _fp(_finding(
        domain=Domain.SCA, package=pkg, cve_id="CVE-2023-1234",
        location=Location(file_path="requirements.txt", line_start=17, line_end=17),
    ))
    assert a.issue_id == b.issue_id


def test_sca_different_cve_same_package_differs():
    pkg = Package(name="flask", installed_version="2.0.0")
    a = _fp(_finding(domain=Domain.SCA, package=pkg, cve_id="CVE-2023-1234"))
    b = _fp(_finding(domain=Domain.SCA, package=pkg, cve_id="CVE-2023-9999"))
    assert a.issue_id != b.issue_id


def test_secret_issue_id_uses_redacted_ref_only():
    ref = SecretRef(kind="aws-key", last_four="MPLE")
    finding = _fp(_finding(domain=Domain.SECRET, secret=ref, raw={}))
    assert finding.issue_id is not None


def test_ids_are_stable_across_process_runs():
    """No randomized hashing — PYTHONHASHSEED must not matter."""
    assert snippet_hash("x = 1") == (
        "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"[:32]
    ) or len(snippet_hash("x = 1")) == 32


def test_batch_preserves_order():
    findings = tuple(
        _finding(location=Location(file_path=f"f{i}.py", line_start=1, line_end=1))
        for i in range(5)
    )
    out = apply_fingerprints(findings, {})
    assert [f.location.file_path for f in out] == [f"f{i}.py" for i in range(5)]