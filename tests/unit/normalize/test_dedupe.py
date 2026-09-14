from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.domain.result import TriagedFinding
from sureshot.engine.normalize.dedupe import dedupe


def _finding(tool="semgrep", rule_id="r1", issue_id="is_1", instance_id="in_1", **overrides) -> SecurityFinding:
    base = dict(
        instance_id=instance_id, issue_id=issue_id,
        tool=tool, tool_version="1.0", rule_id=rule_id,
        domain=Domain.SAST, title="t", severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path="app.py", line_start=1, line_end=1),
    )
    return SecurityFinding(**(base | overrides))


def _triaged(score=50.0, **overrides) -> TriagedFinding:
    return TriagedFinding(finding=_finding(**overrides), score=score)


def test_single_finding_is_its_own_issue():
    issues = dedupe((_triaged(),))
    assert len(issues) == 1
    assert issues[0].issue_id == "is_1"
    assert issues[0].occurrences == 1


def test_same_issue_id_collapses_to_one_issue():
    a = _triaged(instance_id="in_1", score=80.0)
    b = _triaged(instance_id="in_2", score=60.0)
    issues = dedupe((a, b))
    assert len(issues) == 1
    assert issues[0].occurrences == 2


def test_different_issue_ids_stay_separate():
    a = _triaged(issue_id="is_1", instance_id="in_1", location=Location(file_path="a.py", line_start=1, line_end=1))
    b = _triaged(issue_id="is_2", instance_id="in_2", location=Location(file_path="b.py", line_start=1, line_end=1))
    issues = dedupe((a, b))
    assert len(issues) == 2


def test_primary_is_highest_scoring_instance():
    low = _triaged(instance_id="in_1", score=10.0)
    high = _triaged(instance_id="in_2", score=90.0)
    issues = dedupe((low, high))
    assert issues[0].primary.score == 90.0
    assert issues[0].duplicates[0].score == 10.0


def test_tools_lists_distinct_tools():
    a = _triaged(tool="semgrep", instance_id="in_1")
    b = _triaged(tool="codeql", instance_id="in_2")
    issues = dedupe((a, b))
    assert issues[0].tools == ("codeql", "semgrep")


def test_confirmed_by_multiple_tools_true_when_two_tools_agree():
    a = _triaged(tool="semgrep", instance_id="in_1")
    b = _triaged(tool="codeql", instance_id="in_2")
    issues = dedupe((a, b))
    assert issues[0].confirmed_by_multiple_tools is True


def test_single_tool_is_not_confirmed_by_multiple():
    issues = dedupe((_triaged(),))
    assert issues[0].confirmed_by_multiple_tools is False


def test_same_tool_twice_does_not_count_as_multiple():
    a = _triaged(tool="semgrep", instance_id="in_1")
    b = _triaged(tool="semgrep", instance_id="in_2")
    issues = dedupe((a, b))
    assert issues[0].confirmed_by_multiple_tools is False


def test_issues_sorted_by_score_descending():
    low = _triaged(
        issue_id="is_low", instance_id="in_1", score=10.0,
        location=Location(file_path="a.py", line_start=1, line_end=1),
    )
    high = _triaged(
        issue_id="is_high", instance_id="in_2", score=90.0,
        location=Location(file_path="b.py", line_start=1, line_end=1),
    )
    issues = dedupe((low, high))
    assert [i.issue_id for i in issues] == ["is_high", "is_low"]


def test_empty_input_is_empty():
    assert dedupe(()) == ()


# ---- SAST cross-tool correlation ----
# Real case that motivated this: Semgrep and CodeQL flagging the same SQL
# injection tagged different CWEs (CWE-704 vs CWE-89) at adjacent lines,
# which meant exact issue_id matching alone never collapsed them.

def test_sast_findings_nearby_lines_different_cwe_still_correlate():
    a = _triaged(
        tool="semgrep", issue_id="is_semgrep", instance_id="in_1",
        cwe_ids=("CWE-704",),
        location=Location(file_path="app.py", line_start=11, line_end=11),
    )
    b = _triaged(
        tool="codeql", issue_id="is_codeql", instance_id="in_2",
        cwe_ids=("CWE-89",),
        location=Location(file_path="app.py", line_start=12, line_end=12),
    )
    issues = dedupe((a, b))
    assert len(issues) == 1
    assert issues[0].confirmed_by_multiple_tools is True
    assert issues[0].occurrences == 2


def test_sast_findings_far_apart_lines_do_not_correlate():
    a = _triaged(
        issue_id="is_1", instance_id="in_1",
        location=Location(file_path="app.py", line_start=10, line_end=10),
    )
    b = _triaged(
        issue_id="is_2", instance_id="in_2",
        location=Location(file_path="app.py", line_start=50, line_end=50),
    )
    issues = dedupe((a, b))
    assert len(issues) == 2


def test_sast_findings_same_line_different_file_do_not_correlate():
    a = _triaged(
        issue_id="is_1", instance_id="in_1",
        location=Location(file_path="a.py", line_start=5, line_end=5),
    )
    b = _triaged(
        issue_id="is_2", instance_id="in_2",
        location=Location(file_path="b.py", line_start=5, line_end=5),
    )
    issues = dedupe((a, b))
    assert len(issues) == 2


def test_sca_findings_do_not_get_fuzzy_correlation():
    """Exact-only for SCA — it already has a reliable key (package + CVE);
    proximity means nothing for a dependency manifest line."""
    from sureshot.domain.finding import Package

    a = _triaged(
        issue_id="is_1", instance_id="in_1", domain=Domain.SCA,
        package=Package(name="flask", installed_version="0.12.2"),
        location=Location(file_path="requirements.txt", line_start=1, line_end=1),
    )
    b = _triaged(
        issue_id="is_2", instance_id="in_2", domain=Domain.SCA,
        package=Package(name="requests", installed_version="2.6.0"),
        location=Location(file_path="requirements.txt", line_start=1, line_end=1),
    )
    issues = dedupe((a, b))
    assert len(issues) == 2


def test_correlated_group_keeps_highest_scoring_as_primary():
    low = _triaged(
        tool="semgrep", issue_id="is_semgrep", instance_id="in_1", score=40.0,
        location=Location(file_path="app.py", line_start=11, line_end=11),
    )
    high = _triaged(
        tool="codeql", issue_id="is_codeql", instance_id="in_2", score=90.0,
        location=Location(file_path="app.py", line_start=12, line_end=12),
    )
    issues = dedupe((low, high))
    assert len(issues) == 1
    assert issues[0].primary.finding.tool == "codeql"
    assert issues[0].issue_id == "is_codeql"
