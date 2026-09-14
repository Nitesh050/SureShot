from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.diff.baseline import Baseline
from sureshot.engine.diff.changed import filter_to_changed_files
from sureshot.engine.diff.reconcile import reconcile


def _finding(issue_id, path="app.py") -> SecurityFinding:
    return SecurityFinding(
        instance_id=f"in_{issue_id}", issue_id=issue_id,
        tool="semgrep", tool_version="1.0", rule_id="r1",
        domain=Domain.SAST, title="t", severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=1, line_end=1),
    )


def test_no_baseline_means_everything_is_new():
    result = reconcile((_finding("is_1"),), None)
    assert result.new == (_finding("is_1"),)
    assert result.persisting == ()
    assert result.fixed_issue_ids == frozenset()


def test_issue_in_both_is_persisting():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.persisting == (_finding("is_1"),)
    assert result.new == ()


def test_issue_only_in_current_is_new():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"), _finding("is_2")), baseline)
    assert {f.issue_id for f in result.new} == {"is_2"}
    assert {f.issue_id for f in result.persisting} == {"is_1"}


def test_issue_only_in_baseline_is_fixed():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"), _finding("is_2")))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.fixed_issue_ids == frozenset({"is_2"})


def test_empty_current_with_baseline_fixes_everything():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((), baseline)
    assert result.fixed_issue_ids == frozenset({"is_1"})
    assert result.new == ()


def test_regressed_true_when_new_findings_exist():
    baseline = Baseline.from_findings("sc_0", ())
    result = reconcile((_finding("is_1"),), baseline)
    assert result.regressed is True


def test_regressed_false_when_nothing_new():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.regressed is False


def test_identical_scan_twice_is_fully_persisting():
    findings = (_finding("is_1"), _finding("is_2"))
    baseline = Baseline.from_findings("sc_0", findings)
    result = reconcile(findings, baseline)
    assert len(result.persisting) == 2
    assert result.new == ()
    assert result.fixed_issue_ids == frozenset()


def test_filter_to_changed_files_keeps_only_matching_paths():
    findings = (_finding("is_1", path="a.py"), _finding("is_2", path="b.py"))
    filtered = filter_to_changed_files(findings, frozenset({"a.py"}))
    assert len(filtered) == 1
    assert filtered[0].location.file_path == "a.py"


def test_filter_to_changed_files_empty_set_drops_everything():
    findings = (_finding("is_1"),)
    assert filter_to_changed_files(findings, frozenset()) == ()
