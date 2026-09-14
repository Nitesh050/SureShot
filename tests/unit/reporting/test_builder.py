def test_report_carries_scan_identity(sample_report):
    assert sample_report.scan_id == "sc_test"
    assert sample_report.org_id == "org_1"
    assert sample_report.project_id == "demo"


def test_report_dedupes_findings_into_issues(sample_report):
    assert len(sample_report.issues) == 1
    assert sample_report.issues[0].issue_id == "is_1"


def test_actionable_issues_excludes_dismissed(sample_report):
    assert len(sample_report.actionable_issues) == 1


def test_empty_result_produces_no_issues(empty_report):
    assert empty_report.issues == ()
    assert empty_report.actionable_issues == ()
