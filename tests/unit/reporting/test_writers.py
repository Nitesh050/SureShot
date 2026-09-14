import json

from sureshot.reporting.writers import html as html_writer
from sureshot.reporting.writers import json as json_writer
from sureshot.reporting.writers import pdf as pdf_writer
from sureshot.reporting.writers import sarif as sarif_writer


# ---- json ----

def test_json_output_is_valid_json(sample_report):
    payload = json.loads(json_writer.write(sample_report))
    assert payload["scan_id"] == "sc_test"


def test_json_includes_issue_and_score(sample_report):
    payload = json.loads(json_writer.write(sample_report))
    assert len(payload["issues"]) == 1
    assert payload["issues"][0]["score"] == 82.5
    assert payload["issues"][0]["finding"]["rule_id"] == "python.sqli"


def test_json_empty_report_has_empty_issues(empty_report):
    payload = json.loads(json_writer.write(empty_report))
    assert payload["issues"] == []


# ---- sarif ----

def test_sarif_output_is_valid_json(sample_report):
    payload = json.loads(sarif_writer.write(sample_report))
    assert payload["version"] == "2.1.0"


def test_sarif_has_one_run_with_matching_result(sample_report):
    payload = json.loads(sarif_writer.write(sample_report))
    run = payload["runs"][0]
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "python.sqli"


def test_sarif_rule_carries_cwe_tag(sample_report):
    payload = json.loads(sarif_writer.write(sample_report))
    rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
    assert "external/cwe/cwe-89" in rule["properties"]["tags"]


def test_sarif_critical_and_high_map_to_error_level(sample_report):
    payload = json.loads(sarif_writer.write(sample_report))
    assert payload["runs"][0]["results"][0]["level"] == "error"


def test_sarif_empty_report_has_no_results(empty_report):
    payload = json.loads(sarif_writer.write(empty_report))
    assert payload["runs"][0]["results"] == []


# ---- html ----

def test_html_contains_finding_title(sample_report):
    html = html_writer.write(sample_report)
    assert "SQL injection" in html


def test_html_escapes_untrusted_content():
    """Autoescape must be on — a title containing markup must not pass through raw."""
    from datetime import UTC, datetime

    from sureshot.domain.analysis import SecurityAnalysis
    from sureshot.domain.enums import Domain, Severity, StepStatus, Verdict
    from sureshot.domain.finding import Location, SecurityFinding
    from sureshot.domain.repository import RepositoryProfile
    from sureshot.domain.result import TriagedFinding
    from sureshot.domain.scan import ScanProvenance, ScanState
    from sureshot.engine.pipeline.steps import PipelineResult
    from sureshot.reporting.builder import build_report

    finding = SecurityFinding(
        instance_id="in_x", issue_id="is_x", tool="semgrep", tool_version="1.0",
        rule_id="r", domain=Domain.SAST, title="<script>alert(1)</script>",
        severity=Severity.LOW,
        location=Location(file_path="a.py", line_start=1, line_end=1),
    )
    triaged = (TriagedFinding(finding=finding, score=10.0),)
    state = ScanState(
        scan_id="sc_x", org_id="o", project_id="p", workdir="/tmp",
        started_at=datetime.now(UTC), provenance=ScanProvenance(engine_version="0.1.0"),
    )
    profile = RepositoryProfile(total_files=1, scanned_files=1, skipped_files=0, total_bytes=1)
    report = build_report(PipelineResult(state=state, profile=profile, triaged=triaged))

    html = html_writer.write(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_empty_report_says_no_findings(empty_report):
    html = html_writer.write(empty_report)
    assert "No findings" in html


def test_html_shows_coverage_gap(sample_report):
    html = html_writer.write(sample_report)
    assert "coverage" in html.lower()


# ---- pdf ----

def test_pdf_output_has_valid_magic_bytes(sample_report):
    pdf_bytes = pdf_writer.write(sample_report)
    assert pdf_bytes[:5] == b"%PDF-"


def test_pdf_output_has_valid_trailer(sample_report):
    pdf_bytes = pdf_writer.write(sample_report)
    assert b"%%EOF" in pdf_bytes[-32:]


def test_pdf_empty_report_still_produces_valid_pdf(empty_report):
    pdf_bytes = pdf_writer.write(empty_report)
    assert pdf_bytes[:5] == b"%PDF-"
