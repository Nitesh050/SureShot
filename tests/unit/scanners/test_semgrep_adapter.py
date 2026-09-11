from pathlib import Path

import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.semgrep.adapter import (
    AdapterError,
    adapt_results,
    extract_cwe_ids,
    map_severity,
)


def _result(**overrides) -> dict:
    base = {
        "check_id": "python.lang.security.sqli",
        "path": "/tmp/sureshot-sc_01-x7f2/source/backend/users.py",
        "start": {"line": 42, "col": 12},
        "end": {"line": 44, "col": 30},
        "extra": {
            "message": "Detected SQL statement built from user input",
            "severity": "ERROR",
            "lines": "query = 'SELECT * FROM users WHERE name = ' + name",
            "metadata": {"cwe": ["CWE-89: Improper Neutralization"], "confidence": "HIGH"},
        },
    }
    extra = overrides.pop("extra", {})
    base["extra"].update(extra)
    base.update(overrides)
    return base


def _tool() -> ToolRecord:
    return ToolRecord(name="semgrep", version="1.90.0")


ROOT = Path("/tmp/sureshot-sc_01-x7f2/source")


def test_path_is_made_repo_relative():
    findings = adapt_results([_result()], ROOT, _tool())
    assert findings[0].location.file_path == "backend/users.py"


def test_absolute_path_outside_root_is_rejected():
    bad = _result(path="/etc/passwd")
    with pytest.raises(AdapterError, match="outside"):
        adapt_results([bad], ROOT, _tool())


def test_cwe_extracted_from_prose_string():
    assert extract_cwe_ids(["CWE-89: Improper Neutralization"]) == ("CWE-89",)


def test_multiple_cwes_extracted_and_deduped():
    raw = ["CWE-89: SQLi", "CWE-89: duplicate", "CWE-79: XSS"]
    assert extract_cwe_ids(raw) == ("CWE-79", "CWE-89")


def test_malformed_cwe_entries_are_dropped():
    assert extract_cwe_ids(["not a cwe", "CWE-22: Path Traversal"]) == ("CWE-22",)


def test_cwe_accepts_bare_string_not_list():
    assert extract_cwe_ids("CWE-89: SQLi") == ("CWE-89",)


def test_missing_cwe_metadata_is_empty():
    assert extract_cwe_ids(None) == ()


def test_severity_uses_confidence_to_break_ties():
    assert map_severity("ERROR", "HIGH") is Severity.HIGH
    assert map_severity("ERROR", "LOW") is Severity.MEDIUM
    assert map_severity("WARNING", "HIGH") is Severity.MEDIUM
    assert map_severity("INFO", "HIGH") is Severity.LOW


def test_unknown_severity_defaults_low():
    assert map_severity("BOGUS", "HIGH") is Severity.LOW


def test_domain_is_sast():
    assert adapt_results([_result()], ROOT, _tool())[0].domain is Domain.SAST


def test_rule_id_and_tool_version_preserved():
    finding = adapt_results([_result()], ROOT, _tool())[0]
    assert finding.rule_id == "python.lang.security.sqli"
    assert finding.tool_version == "1.90.0"


def test_title_derived_from_rule_id_not_message():
    finding = adapt_results([_result()], ROOT, _tool())[0]
    assert finding.title == "Sqli"
    assert "SQL statement" in finding.description


def test_reversed_line_range_is_corrected():
    bad = _result(start={"line": 44, "col": 1}, end={"line": 42, "col": 1})
    finding = adapt_results([bad], ROOT, _tool())[0]
    assert finding.location.line_start == 44
    assert finding.location.line_end == 44


def test_zero_line_number_clamped_to_one():
    bad = _result(start={"line": 0, "col": 0}, end={"line": 0, "col": 0})
    finding = adapt_results([bad], ROOT, _tool())[0]
    assert finding.location.line_start == 1


def test_matched_source_is_not_retained_in_raw():
    finding = adapt_results([_result()], ROOT, _tool())[0]
    assert "lines" not in finding.raw


def test_missing_required_field_raises():
    broken = _result()
    del broken["check_id"]
    with pytest.raises(AdapterError, match="check_id"):
        adapt_results([broken], ROOT, _tool())


def test_secret_rule_produces_redacted_secret_finding():
    secret = _result(
        check_id="generic.secrets.security.detected-aws-access-key-id",
        extra={
            "message": "AWS access key detected",
            "severity": "ERROR",
            "lines": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "metadata": {"cwe": ["CWE-798: Hard-coded Credentials"]},
        },
    )
    finding = adapt_results([secret], ROOT, _tool())[0]
    assert finding.domain is Domain.SECRET
    assert finding.secret is not None
    assert finding.raw == {}
    assert "AKIAIOSFODNN7EXAMPLE" not in str(finding.model_dump())


def test_batch_with_one_bad_result_reports_index():
    good = _result()
    bad = _result()
    del bad["path"]
    with pytest.raises(AdapterError, match="index 1"):
        adapt_results([good, bad], ROOT, _tool())
