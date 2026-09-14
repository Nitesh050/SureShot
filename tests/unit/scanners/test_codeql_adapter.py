import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.codeql.adapter import AdapterError, adapt_results


def _tool() -> ToolRecord:
    return ToolRecord(name="codeql", version="2.27.0")


def _rule(**overrides) -> dict:
    rule = {
        "id": "py/sql-injection",
        "shortDescription": {"text": "SQL query built from user-controlled sources"},
        "fullDescription": {"text": "full description"},
        "defaultConfiguration": {"enabled": True, "level": "error"},
        "properties": {
            "tags": ["security", "external/cwe/cwe-089"],
            "precision": "high",
            "problem.severity": "error",
            "security-severity": "8.8",
        },
    }
    rule.update(overrides)
    return rule


def _result(**overrides) -> dict:
    result = {
        "ruleId": "py/sql-injection",
        "message": {"text": "This SQL query depends on a user-provided value."},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": "app.py"},
                "region": {"startLine": 12, "endColumn": 30},
            }
        }],
    }
    result.update(overrides)
    return result


def _payload(rules=None, results=None) -> dict:
    return {
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": rules if rules is not None else [_rule()]}},
            "results": results if results is not None else [_result()],
        }]
    }


def test_finding_maps_to_sast_domain():
    f = adapt_results(_payload(), _tool())[0]
    assert f.domain is Domain.SAST


def test_rule_id_and_title_are_set():
    f = adapt_results(_payload(), _tool())[0]
    assert f.rule_id == "py/sql-injection"
    assert f.title == "SQL query built from user-controlled sources"


def test_message_becomes_description():
    f = adapt_results(_payload(), _tool())[0]
    assert "user-provided value" in f.description


def test_cwe_tag_normalized_from_leading_zero():
    f = adapt_results(_payload(), _tool())[0]
    assert f.cwe_ids == ("CWE-89",)


def test_security_severity_maps_to_high():
    f = adapt_results(_payload(), _tool())[0]
    assert f.severity is Severity.HIGH


def test_security_severity_critical_range():
    rules = [_rule(properties={**_rule()["properties"], "security-severity": "9.5"})]
    f = adapt_results(_payload(rules=rules), _tool())[0]
    assert f.severity is Severity.CRITICAL


def test_missing_security_severity_falls_back_to_level():
    rule = _rule()
    del rule["properties"]["security-severity"]
    f = adapt_results(_payload(rules=[rule]), _tool())[0]
    assert f.severity is Severity.HIGH  # defaultConfiguration.level == "error"


def test_single_line_region_defaults_end_line_to_start():
    """SARIF omits endLine entirely for single-line regions."""
    f = adapt_results(_payload(), _tool())[0]
    assert f.location.line_start == 12
    assert f.location.line_end == 12


def test_explicit_end_line_is_respected():
    result = _result(locations=[{
        "physicalLocation": {
            "artifactLocation": {"uri": "app.py"},
            "region": {"startLine": 10, "endLine": 14},
        }
    }])
    f = adapt_results(_payload(results=[result]), _tool())[0]
    assert f.location.line_start == 10
    assert f.location.line_end == 14


def test_unknown_rule_id_still_produces_finding():
    result = _result(ruleId="js/unknown-rule")
    f = adapt_results(_payload(rules=[], results=[result]), _tool())[0]
    assert f.rule_id == "js/unknown-rule"
    assert f.title == "js/unknown-rule"


def test_absolute_uri_is_rejected():
    result = _result(locations=[{
        "physicalLocation": {
            "artifactLocation": {"uri": "/etc/passwd"},
            "region": {"startLine": 1},
        }
    }])
    with pytest.raises(AdapterError, match="outside"):
        adapt_results(_payload(results=[result]), _tool())


def test_missing_location_raises():
    result = _result(locations=[])
    with pytest.raises(AdapterError, match="location"):
        adapt_results(_payload(results=[result]), _tool())


def test_missing_rule_id_raises():
    result = _result()
    del result["ruleId"]
    with pytest.raises(AdapterError, match="ruleId"):
        adapt_results(_payload(results=[result]), _tool())


def test_no_runs_is_empty():
    assert adapt_results({"runs": []}, _tool()) == ()


def test_missing_runs_key_is_empty():
    assert adapt_results({}, _tool()) == ()


def test_empty_results_is_empty():
    assert adapt_results(_payload(results=[]), _tool()) == ()


def test_batch_with_one_bad_result_reports_index():
    good = _result()
    bad = _result()
    del bad["ruleId"]
    with pytest.raises(AdapterError, match="index 1"):
        adapt_results(_payload(results=[good, bad]), _tool())
