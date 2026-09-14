import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.trivy.adapter import AdapterError, adapt_results


def _tool() -> ToolRecord:
    return ToolRecord(name="trivy", version="0.74.0")


def _vuln_result(**overrides) -> dict:
    result = {
        "Target": "requirements.txt",
        "Class": "lang-pkgs",
        "Type": "pip",
        "Packages": [
            {
                "Name": "flask",
                "Identifier": {"PURL": "pkg:pypi/flask@0.12.2", "UID": "uid1"},
                "Version": "0.12.2",
                "Locations": [{"StartLine": 1, "EndLine": 1}],
            }
        ],
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2018-1000656",
                "PkgName": "flask",
                "PkgIdentifier": {"PURL": "pkg:pypi/flask@0.12.2", "UID": "uid1"},
                "InstalledVersion": "0.12.2",
                "FixedVersion": "0.12.3",
                "Severity": "HIGH",
                "CweIDs": ["CWE-20"],
                "Title": "python-flask: Denial of Service",
                "Description": "desc",
            }
        ],
    }
    result.update(overrides)
    return result


def _secret_result(**overrides) -> dict:
    result = {
        "Target": "config.py",
        "Class": "secret",
        "Secrets": [
            {
                "RuleID": "aws-access-key-id",
                "Category": "AWS",
                "Severity": "CRITICAL",
                "Title": "AWS Access Key ID",
                "StartLine": 1,
                "EndLine": 1,
                "Match": 'AWS_ACCESS_KEY_ID = "********************"',
            }
        ],
    }
    result.update(overrides)
    return result


def test_vulnerability_maps_to_sca_domain():
    findings = adapt_results({"Results": [_vuln_result()]}, _tool())
    assert findings[0].domain is Domain.SCA


def test_vulnerability_carries_package_info():
    f = adapt_results({"Results": [_vuln_result()]}, _tool())[0]
    assert f.package.name == "flask"
    assert f.package.installed_version == "0.12.2"
    assert f.package.fixed_version == "0.12.3"


def test_vulnerability_location_from_package_declaration():
    f = adapt_results({"Results": [_vuln_result()]}, _tool())[0]
    assert f.location.file_path == "requirements.txt"
    assert f.location.line_start == 1


def test_cve_id_extracted_when_present():
    f = adapt_results({"Results": [_vuln_result()]}, _tool())[0]
    assert f.cve_id == "CVE-2018-1000656"


def test_ghsa_only_id_has_no_cve():
    vuln = _vuln_result()
    vuln["Vulnerabilities"][0]["VulnerabilityID"] = "GHSA-562c-5r94-xh97"
    f = adapt_results({"Results": [vuln]}, _tool())[0]
    assert f.cve_id is None
    assert f.rule_id == "GHSA-562c-5r94-xh97"


def test_severity_mapped_from_trivy_scale():
    vuln = _vuln_result()
    vuln["Vulnerabilities"][0]["Severity"] = "CRITICAL"
    f = adapt_results({"Results": [vuln]}, _tool())[0]
    assert f.severity is Severity.CRITICAL


def test_unknown_severity_maps_to_info():
    vuln = _vuln_result()
    vuln["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
    f = adapt_results({"Results": [vuln]}, _tool())[0]
    assert f.severity is Severity.INFO


def test_missing_fixed_version_is_none():
    vuln = _vuln_result()
    del vuln["Vulnerabilities"][0]["FixedVersion"]
    f = adapt_results({"Results": [vuln]}, _tool())[0]
    assert f.package.fixed_version is None


def test_malformed_cwe_ids_are_dropped():
    vuln = _vuln_result()
    vuln["Vulnerabilities"][0]["CweIDs"] = ["CWE-20", "not-a-cwe", "CWE-89"]
    f = adapt_results({"Results": [vuln]}, _tool())[0]
    assert f.cwe_ids == ("CWE-20", "CWE-89")


def test_secret_maps_to_secret_domain():
    f = adapt_results({"Results": [_secret_result()]}, _tool())[0]
    assert f.domain is Domain.SECRET


def test_secret_carries_rule_as_kind():
    f = adapt_results({"Results": [_secret_result()]}, _tool())[0]
    assert f.secret.kind == "aws-access-key-id"


def test_secret_raw_is_empty():
    f = adapt_results({"Results": [_secret_result()]}, _tool())[0]
    assert f.raw == {}


def test_secret_location_uses_start_line():
    f = adapt_results({"Results": [_secret_result()]}, _tool())[0]
    assert f.location.file_path == "config.py"
    assert f.location.line_start == 1


def test_mixed_vuln_and_secret_results():
    findings = adapt_results({"Results": [_vuln_result(), _secret_result()]}, _tool())
    assert {f.domain for f in findings} == {Domain.SCA, Domain.SECRET}


def test_empty_results_is_empty():
    assert adapt_results({"Results": []}, _tool()) == ()


def test_missing_results_key_is_empty():
    assert adapt_results({}, _tool()) == ()


def test_absolute_target_path_is_rejected():
    vuln = _vuln_result(Target="/etc/passwd")
    with pytest.raises(AdapterError, match="outside"):
        adapt_results({"Results": [vuln]}, _tool())


def test_missing_required_field_raises():
    vuln = _vuln_result()
    del vuln["Vulnerabilities"][0]["VulnerabilityID"]
    with pytest.raises(AdapterError, match="VulnerabilityID"):
        adapt_results({"Results": [vuln]}, _tool())


def test_batch_with_one_bad_result_reports_index():
    good = _secret_result()
    bad = _vuln_result()
    del bad["Vulnerabilities"][0]["VulnerabilityID"]
    with pytest.raises(AdapterError, match="index 1"):
        adapt_results({"Results": [good, bad]}, _tool())
