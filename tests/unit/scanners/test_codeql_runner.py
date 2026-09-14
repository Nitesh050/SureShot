import json
from pathlib import Path

import pytest

from sureshot.domain.repository import LanguageStat, RepositoryProfile
from sureshot.engine.scanners.base import ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.codeql.scanner import CodeQLScanner
from sureshot.engine.scanners.sandbox import ProcessResult, SandboxTimeout


def _profile(language: str = "Python") -> RepositoryProfile:
    return RepositoryProfile(
        total_files=1, scanned_files=1, skipped_files=0, total_bytes=1,
        languages=(LanguageStat(name=language, files=1, bytes=100),),
    )


def _request(tmp_path: Path) -> ScanRequest:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    return ScanRequest(source=source.resolve(), output=output.resolve())


def _version_reply():
    return ProcessResult(exit_code=0, stdout='{"version": "2.27.0"}', stderr="", duration_ms=1)


def _argv_kind(argv: list[str]) -> str:
    if "version" in argv:
        return "version"
    if "create" in argv:
        return "create"
    if "analyze" in argv:
        return "analyze"
    return "unknown"


def _fake_factory(sarif_payload: dict, create_exit: int = 0, analyze_exit: int = 0):
    def _fake(argv, **kwargs):
        kind = _argv_kind(argv)
        if kind == "version":
            return _version_reply()
        if kind == "create":
            return ProcessResult(exit_code=create_exit, stdout="", stderr="create failed", duration_ms=5)
        if kind == "analyze":
            output_arg = next(a for a in argv if a.startswith("--output="))
            sarif_path = Path(output_arg.split("=", 1)[1])
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_path.write_text(json.dumps(sarif_payload))
            return ProcessResult(exit_code=analyze_exit, stdout="", stderr="analyze failed", duration_ms=7)
        raise AssertionError(f"unexpected argv: {argv}")

    return _fake


def test_no_supported_language_skips_without_calling_binary(tmp_path: Path, monkeypatch):
    def _explode(argv, **kwargs):
        raise AssertionError("should not run codeql when no language is selected")

    monkeypatch.setattr("sureshot.engine.scanners.codeql.scanner.run_sandboxed", _explode)
    outcome = CodeQLScanner(profile=None).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert outcome.findings == ()


def test_unsupported_language_skips(tmp_path: Path, monkeypatch):
    def _explode(argv, **kwargs):
        raise AssertionError("should not run codeql for an unsupported language")

    monkeypatch.setattr("sureshot.engine.scanners.codeql.scanner.run_sandboxed", _explode)
    outcome = CodeQLScanner(profile=_profile("PHP")).scan(_request(tmp_path))
    assert outcome.degraded is True


def test_clean_scan_with_no_findings(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.codeql.scanner.run_sandboxed",
        _fake_factory({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
    )
    outcome = CodeQLScanner(profile=_profile()).scan(_request(tmp_path))
    assert outcome.findings == ()
    assert outcome.degraded is False


def test_findings_are_adapted(tmp_path: Path, monkeypatch):
    sarif = {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "py/sql-injection",
                "shortDescription": {"text": "SQLi"},
                "properties": {"tags": ["external/cwe/cwe-089"], "security-severity": "8.8"},
            }]}},
            "results": [{
                "ruleId": "py/sql-injection",
                "message": {"text": "tainted"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 5},
                    }
                }],
            }],
        }]
    }
    monkeypatch.setattr(
        "sureshot.engine.scanners.codeql.scanner.run_sandboxed", _fake_factory(sarif)
    )
    outcome = CodeQLScanner(profile=_profile()).scan(_request(tmp_path))
    assert len(outcome.findings) == 1
    assert outcome.findings[0].rule_id == "py/sql-injection"
    assert outcome.tool.ruleset_id == "codeql/python-queries:codeql-suites/python-security-extended.qls"


def test_version_timeout_is_degraded_not_fatal(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        raise SandboxTimeout("codeql exceeded 30s")

    monkeypatch.setattr("sureshot.engine.scanners.codeql.scanner.run_sandboxed", _fake)
    outcome = CodeQLScanner(profile=_profile()).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert outcome.findings == ()


def test_database_create_timeout_is_degraded(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        kind = _argv_kind(argv)
        if kind == "version":
            return _version_reply()
        raise SandboxTimeout("create exceeded timeout")

    monkeypatch.setattr("sureshot.engine.scanners.codeql.scanner.run_sandboxed", _fake)
    outcome = CodeQLScanner(profile=_profile()).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert "database create" in outcome.partial_reason


def test_database_create_failure_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.codeql.scanner.run_sandboxed",
        _fake_factory({}, create_exit=2),
    )
    with pytest.raises(ScannerUnavailable, match="database create failed"):
        CodeQLScanner(profile=_profile()).scan(_request(tmp_path))


def test_database_analyze_failure_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.codeql.scanner.run_sandboxed",
        _fake_factory({}, analyze_exit=2),
    )
    with pytest.raises(ScannerUnavailable, match="database analyze failed"):
        CodeQLScanner(profile=_profile()).scan(_request(tmp_path))


def test_missing_binary_raises_scanner_unavailable():
    with pytest.raises(ScannerUnavailable, match="unavailable"):
        CodeQLScanner(binary="codeql-does-not-exist").version()
