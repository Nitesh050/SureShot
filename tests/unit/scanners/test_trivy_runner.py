import json
from pathlib import Path

import pytest

from sureshot.engine.scanners.base import ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.sandbox import ProcessResult, SandboxTimeout
from sureshot.engine.scanners.trivy.scanner import TrivyScanner


def _request(tmp_path: Path) -> ScanRequest:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    return ScanRequest(source=source.resolve(), output=output.resolve())


def _version_reply():
    return ProcessResult(exit_code=0, stdout='{"Version": "0.74.0"}', stderr="", duration_ms=1)


def test_clean_scan_with_no_findings(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        return ProcessResult(exit_code=0, stdout='{"Results": []}', stderr="", duration_ms=5)

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    outcome = TrivyScanner().scan(_request(tmp_path))
    assert outcome.findings == ()
    assert outcome.degraded is False


def test_findings_are_adapted(tmp_path: Path, monkeypatch):
    payload = {
        "Results": [{
            "Target": "requirements.txt",
            "Packages": [{
                "Name": "flask", "Identifier": {"UID": "u1"},
                "Locations": [{"StartLine": 1, "EndLine": 1}],
            }],
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2018-1000656", "PkgName": "flask",
                "PkgIdentifier": {"UID": "u1"}, "InstalledVersion": "0.12.2",
                "Severity": "HIGH",
            }],
        }],
    }

    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        return ProcessResult(exit_code=0, stdout=json.dumps(payload), stderr="", duration_ms=5)

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    outcome = TrivyScanner().scan(_request(tmp_path))
    assert len(outcome.findings) == 1
    assert outcome.findings[0].rule_id == "CVE-2018-1000656"


def test_timeout_is_degraded_not_fatal(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        raise SandboxTimeout("trivy exceeded 900s")

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    outcome = TrivyScanner().scan(_request(tmp_path))
    assert outcome.degraded is True
    assert outcome.findings == ()


def test_fatal_exit_code_raises(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        return ProcessResult(exit_code=1, stdout="", stderr="fatal: bad path", duration_ms=5)

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    with pytest.raises(ScannerUnavailable, match="fatal"):
        TrivyScanner().scan(_request(tmp_path))


def test_truncated_output_is_degraded(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        return ProcessResult(
            exit_code=0, stdout="{ truncated", stderr="", duration_ms=5, truncated=True
        )

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    outcome = TrivyScanner().scan(_request(tmp_path))
    assert outcome.degraded is True
    assert "truncated" in outcome.partial_reason


def test_unparseable_output_raises(tmp_path: Path, monkeypatch):
    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        return ProcessResult(exit_code=0, stdout="not json", stderr="", duration_ms=5)

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    with pytest.raises(ScannerUnavailable, match="parse"):
        TrivyScanner().scan(_request(tmp_path))


def test_cache_dir_is_passed_through(tmp_path: Path, monkeypatch):
    captured = {}

    def _fake(argv, **kwargs):
        if "--version" in argv:
            return _version_reply()
        captured["argv"] = argv
        return ProcessResult(exit_code=0, stdout='{"Results": []}', stderr="", duration_ms=5)

    monkeypatch.setattr("sureshot.engine.scanners.trivy.scanner.run_sandboxed", _fake)
    TrivyScanner(cache_dir=Path("/tmp/my-cache")).scan(_request(tmp_path))
    assert "--cache-dir" in captured["argv"]
    assert "/tmp/my-cache" in captured["argv"]


def test_missing_binary_raises_scanner_unavailable(tmp_path: Path):
    with pytest.raises(ScannerUnavailable, match="unavailable"):
        TrivyScanner(binary="trivy-does-not-exist").version()
