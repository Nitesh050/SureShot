import json
import shutil
from pathlib import Path

import pytest

from sureshot.domain.enums import Coverage, Domain
from sureshot.domain.repository import CoverageNote, LanguageStat, RepositoryProfile
from sureshot.engine.scanners.base import ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.sandbox import ProcessResult, SandboxTimeout
from sureshot.engine.scanners.semgrep.rulesets import select_rulesets
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner


def _profile(*languages: str) -> RepositoryProfile:
    return RepositoryProfile(
        total_files=1,
        scanned_files=1,
        skipped_files=0,
        total_bytes=10,
        languages=tuple(
            LanguageStat(name=name, files=1, bytes=100) for name in languages
        ),
        coverage=(
            CoverageNote(domain=Domain.SAST, coverage=Coverage.FULL, reason="ok"),
        ),
    )


def _request(tmp_path: Path) -> ScanRequest:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    return ScanRequest(source=source.resolve(), output=output.resolve())


def test_rulesets_always_include_security_audit():
    assert "p/security-audit" in select_rulesets(_profile("Python"))


def test_rulesets_add_language_packs():
    rules = select_rulesets(_profile("Python", "JavaScript"))
    assert "p/python" in rules
    assert "p/javascript" in rules


def test_rulesets_ignore_unsupported_languages():
    assert select_rulesets(_profile("COBOL")) == ("p/security-audit", "p/secrets")


def test_rulesets_are_deterministic():
    first = select_rulesets(_profile("Python", "Go"))
    second = select_rulesets(_profile("Go", "Python"))
    assert first == second


def test_ruleset_hash_is_stable():
    scanner = SemgrepScanner()
    a = scanner._ruleset_record("1.0.0", ("p/a", "p/b"))
    b = scanner._ruleset_record("1.0.0", ("p/a", "p/b"))
    assert a.ruleset_hash == b.ruleset_hash


def test_ruleset_hash_changes_with_rules():
    scanner = SemgrepScanner()
    a = scanner._ruleset_record("1.0.0", ("p/a",))
    b = scanner._ruleset_record("1.0.0", ("p/a", "p/b"))
    assert a.ruleset_hash != b.ruleset_hash


def test_findings_exit_code_is_not_an_error(tmp_path: Path, monkeypatch):
    payload = {"results": [], "errors": [], "paths": {"scanned": ["a.py"]}}
    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed",
        lambda *a, **k: ProcessResult(
            exit_code=1, stdout=json.dumps(payload), stderr="", duration_ms=5
        ),
    )
    outcome = SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))
    assert outcome.degraded is False


def test_fatal_exit_code_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed",
        lambda *a, **k: ProcessResult(
            exit_code=2, stdout="", stderr="fatal: bad config", duration_ms=5
        ),
    )
    with pytest.raises(ScannerUnavailable, match="fatal"):
        SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))


def test_partial_errors_mark_outcome_degraded(tmp_path: Path, monkeypatch):
    payload = {
        "results": [],
        "errors": [{"message": "parse error in b.py", "level": "warn"}],
        "paths": {"scanned": ["a.py"]},
    }
    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed",
        lambda *a, **k: ProcessResult(
            exit_code=0, stdout=json.dumps(payload), stderr="", duration_ms=5
        ),
    )
    outcome = SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert "1 file" in outcome.partial_reason


def test_timeout_is_degraded_not_fatal(tmp_path: Path, monkeypatch):
    def _boom(*args, **kwargs):
        raise SandboxTimeout("semgrep exceeded 900s")

    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed", _boom
    )
    outcome = SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert outcome.findings == ()


def test_truncated_output_is_degraded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed",
        lambda *a, **k: ProcessResult(
            exit_code=0, stdout="{ truncated", stderr="", duration_ms=5, truncated=True
        ),
    )
    outcome = SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))
    assert outcome.degraded is True
    assert "truncated" in outcome.partial_reason


def test_unparseable_output_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed",
        lambda *a, **k: ProcessResult(
            exit_code=0, stdout="not json", stderr="", duration_ms=5
        ),
    )
    with pytest.raises(ScannerUnavailable, match="parse"):
        SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))


def test_scan_is_offline_by_default(tmp_path: Path, monkeypatch):
    captured: dict = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env")
        payload = {"results": [], "errors": [], "paths": {"scanned": []}}
        return ProcessResult(
            exit_code=0, stdout=json.dumps(payload), stderr="", duration_ms=1
        )

    monkeypatch.setattr(
        "sureshot.engine.scanners.semgrep.scanner.run_sandboxed", _capture
    )
    SemgrepScanner(profile=_profile("Python")).scan(_request(tmp_path))
    assert "--metrics=off" in captured["argv"]
    assert "--disable-version-check" in captured["argv"]
    assert captured["env"]["SEMGREP_SEND_METRICS"] == "off"