from datetime import UTC, datetime
from pathlib import Path

import pytest

from sureshot.domain.enums import Domain, Severity, StepStatus, Verdict
from sureshot.domain.scan import ScanProvenance, ScanState
from sureshot.engine.pipeline.steps import (
    PipelineContext,
    run_pipeline,
    step_fingerprint,
    step_profile,
    step_score,
)
from sureshot.engine.scanners.base import ScanOutcome
from sureshot.domain.scan import ToolRecord

VULNERABLE = '''import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM u WHERE n = '" + username + "'").fetchall()
'''


def _state(workdir: Path) -> ScanState:
    return ScanState(
        scan_id="sc_1", org_id="local", project_id="demo",
        workdir=str(workdir), started_at=datetime.now(UTC),
        provenance=ScanProvenance(engine_version="0.1.0"),
    )


class StubScanner:
    name = "stub"
    domains = (Domain.SAST,)

    def __init__(self, findings=()) -> None:
        self._findings = findings

    def version(self):
        return ToolRecord(name="stub", version="1.0")

    def scan(self, request):
        return ScanOutcome(findings=self._findings, tool=self.version(), duration_ms=1)


class StubTriage:
    def triage_batch(self, findings, snippets):
        from sureshot.domain.analysis import Evidence, SecurityAnalysis
        from sureshot.domain.finding import Location
        return tuple(
            SecurityAnalysis(
                analysis_id=f"an_{i}", instance_id=f.instance_id,
                verdict=Verdict.TRUE_POSITIVE, confidence=0.9, rationale="r",
                evidence=(Evidence(location=f.location, note="n"),),
                model_id="stub", prompt_version="triage.v1", prompt_hash="h" * 16,
                created_at=datetime.now(UTC),
            )
            for i, f in enumerate(findings)
        )


def _ctx(tmp_path: Path, **kwargs) -> PipelineContext:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    return PipelineContext(
        source=source.resolve(), output=tmp_path.resolve(),
        scanners=kwargs.get("scanners", (StubScanner(),)),
        triage=kwargs.get("triage", StubTriage()),
        timeout_seconds=60,
    )


def test_profile_records_a_step(tmp_path: Path):
    ctx = _ctx(tmp_path)
    (ctx.source / "a.py").write_text(VULNERABLE)
    state, profile = step_profile(_state(tmp_path), ctx)
    assert profile.scanned_files == 1
    assert state.steps[0].step == "profile"


def test_pipeline_returns_triaged_findings(tmp_path: Path):
    ctx = _ctx(tmp_path)
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert result.state.steps
    assert isinstance(result.triaged, tuple)


def test_scanner_failure_degrades_but_continues(tmp_path: Path):
    from sureshot.engine.scanners.base import ScannerUnavailable

    class Broken:
        name = "broken"
        domains = (Domain.SAST,)
        def version(self): return ToolRecord(name="broken", version="0")
        def scan(self, request): raise ScannerUnavailable("binary missing")

    ctx = _ctx(tmp_path, scanners=(Broken(), StubScanner()))
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert result.state.degraded is True
    assert any(s.status is StepStatus.DEGRADED for s in result.state.steps)


def test_all_scanners_failing_is_still_not_fatal(tmp_path: Path):
    from sureshot.engine.scanners.base import ScannerUnavailable

    class Broken:
        name = "broken"
        domains = (Domain.SAST,)
        def version(self): return ToolRecord(name="broken", version="0")
        def scan(self, request): raise ScannerUnavailable("gone")

    ctx = _ctx(tmp_path, scanners=(Broken(),))
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert result.triaged == ()
    assert result.state.degraded is True


def test_results_are_sorted_by_score_descending(tmp_path: Path):
    ctx = _ctx(tmp_path)
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    scores = [t.score for t in result.triaged]
    assert scores == sorted(scores, reverse=True)


def test_provenance_accumulates_every_tool(tmp_path: Path):
    ctx = _ctx(tmp_path, scanners=(StubScanner(), StubScanner()))
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert len(result.state.provenance.tools) == 2


def test_policy_hash_lands_in_provenance(tmp_path: Path):
    ctx = _ctx(tmp_path)
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert result.state.provenance.risk_policy_hash is not None


def test_empty_repository_produces_no_findings(tmp_path: Path):
    result = run_pipeline(_state(tmp_path), _ctx(tmp_path))
    assert result.triaged == ()
    assert result.state.degraded is False


def test_triage_failure_degrades_without_losing_findings(tmp_path: Path):
    from sureshot.domain.finding import Location, SecurityFinding

    class BrokenTriage:
        def triage_batch(self, findings, snippets):
            raise RuntimeError("model down")

    finding = SecurityFinding(
        tool="stub", tool_version="1.0", rule_id="stub.sqli",
        domain=Domain.SAST, title="Sqli", severity=Severity.HIGH,
        cwe_ids=("CWE-89",),
        location=Location(file_path="a.py", line_start=5, line_end=5),
    )
    ctx = _ctx(tmp_path, scanners=(StubScanner(findings=(finding,)),), triage=BrokenTriage())
    (ctx.source / "a.py").write_text(VULNERABLE)
    result = run_pipeline(_state(tmp_path), ctx)
    assert result.triaged
    assert all(t.analysis is None for t in result.triaged)
    assert result.state.degraded is True
