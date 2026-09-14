from datetime import UTC, datetime

import pytest

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.enums import Domain, Severity, StepStatus, Verdict
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.domain.repository import CoverageNote, RepositoryProfile
from sureshot.domain.result import TriagedFinding
from sureshot.domain.scan import ScanProvenance, ScanState, StepResult, ToolRecord
from sureshot.engine.pipeline.steps import PipelineResult
from sureshot.reporting.builder import build_report


def _finding(instance_id="in_1", issue_id="is_1", tool="semgrep", severity=Severity.HIGH) -> SecurityFinding:
    return SecurityFinding(
        instance_id=instance_id, issue_id=issue_id,
        tool=tool, tool_version="1.0", rule_id="python.sqli",
        domain=Domain.SAST, title="SQL injection", description="tainted query",
        severity=severity, cwe_ids=("CWE-89",),
        location=Location(file_path="app.py", line_start=12, line_end=12),
    )


def _analysis(instance_id="in_1", verdict=Verdict.TRUE_POSITIVE) -> SecurityAnalysis:
    from sureshot.domain.analysis import Evidence
    return SecurityAnalysis(
        analysis_id="an_1", instance_id=instance_id, verdict=verdict,
        confidence=0.9, rationale="concatenated input",
        evidence=(Evidence(location=Location(file_path="app.py", line_start=12, line_end=12), note="n"),)
        if verdict is not Verdict.NEEDS_HUMAN else (),
        model_id="claude", prompt_version="triage.v3", prompt_hash="h" * 16,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_report():
    finding = _finding()
    triaged = (TriagedFinding(finding=finding, analysis=_analysis(), score=82.5),)

    state = ScanState(
        scan_id="sc_test", org_id="org_1", project_id="demo",
        workdir="/tmp/demo", started_at=datetime.now(UTC),
        provenance=ScanProvenance(
            engine_version="0.1.0",
            tools=(ToolRecord(name="semgrep", version="1.90.0"),),
            risk_policy_hash="policyhash1234",
        ),
        steps=(StepResult(step="scan", status=StepStatus.OK, duration_ms=100),),
    )
    profile = RepositoryProfile(
        total_files=1, scanned_files=1, skipped_files=0, total_bytes=100,
        coverage=(CoverageNote(domain=Domain.SCA, coverage="none", reason="no manifests"),),
    )
    result = PipelineResult(state=state, profile=profile, triaged=triaged)
    return build_report(result, generated_at=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.fixture
def empty_report():
    state = ScanState(
        scan_id="sc_empty", org_id="org_1", project_id="demo",
        workdir="/tmp/demo", started_at=datetime.now(UTC),
        provenance=ScanProvenance(engine_version="0.1.0"),
    )
    profile = RepositoryProfile(total_files=0, scanned_files=0, skipped_files=0, total_bytes=0)
    result = PipelineResult(state=state, profile=profile, triaged=())
    return build_report(result, generated_at=datetime(2026, 1, 1, tzinfo=UTC))
