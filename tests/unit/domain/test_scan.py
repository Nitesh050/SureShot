from datetime import UTC, datetime

from sureshot.domain.enums import StepStatus
from sureshot.domain.scan import ScanProvenance, ScanState, StepResult, ToolRecord


def _state() -> ScanState:
    return ScanState(
        scan_id="sc_01",
        org_id="or_01",
        project_id="pr_01",
        workdir="/tmp/aegis-x7f2",
        started_at=datetime.now(UTC),
        provenance=ScanProvenance(engine_version="0.1.0"),
    )


def test_recording_a_step_returns_a_new_state():
    original = _state()
    updated = original.record(
        StepResult(step="ingest", status=StepStatus.OK, duration_ms=120)
    )
    assert original.steps == ()
    assert len(updated.steps) == 1


def test_degraded_step_does_not_block_pipeline():
    result = StepResult(step="semgrep", status=StepStatus.DEGRADED, duration_ms=90)
    assert result.blocks_pipeline is False


def test_failed_step_blocks_pipeline():
    result = StepResult(step="ingest", status=StepStatus.FAILED, duration_ms=5)
    assert result.blocks_pipeline is True


def test_scan_is_degraded_if_any_step_is_not_ok():
    state = _state().record(
        StepResult(step="trivy", status=StepStatus.DEGRADED, duration_ms=300)
    )
    assert state.degraded is True


def test_provenance_accumulates_tool_records():
    provenance = ScanProvenance(engine_version="0.1.0").with_tool(
        ToolRecord(name="semgrep", version="1.90.0", ruleset_id="p/security-audit")
    )
    assert provenance.tools[0].name == "semgrep"