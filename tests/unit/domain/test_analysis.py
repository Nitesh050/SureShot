from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sureshot.domain.analysis import Evidence, SecurityAnalysis
from sureshot.domain.enums import GuardHold, Verdict
from sureshot.domain.finding import Location


def _evidence() -> Evidence:
    return Evidence(
        location=Location(file_path="backend/users.py", line_start=42, line_end=44),
        note="username flows into execute() unparameterized",
    )


def _analysis(**overrides) -> SecurityAnalysis:
    base = dict(
        analysis_id="an_01",
        instance_id="in_01",
        verdict=Verdict.TRUE_POSITIVE,
        confidence=0.9,
        rationale="user input reaches the query unsanitized",
        evidence=(_evidence(),),
        model_id="test-model",
        prompt_version="triage.v3",
        prompt_hash="abc123",
        created_at=datetime.now(UTC),
    )
    return SecurityAnalysis(**(base | overrides))


def test_valid_analysis():
    assert _analysis().verdict is Verdict.TRUE_POSITIVE


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError):
        _analysis(created_at=datetime(2026, 1, 1))


def test_dismissal_without_evidence_rejected():
    with pytest.raises(ValidationError):
        _analysis(verdict=Verdict.FALSE_POSITIVE, evidence=())


def test_needs_human_may_have_no_evidence():
    assert _analysis(verdict=Verdict.NEEDS_HUMAN, evidence=()).evidence == ()


def test_hold_cannot_coexist_with_dismissal():
    with pytest.raises(ValidationError):
        _analysis(
            verdict=Verdict.FALSE_POSITIVE,
            guard_holds=(GuardHold.INJECTION,),
        )


def test_held_diverts_a_dismissal_to_review():
    held = _analysis(verdict=Verdict.FALSE_POSITIVE).held(GuardHold.INJECTION)
    assert held.verdict is Verdict.NEEDS_HUMAN
    assert held.guard_holds == (GuardHold.INJECTION,)


def test_held_is_idempotent():
    once = _analysis().held(GuardHold.EVIDENCE)
    assert once.held(GuardHold.EVIDENCE) is once


def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        _analysis(confidence=1.4)