from datetime import UTC, datetime

from sureshot.domain.analysis import Evidence, SecurityAnalysis
from sureshot.domain.enums import Domain, Severity, Verdict
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.guards.policy import apply_critical_floor

FLOOR = 40.0


def _finding(severity=Severity.CRITICAL) -> SecurityFinding:
    return SecurityFinding(
        instance_id="in_1", issue_id="is_1", tool="semgrep", tool_version="1.0",
        rule_id="r", domain=Domain.SAST, title="t", severity=severity,
        cwe_ids=("CWE-89",), location=Location(file_path="a.py", line_start=1, line_end=1),
    )


def _analysis(verdict=Verdict.FALSE_POSITIVE) -> SecurityAnalysis:
    return SecurityAnalysis(
        analysis_id="an_1", instance_id="in_1", verdict=verdict,
        confidence=0.9, rationale="r",
        evidence=(Evidence(location=Location(file_path="a.py", line_start=1, line_end=1), note="n"),)
        if verdict is not Verdict.NEEDS_HUMAN else (),
        model_id="m", prompt_version="v1", prompt_hash="h" * 16,
        created_at=datetime.now(UTC),
    )


def test_critical_dismissal_below_floor_is_raised():
    result = apply_critical_floor(_finding(), _analysis(Verdict.FALSE_POSITIVE), score=10.0, floor=FLOOR)
    assert result.floored is True
    assert result.score == FLOOR


def test_critical_dismissal_above_floor_is_untouched():
    result = apply_critical_floor(_finding(), _analysis(Verdict.FALSE_POSITIVE), score=80.0, floor=FLOOR)
    assert result.floored is False
    assert result.score == 80.0


def test_non_critical_severity_is_never_floored():
    result = apply_critical_floor(_finding(Severity.HIGH), _analysis(Verdict.FALSE_POSITIVE), score=5.0, floor=FLOOR)
    assert result.floored is False
    assert result.score == 5.0


def test_true_positive_verdict_is_never_floored():
    """The floor guards against burial via dismissal, not a general boost."""
    result = apply_critical_floor(_finding(), _analysis(Verdict.TRUE_POSITIVE), score=5.0, floor=FLOOR)
    assert result.floored is False
    assert result.score == 5.0


def test_no_analysis_is_never_floored():
    result = apply_critical_floor(_finding(), None, score=5.0, floor=FLOOR)
    assert result.floored is False


def test_holds_property_reflects_floored_state():
    from sureshot.domain.enums import GuardHold

    floored = apply_critical_floor(_finding(), _analysis(Verdict.FALSE_POSITIVE), score=10.0, floor=FLOOR)
    untouched = apply_critical_floor(_finding(), _analysis(Verdict.TRUE_POSITIVE), score=10.0, floor=FLOOR)
    assert floored.holds == (GuardHold.POLICY,)
    assert untouched.holds == ()
