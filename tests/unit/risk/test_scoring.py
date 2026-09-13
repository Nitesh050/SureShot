from datetime import UTC, datetime

import pytest

from sureshot.domain.analysis import Evidence, SecurityAnalysis
from sureshot.domain.enums import Domain, GuardHold, Severity, Verdict
from sureshot.domain.finding import Location, Package, SecurityFinding
from sureshot.engine.risk.scoring import RiskPolicy, score_finding


POLICY = RiskPolicy.default()


def _finding(path="app/users.py", severity=Severity.HIGH, **overrides) -> SecurityFinding:
    base = dict(
        instance_id="in_1", issue_id="is_1",
        tool="semgrep", tool_version="1.0", rule_id="r", domain=Domain.SAST,
        title="t", severity=severity, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=1, line_end=1),
    )
    return SecurityFinding(**(base | overrides))


def _analysis(verdict=Verdict.TRUE_POSITIVE, confidence=0.9, **overrides) -> SecurityAnalysis:
    base = dict(
        analysis_id="an_1", instance_id="in_1", verdict=verdict,
        confidence=confidence, rationale="r",
        evidence=(Evidence(location=Location(file_path="app/users.py",
                                             line_start=1, line_end=1), note="n"),)
        if verdict is not Verdict.NEEDS_HUMAN else (),
        model_id="m", prompt_version="triage.v1", prompt_hash="h" * 16,
        created_at=datetime.now(UTC),
    )
    return SecurityAnalysis(**(base | overrides))


def test_score_is_bounded():
    result = score_finding(_finding(), _analysis(), POLICY)
    assert 0.0 <= result.score <= 100.0


def test_severity_dominates_ordering():
    critical = score_finding(_finding(severity=Severity.CRITICAL), _analysis(), POLICY)
    low = score_finding(_finding(severity=Severity.LOW), _analysis(), POLICY)
    assert critical.score > low.score


def test_test_path_lowers_score():
    prod = score_finding(_finding("app/users.py"), _analysis(), POLICY)
    test = score_finding(_finding("tests/test_users.py"), _analysis(), POLICY)
    assert test.score < prod.score


def test_dismissal_lowers_but_does_not_zero():
    kept = score_finding(_finding(), _analysis(Verdict.TRUE_POSITIVE), POLICY)
    dismissed = score_finding(_finding(), _analysis(Verdict.FALSE_POSITIVE), POLICY)
    assert 0 < dismissed.score < kept.score


def test_critical_dismissal_is_floored_by_policy():
    """A model may not bury a critical finding."""
    result = score_finding(
        _finding(severity=Severity.CRITICAL), _analysis(Verdict.FALSE_POSITIVE), POLICY
    )
    assert result.score >= POLICY.critical_floor
    assert GuardHold.POLICY in result.holds


def test_high_severity_dismissal_is_not_floored():
    result = score_finding(
        _finding(severity=Severity.HIGH), _analysis(Verdict.FALSE_POSITIVE), POLICY
    )
    assert result.holds == ()


def test_held_analysis_scores_above_a_dismissal():
    held = score_finding(_finding(), _analysis(Verdict.NEEDS_HUMAN, 0.0), POLICY)
    dismissed = score_finding(_finding(), _analysis(Verdict.FALSE_POSITIVE), POLICY)
    assert held.score > dismissed.score


def test_low_confidence_pulls_toward_neutral():
    """A confident dismissal is trusted; an unsure one stays closer to full risk."""
    confident = score_finding(
        _finding(), _analysis(Verdict.FALSE_POSITIVE, confidence=0.95), POLICY
    )
    unsure = score_finding(
        _finding(), _analysis(Verdict.FALSE_POSITIVE, confidence=0.5), POLICY
    )
    assert confident.score < unsure.score


def test_sca_with_fix_outranks_one_without():
    with_fix = _finding(domain=Domain.SCA, cve_id="CVE-1",
                        package=Package(name="a", installed_version="1", fixed_version="2"))
    without = _finding(domain=Domain.SCA, cve_id="CVE-2",
                       package=Package(name="b", installed_version="1"))
    assert score_finding(with_fix, _analysis(), POLICY).score > \
           score_finding(without, _analysis(), POLICY).score


def test_contributions_are_explainable():
    result = score_finding(_finding(), _analysis(), POLICY)
    assert "severity" in result.contributions
    assert "path_role" in result.contributions
    assert sum(abs(v) for v in result.contributions.values()) > 0


def test_policy_hash_is_stable():
    assert RiskPolicy.default().hash == RiskPolicy.default().hash


def test_policy_hash_changes_with_weights():
    tweaked = RiskPolicy.default().model_copy(update={"critical_floor": 90.0})
    assert tweaked.hash != RiskPolicy.default().hash


def test_ordering_is_deterministic():
    findings = [_finding(f"app/f{i}.py") for i in range(5)]
    first = [score_finding(f, _analysis(), POLICY).score for f in findings]
    second = [score_finding(f, _analysis(), POLICY).score for f in findings]
    assert first == second