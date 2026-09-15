from datetime import UTC, datetime

from sureshot.domain.analysis import Evidence, SecurityAnalysis
from sureshot.domain.enums import GuardHold, Verdict
from sureshot.domain.finding import Location
from sureshot.engine.context.snippet import Snippet
from sureshot.engine.guards.evidence import citations_within_window, enforce_evidence_window


def _analysis(line_start=7, **overrides) -> SecurityAnalysis:
    base = dict(
        analysis_id="an_1", instance_id="in_1", verdict=Verdict.TRUE_POSITIVE,
        confidence=0.9, rationale="r",
        evidence=(Evidence(location=Location(file_path="a.py", line_start=line_start,
                                              line_end=line_start), note="n"),),
        model_id="m", prompt_version="v1", prompt_hash="h" * 16,
        created_at=datetime.now(UTC),
    )
    return SecurityAnalysis(**(base | overrides))


def _snippet(context="line1\nline2\nline3", context_start=5) -> Snippet:
    return Snippet(matched="line2", context=context, context_start=context_start)


def test_citation_inside_window_passes():
    assert citations_within_window(_analysis(line_start=6), _snippet()) is True


def test_citation_at_window_edges_passes():
    assert citations_within_window(_analysis(line_start=5), _snippet()) is True
    assert citations_within_window(_analysis(line_start=7), _snippet()) is True


def test_citation_outside_window_fails():
    assert citations_within_window(_analysis(line_start=900), _snippet()) is False


def test_no_evidence_trivially_passes():
    needs_human = _analysis(verdict=Verdict.NEEDS_HUMAN, evidence=())
    assert citations_within_window(needs_human, _snippet()) is True


def test_enforce_holds_out_of_window_citation():
    held = enforce_evidence_window(_analysis(line_start=900), _snippet())
    assert held.verdict is Verdict.NEEDS_HUMAN
    assert GuardHold.EVIDENCE in held.guard_holds


def test_enforce_leaves_in_window_citation_untouched():
    analysis = _analysis(line_start=6)
    result = enforce_evidence_window(analysis, _snippet())
    assert result is analysis
    assert result.guard_holds == ()
