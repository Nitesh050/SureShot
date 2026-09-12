import pytest
from pydantic import ValidationError

from sureshot.domain.enums import Verdict
from sureshot.engine.intelligence.llm.schemas import (
    Reachability,
    TriageCitation,
    TriageResponse,
    parse_triage_response,
)


def _payload(**overrides) -> dict:
    base = {
        "verdict": "true_positive",
        "reachability": "untrusted_input",
        "confidence": 0.9,
        "rationale": "username flows from the request into the query unparameterized",
        "citations": [{"line_start": 7, "line_end": 9, "note": "string concatenation"}],
        "impact": "an attacker can read arbitrary rows",
        "remediation": "use a parameterized query",
    }
    return base | overrides


def test_valid_response_parses():
    assert parse_triage_response(_payload()).verdict is Verdict.TRUE_POSITIVE


def test_json_fences_are_stripped():
    raw = "```json\n" + TriageResponse(**_payload()).model_dump_json() + "\n```"
    assert parse_triage_response(raw).verdict is Verdict.TRUE_POSITIVE


def test_preamble_before_json_is_tolerated():
    raw = 'Here is my analysis:\n{"verdict": "needs_human", "reachability": "unknown", ' \
          '"confidence": 0.3, "rationale": "insufficient context", "citations": []}'
    assert parse_triage_response(raw).verdict is Verdict.NEEDS_HUMAN


def test_unparseable_output_raises():
    with pytest.raises(ValueError, match="no JSON"):
        parse_triage_response("I'm not sure about this one, sorry.")


def test_decisive_verdict_requires_citation():
    with pytest.raises(ValidationError, match="citation"):
        TriageResponse(**_payload(citations=[]))


def test_needs_human_may_omit_citations():
    assert TriageResponse(**_payload(verdict="needs_human", citations=[])).citations == ()


def test_dismissal_claiming_untrusted_input_is_rejected():
    """A model cannot dismiss while asserting the input is attacker-controlled."""
    with pytest.raises(ValidationError, match="contradic"):
        TriageResponse(**_payload(verdict="false_positive", reachability="untrusted_input"))


def test_high_confidence_with_unknown_reachability_is_rejected():
    with pytest.raises(ValidationError, match="reachability"):
        TriageResponse(**_payload(reachability="unknown", confidence=0.95))


def test_reversed_citation_lines_rejected():
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(citations=[{"line_start": 9, "line_end": 7, "note": "x"}]))


def test_empty_rationale_rejected():
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(rationale="   "))


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(confidence=1.2))


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(severity_override="critical"))


def test_citation_count_capped():
    many = [{"line_start": i, "line_end": i, "note": "n"} for i in range(1, 30)]
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(citations=many))


def test_rationale_length_capped():
    with pytest.raises(ValidationError):
        TriageResponse(**_payload(rationale="x" * 5000))