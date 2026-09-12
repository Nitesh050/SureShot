from pathlib import Path

import pytest

from sureshot.domain.enums import Domain, GuardHold, Severity, Verdict
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.context.snippet import Snippet
from sureshot.engine.intelligence.llm.budget import BudgetExceeded, TokenBudget
from sureshot.engine.intelligence.llm.cache import TriageCache
from sureshot.engine.intelligence.llm.client import LLMError, ModelReply
from sureshot.engine.intelligence.llm.triage import TriageEngine

VALID = """{"verdict": "true_positive", "reachability": "untrusted_input",
"confidence": 0.9, "rationale": "concatenated user input",
"citations": [{"line_start": 7, "line_end": 7, "note": "concatenation"}]}"""

DISMISSAL = """{"verdict": "false_positive", "reachability": "not_reachable",
"confidence": 0.9, "rationale": "test fixture",
"citations": [{"line_start": 7, "line_end": 7, "note": "hardcoded literal"}]}"""


class FakeClient:
    model_id = "fake-model"

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.calls = 0

    def complete(self, prompt: str, max_tokens: int = 1024) -> ModelReply:
        self.calls += 1
        text = self.replies[min(self.calls - 1, len(self.replies) - 1)]
        return ModelReply(text=text, input_tokens=100, output_tokens=50)


def _finding(path="app.py", line=7) -> SecurityFinding:
    return SecurityFinding(
        instance_id=f"in_{path}_{line}", issue_id="is_1",
        tool="semgrep", tool_version="1.0", rule_id="python.sqli",
        domain=Domain.SAST, title="Sqli", description="SQL injection",
        severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=line, line_end=line),
    )


def _snippet(text="query = 'SELECT ' + name") -> Snippet:
    return Snippet(matched=text, context=text, context_start=7)


def _engine(client, **kwargs) -> TriageEngine:
    return TriageEngine(client=client, **kwargs)


def test_produces_analysis(tmp_path: Path):
    analysis = _engine(FakeClient(VALID)).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.TRUE_POSITIVE
    assert analysis.instance_id == _finding().instance_id


def test_provenance_is_recorded():
    analysis = _engine(FakeClient(VALID)).triage(_finding(), _snippet())
    assert analysis.model_id == "fake-model"
    assert analysis.prompt_version == "triage.v3"
    assert len(analysis.prompt_hash) == 16


def test_cache_prevents_second_call():
    client = FakeClient(VALID)
    engine = _engine(client, cache=TriageCache())
    engine.triage(_finding(), _snippet())
    engine.triage(_finding(), _snippet())
    assert client.calls == 1


def test_cache_misses_on_different_finding():
    client = FakeClient(VALID)
    engine = _engine(client, cache=TriageCache())
    engine.triage(_finding(line=7), _snippet())
    engine.triage(_finding(line=99), _snippet())
    assert client.calls == 2


def test_citation_outside_file_is_held():
    bad = """{"verdict": "false_positive", "reachability": "not_reachable",
    "confidence": 0.9, "rationale": "safe",
    "citations": [{"line_start": 900, "line_end": 900, "note": "guard"}]}"""
    analysis = _engine(FakeClient(bad)).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.NEEDS_HUMAN
    assert GuardHold.EVIDENCE in analysis.guard_holds


def test_citation_within_context_window_is_accepted():
    analysis = _engine(FakeClient(VALID)).triage(_finding(), _snippet())
    assert analysis.guard_holds == ()


def test_unparseable_reply_is_held_not_raised():
    analysis = _engine(FakeClient("I cannot determine this")).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.NEEDS_HUMAN


def test_contradictory_reply_is_held():
    contradiction = """{"verdict": "false_positive", "reachability": "untrusted_input",
    "confidence": 0.9, "rationale": "fine",
    "citations": [{"line_start": 7, "line_end": 7, "note": "x"}]}"""
    analysis = _engine(FakeClient(contradiction)).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.NEEDS_HUMAN


def test_retry_on_first_bad_reply():
    client = FakeClient("garbage", VALID)
    analysis = _engine(client, max_retries=1).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.TRUE_POSITIVE
    assert client.calls == 2


def test_missing_snippet_is_held_without_calling_model():
    client = FakeClient(VALID)
    analysis = _engine(client).triage(_finding(), Snippet(matched="", context="", context_start=1))
    assert analysis.verdict is Verdict.NEEDS_HUMAN
    assert client.calls == 0


def test_budget_exhaustion_holds_remaining():
    budget = TokenBudget(max_input_tokens=150)
    engine = _engine(FakeClient(VALID), budget=budget)
    engine.triage(_finding(line=7), _snippet())
    analysis = engine.triage(_finding(line=8), _snippet())
    assert GuardHold.BUDGET in analysis.guard_holds


def test_budget_tracks_spend():
    budget = TokenBudget(max_input_tokens=10_000)
    engine = _engine(FakeClient(VALID), budget=budget)
    engine.triage(_finding(), _snippet())
    assert budget.spent_input == 100


def test_batch_preserves_order():
    findings = tuple(_finding(line=i) for i in range(7, 12))
    snippets = {f.instance_id: _snippet() for f in findings}
    results = _engine(FakeClient(VALID)).triage_batch(findings, snippets)
    assert [a.instance_id for a in results] == [f.instance_id for f in findings]


def test_client_failure_is_held_not_fatal():
    class Broken:
        model_id = "broken"
        def complete(self, prompt, max_tokens=1024):
            raise LLMError("upstream 529")

    analysis = _engine(Broken()).triage(_finding(), _snippet())
    assert analysis.verdict is Verdict.NEEDS_HUMAN