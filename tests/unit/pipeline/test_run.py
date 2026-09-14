from pathlib import Path

import pytest

from sureshot.domain.enums import StepStatus, Verdict
from sureshot.engine.intelligence.llm.client import LLMError, ModelReply
from sureshot.engine.pipeline.run import PipelineConfig, run_pipeline

VULNERABLE = '''\
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute(
        "SELECT * FROM users WHERE name = '" + username + "'"
    ).fetchall()
'''

KEEP = """{"verdict": "true_positive", "reachability": "untrusted_input",
"confidence": 0.9, "rationale": "concatenated input",
"citations": [{"line_start": 7, "line_end": 7, "note": "concatenation"}]}"""


class FakeClient:
    model_id = "fake"
    def __init__(self, reply=KEEP): self.reply = reply
    def complete(self, prompt, max_tokens=1024):
        return ModelReply(text=self.reply, input_tokens=50, output_tokens=20)


class BrokenClient:
    model_id = "broken"
    def complete(self, prompt, max_tokens=1024):
        raise LLMError("upstream down")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "users.py").write_text(VULNERABLE)
    return tmp_path


def test_pipeline_produces_scored_findings(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient()))
    assert result.findings
    assert all(f.risk.score > 0 for f in result.findings)


def test_findings_sorted_by_score_descending(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient()))
    scores = [f.risk.score for f in result.findings]
    assert scores == sorted(scores, reverse=True)


def test_every_finding_has_fingerprints(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient()))
    assert all(f.finding.instance_id and f.finding.issue_id for f in result.findings)


def test_triage_disabled_still_scores(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=None))
    assert result.findings
    assert all(f.analysis is None for f in result.findings)


def test_llm_outage_degrades_not_fails(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=BrokenClient()))
    assert result.findings
    assert all(f.analysis.verdict is Verdict.NEEDS_HUMAN for f in result.findings)


def test_steps_are_recorded_in_order(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient()))
    assert [s.step for s in result.state.steps] == [
        "profile", "scan", "fingerprint", "triage", "risk"
    ]


def test_provenance_captures_every_component(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient()))
    p = result.state.provenance
    assert p.tools and p.tools[0].name == "semgrep"
    assert p.model_id == "fake"
    assert "triage.v3" in p.prompt_versions
    assert p.risk_policy_hash


def test_empty_repository_completes_cleanly(tmp_path: Path):
    (tmp_path / "README.md").write_text("nothing here")
    result = run_pipeline(tmp_path, PipelineConfig(client=FakeClient()))
    assert result.findings == ()
    assert result.state.degraded is False


def test_coverage_gaps_are_reported(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "requirements.txt").write_text("flask")
    result = run_pipeline(tmp_path, PipelineConfig(client=FakeClient()))
    assert any("lockfile" in n.reason for n in result.profile.coverage)


def test_max_triage_caps_model_calls(repo: Path):
    client = FakeClient()
    calls = []
    original = client.complete
    client.complete = lambda *a, **k: (calls.append(1), original(*a, **k))[1]
    run_pipeline(repo, PipelineConfig(client=client, max_triage=1))
    assert len(calls) <= 1


def test_untriaged_findings_still_appear(repo: Path):
    result = run_pipeline(repo, PipelineConfig(client=FakeClient(), max_triage=0))
    assert result.findings
    assert all(f.analysis is None for f in result.findings)
