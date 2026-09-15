"""Adversarial: plant a real-shaped secret in the code shown to the LLM, run
the pipeline's redact step ahead of triage, and prove the secret never
reaches the rendered prompt — the whole point of guards/redaction.py."""

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecretRef, SecurityFinding
from sureshot.engine.context.snippet import Snippet, snippet_key
from sureshot.engine.guards.redaction import redact_snippets
from sureshot.engine.intelligence.llm.client import ModelReply
from sureshot.engine.intelligence.llm.triage import TriageEngine

PLANTED_KEY = "AKIAABCDEFGHIJKLMNOP"

VALID = """{"verdict": "true_positive", "reachability": "untrusted_input",
"confidence": 0.9, "rationale": "hardcoded credential",
"citations": [{"line_start": 3, "line_end": 3, "note": "key assignment"}]}"""


class RecordingClient:
    """Captures every prompt it's asked to complete, standing in for the
    real network call an adversarial test must never make."""

    model_id = "recording"

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, prompt: str, max_tokens: int = 1024) -> ModelReply:
        self.prompts.append(prompt)
        return ModelReply(text=VALID, input_tokens=10, output_tokens=10)


def _secret_finding() -> SecurityFinding:
    return SecurityFinding(
        instance_id="in_secret", issue_id="is_secret",
        tool="trivy", tool_version="1.0", rule_id="aws-access-key-id",
        domain=Domain.SECRET, title="AWS access key", severity=Severity.CRITICAL,
        location=Location(file_path="config.py", line_start=3, line_end=3),
        secret=SecretRef(kind="aws-access-key", last_four=PLANTED_KEY[-4:]),
    )


def _sast_finding_near_secret() -> SecurityFinding:
    """A second, unrelated finding whose context window overlaps the
    planted key's line — the case that would leak it if redaction only
    touched the secret finding's own snippet."""
    return SecurityFinding(
        instance_id="in_sast", issue_id="is_sast",
        tool="semgrep", tool_version="1.0", rule_id="python.hardcoded-config",
        domain=Domain.SAST, title="Hardcoded config value", severity=Severity.MEDIUM,
        cwe_ids=("CWE-798",),
        location=Location(file_path="config.py", line_start=5, line_end=5),
    )


def _planted_source() -> str:
    return "\n".join([
        "import boto3",
        "",
        f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'",
        "",
        "client = boto3.client('s3')",
    ])


def test_planted_key_never_reaches_the_rendered_prompt():
    source = _planted_source()
    secret = _secret_finding()
    sast = _sast_finding_near_secret()

    secret_key = snippet_key(secret.location)
    sast_key = snippet_key(sast.location)
    lines = source.splitlines()

    snippets = {
        secret_key: Snippet(
            matched=lines[2], context="\n".join(lines[0:5]), context_start=1,
        ),
        sast_key: Snippet(
            matched=lines[4], context="\n".join(lines[0:5]), context_start=1,
        ),
    }

    # Sanity check: prove the fixture actually contains the raw key before
    # redaction, so a pass-through bug can't make this test pass vacuously.
    assert PLANTED_KEY in snippets[secret_key].context
    assert PLANTED_KEY in snippets[sast_key].context

    redacted = redact_snippets((secret, sast), snippets)

    client = RecordingClient()
    engine = TriageEngine(client=client)
    by_instance = {
        secret.instance_id: redacted[secret_key],
        sast.instance_id: redacted[sast_key],
    }
    engine.triage_batch((secret, sast), by_instance)

    assert client.prompts, "the fake client was never called"
    for prompt in client.prompts:
        assert PLANTED_KEY not in prompt


def test_redaction_leaves_triage_functional():
    """Redaction must not break triage itself — the model still gets
    something to reason about, just not the raw secret."""
    secret = _secret_finding()
    key = snippet_key(secret.location)
    snippet = Snippet(
        matched=f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'",
        context=f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'",
        context_start=3,
    )
    redacted = redact_snippets((secret,), {key: snippet})

    client = RecordingClient()
    engine = TriageEngine(client=client)
    analysis = engine.triage(secret, redacted[key])

    assert len(client.prompts) == 1
    assert analysis.rationale
    assert PLANTED_KEY not in client.prompts[0]
    assert "<REDACTED:aws-access-key>" in client.prompts[0]
