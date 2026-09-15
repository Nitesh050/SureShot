from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecretRef, SecurityFinding
from sureshot.engine.context.snippet import Snippet, snippet_key
from sureshot.engine.guards.redaction import redact_snippets


def _secret_finding(path="config.py", line=3, kind="aws-access-key") -> SecurityFinding:
    return SecurityFinding(
        instance_id="in_secret", issue_id="is_secret",
        tool="trivy", tool_version="1.0", rule_id="aws-access-key-id",
        domain=Domain.SECRET, title="AWS access key", severity=Severity.CRITICAL,
        location=Location(file_path=path, line_start=line, line_end=line),
        secret=SecretRef(kind=kind, last_four="MNOP"),
    )


def _sast_finding(path="config.py", line=3) -> SecurityFinding:
    return SecurityFinding(
        instance_id="in_sast", issue_id="is_sast",
        tool="semgrep", tool_version="1.0", rule_id="python.hardcoded",
        domain=Domain.SAST, title="Hardcoded credential", severity=Severity.HIGH,
        cwe_ids=("CWE-798",),
        location=Location(file_path=path, line_start=line, line_end=line),
    )


def test_line_covered_by_secret_finding_is_replaced():
    finding = _secret_finding(line=3)
    key = snippet_key(finding.location)
    snippet = Snippet(
        matched="AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'",
        context="x = 1\ny = 2\nAWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\nz = 3",
        context_start=1,
    )
    out = redact_snippets((finding,), {key: snippet})
    assert "AKIAABCDEFGHIJKLMNOP" not in out[key].matched
    assert "AKIAABCDEFGHIJKLMNOP" not in out[key].context
    assert "<REDACTED:aws-access-key>" in out[key].matched


def test_secret_finding_redacts_neighboring_findings_context_too():
    """A SAST finding two lines away from a hardcoded key must not leak that
    key just because it fell inside the SAST finding's own context window."""
    secret = _secret_finding(line=3)
    sast = _sast_finding(line=5)
    sast_key = snippet_key(sast.location)
    sast_snippet = Snippet(
        matched="db.execute(query)",
        context="AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\nx = 1\ndb.execute(query)",
        context_start=3,
    )
    out = redact_snippets((secret, sast), {sast_key: sast_snippet})
    assert "AKIAABCDEFGHIJKLMNOP" not in out[sast_key].context


def test_line_outside_secret_range_is_untouched():
    """A snippet far from the secret's own line range, with nothing
    secret-shaped in it, is left alone."""
    secret = _secret_finding(line=3)
    far_away = _sast_finding(line=200)
    far_key = snippet_key(far_away.location)
    snippet = Snippet(matched="print('hello')", context="print('hello')", context_start=200)
    out = redact_snippets((secret, far_away), {far_key: snippet})
    assert out[far_key].matched == "print('hello')"


def test_no_secret_findings_still_applies_pattern_fallback():
    """A key that no scanner flagged (no Domain.SECRET finding at all) must
    still be caught by the provider-prefix pass."""
    sast = _sast_finding(line=1)
    key = snippet_key(sast.location)
    snippet = Snippet(
        matched="token = 'ghp_abcdefghijklmnopqrstuvwxyz012345'",
        context="token = 'ghp_abcdefghijklmnopqrstuvwxyz012345'",
        context_start=1,
    )
    out = redact_snippets((sast,), {key: snippet})
    assert "ghp_abcdefghijklmnopqrstuvwxyz012345" not in out[key].matched
    assert "<REDACTED:github-token>" in out[key].matched


def test_anthropic_and_slack_prefixes_are_caught():
    sast = _sast_finding(line=1)
    key = snippet_key(sast.location)
    snippet = Snippet(
        matched="a = 'sk-ant-api03-abcdefghijklmnopqrstuvwx'\nb = 'xoxb-1234567890-abcdefghij'",
        context="a = 'sk-ant-api03-abcdefghijklmnopqrstuvwx'\nb = 'xoxb-1234567890-abcdefghij'",
        context_start=1,
    )
    out = redact_snippets((sast,), {key: snippet})
    assert "sk-ant-" not in out[key].matched
    assert "xoxb-" not in out[key].matched


def test_high_entropy_fallback_catches_unlabeled_token():
    """A token with no known provider prefix at all, but random-looking
    enough to be a secret, is still redacted."""
    sast = _sast_finding(line=1)
    key = snippet_key(sast.location)
    random_looking = "Zx9qP2mK7wL4vR8tY1nJ6hF3bC5dS0gA"
    snippet = Snippet(
        matched=f"secret = '{random_looking}'",
        context=f"secret = '{random_looking}'",
        context_start=1,
    )
    out = redact_snippets((sast,), {key: snippet})
    assert random_looking not in out[key].matched
    assert "<REDACTED:high-entropy>" in out[key].matched


def test_ordinary_code_is_not_mangled():
    """Normal identifiers/words must survive — the entropy pass should not
    turn every long token in the codebase into noise."""
    sast = _sast_finding(line=1)
    key = snippet_key(sast.location)
    code = "def calculate_total_price_with_discount(base_price, discount_rate):"
    snippet = Snippet(matched=code, context=code, context_start=1)
    out = redact_snippets((sast,), {key: snippet})
    assert out[key].matched == code


def test_empty_snippet_is_left_empty():
    sast = _sast_finding(line=1)
    key = snippet_key(sast.location)
    snippet = Snippet(matched="", context="", context_start=1)
    out = redact_snippets((sast,), {key: snippet})
    assert out[key].matched == ""
    assert out[key].context == ""


def test_unrelated_file_is_not_affected_by_secret_in_another_file():
    secret = _secret_finding(path="config.py", line=3)
    other = _sast_finding(path="other.py", line=3)
    other_key = snippet_key(other.location)
    snippet = Snippet(matched="AKIAABCDEFGHIJKLMNOP", context="AKIAABCDEFGHIJKLMNOP", context_start=3)
    out = redact_snippets((secret, other), {other_key: snippet})
    # different file: the secret's line-range redaction doesn't apply, but
    # the pattern fallback still catches this AWS-shaped token on its own.
    assert "AKIAABCDEFGHIJKLMNOP" not in out[other_key].matched
