from __future__ import annotations

import math
import re
from collections import Counter

from sureshot.domain.enums import Domain
from sureshot.domain.finding import SecurityFinding
from sureshot.engine.context.snippet import Snippet, SnippetKey

# Provider-prefixed secret formats. This is a fallback behind this scan's own
# Domain.SECRET findings, not a replacement for them — it catches a real
# secret sitting on a line that got flagged for something else (e.g. inside
# an unrelated SAST finding's context window) or that no scanner caught.
_PROVIDER_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "anthropic-key": re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    "slack-token": re.compile(r"\bxoxb-[A-Za-z0-9\-]{10,}\b"),
}

# A second, format-agnostic fallback: any long alphanumeric-ish run with high
# Shannon entropy looks more like a key/token than a normal identifier or
# word, regardless of which provider (or no provider at all) it came from.
_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}")
_ENTROPY_THRESHOLD = 4.0


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _redact_line(line: str) -> str:
    for kind, pattern in _PROVIDER_PATTERNS.items():
        line = pattern.sub(f"<REDACTED:{kind}>", line)

    def _maybe_entropy(match: re.Match[str]) -> str:
        token = match.group(0)
        return "<REDACTED:high-entropy>" if _shannon_entropy(token) >= _ENTROPY_THRESHOLD else token

    return _CANDIDATE_TOKEN.sub(_maybe_entropy, line)


def _secret_ranges_by_file(
    findings: tuple[SecurityFinding, ...],
) -> dict[str, list[tuple[int, int, str]]]:
    ranges: dict[str, list[tuple[int, int, str]]] = {}
    for finding in findings:
        if finding.domain is not Domain.SECRET or finding.secret is None:
            continue
        ranges.setdefault(finding.location.file_path, []).append(
            (finding.location.line_start, finding.location.line_end, finding.secret.kind)
        )
    return ranges


def _redact_block(text: str, start_line: int, ranges: list[tuple[int, int, str]]) -> str:
    if not text:
        return text
    lines = text.splitlines()
    for i, line in enumerate(lines):
        lineno = start_line + i
        hit = next((kind for s, e, kind in ranges if s <= lineno <= e), None)
        lines[i] = f"<REDACTED:{hit}>" if hit else _redact_line(line)
    return "\n".join(lines)


def redact_snippets(
    findings: tuple[SecurityFinding, ...],
    snippets: dict[SnippetKey, Snippet],
) -> dict[SnippetKey, Snippet]:
    """Strip secret material out of every snippet before any of them can
    reach an LLM prompt.

    Two passes, deliberately overlapping in coverage:
    1. Exact — any line this scan's own Domain.SECRET findings cover is
       replaced outright with `<REDACTED:kind>`, using the kind this scan
       already determined (aws-access-key, etc). This applies to every
       snippet whose context window overlaps that line, not just the
       secret finding's own snippet — a SAST finding two lines away from a
       hardcoded key would otherwise still show that key in its context.
    2. Fallback — every remaining line is scanned for known provider-key
       prefixes and high-entropy tokens, in case a secret sits on a line no
       scanner flagged as Domain.SECRET at all.

    Must run after fingerprinting: SecurityFinding.instance_id/issue_id are
    computed from finding metadata, not snippet text (see
    normalize/fingerprint.py), so rewriting snippet content here has no
    effect on fingerprint stability.
    """
    ranges_by_file = _secret_ranges_by_file(findings)
    redacted: dict[SnippetKey, Snippet] = {}

    for key, snippet in snippets.items():
        file_path = key[0]
        matched_start = key[1]
        ranges = ranges_by_file.get(file_path, [])
        redacted[key] = Snippet(
            matched=_redact_block(snippet.matched, matched_start, ranges),
            context=_redact_block(snippet.context, snippet.context_start, ranges),
            context_start=snippet.context_start,
            truncated=snippet.truncated,
        )

    return redacted
