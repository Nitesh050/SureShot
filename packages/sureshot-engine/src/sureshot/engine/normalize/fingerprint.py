from __future__ import annotations

import hashlib
import re
from typing import Mapping

from sureshot.domain.enums import Domain
from sureshot.domain.finding import SecurityFinding
from sureshot.engine.context.snippet import Snippet, SnippetKey, snippet_key

_ID_LENGTH = 32

_COMMENT_PATTERNS = (
    re.compile(r"//[^\n]*"),
    re.compile(r"#[^\n]*"),
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"<!--.*?-->", re.DOTALL),
)

_STRING_PATTERN = re.compile(
    r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""",
    re.DOTALL,
)

_WHITESPACE = re.compile(r"\s+")
_PUNCT_SPACING = re.compile(r"\s*([(){}\[\];,])\s*")


def _digest(*parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()[:_ID_LENGTH]


def normalize_snippet(snippet: str) -> str:
    """Reduce a code snippet to a form stable under formatting changes."""
    literals: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        literals.append(match.group(0))
        return f"\x00{len(literals) - 1}\x00"

    protected = _STRING_PATTERN.sub(_stash, snippet)

    for pattern in _COMMENT_PATTERNS:
        protected = pattern.sub(" ", protected)

    collapsed = _WHITESPACE.sub(" ", protected).strip()
    collapsed = _PUNCT_SPACING.sub(r"\1", collapsed)

    for index, literal in enumerate(literals):
        collapsed = collapsed.replace(f"\x00{index}\x00", literal)

    return collapsed


def snippet_hash(snippet: str) -> str:
    return _digest(normalize_snippet(snippet))


def compute_instance_id(finding: SecurityFinding, snippet: str | None) -> str:
    """Identify this specific occurrence. Cache key and analysis join key."""
    anchor = (
        snippet_hash(snippet)
        if snippet
        else f"line:{finding.location.line_start}"
    )
    return _digest(
        "instance",
        finding.tool,
        finding.rule_id,
        finding.location.file_path,
        anchor,
    )


def compute_issue_id(finding: SecurityFinding) -> str:
    """Identify the underlying problem. Reconciliation key across scans and tools."""
    if finding.domain is Domain.SCA and finding.package is not None:
        return _digest(
            "issue",
            Domain.SCA.value,
            finding.package.name,
            finding.cve_id or finding.rule_id,
        )

    if finding.domain is Domain.SECRET and finding.secret is not None:
        return _digest(
            "issue",
            Domain.SECRET.value,
            finding.location.file_path,
            finding.secret.kind,
            finding.secret.last_four,
        )

    classifier = finding.cwe_ids[0] if finding.cwe_ids else f"rule:{finding.rule_id}"
    return _digest(
        "issue",
        finding.domain.value,
        finding.location.file_path,
        classifier,
    )


def compute_content_signature(finding: SecurityFinding, snippet: str | None) -> str | None:
    """Identify a finding by its flagged code content alone, deliberately
    excluding file_path — the one axis compute_issue_id treats as load-
    bearing identity (a SAST/SECRET finding's issue_id changes on rename,
    verified against real GitHub alert behavior in this project). Used only
    for rename detection during reconciliation: when a finding's issue_id
    doesn't match anything in a baseline, this lets a reconciler recognize
    "this is the same finding, it just moved" instead of treating a plain
    git mv as one fixed issue plus one new one — which would silently wipe
    any prior triage disposition on that finding.

    None when there's no snippet to hash — a finding with no available
    source (SCA findings aren't tied to a meaningful code snippet at all)
    has no content signature and can't participate in rename matching, but
    also doesn't need to: compute_issue_id already keys SCA on package
    identity rather than location, so it's already rename-proof.
    """
    if not snippet:
        return None
    return _digest("content", finding.tool, finding.rule_id, normalize_snippet(snippet))


def apply_fingerprints(
    findings: tuple[SecurityFinding, ...],
    snippets: Mapping[SnippetKey, Snippet],
) -> tuple[SecurityFinding, ...]:
    out = []
    for finding in findings:
        snippet = snippets.get(snippet_key(finding.location))
        out.append(finding.model_copy(update={
            "instance_id": compute_instance_id(
                finding, snippet.matched if snippet and snippet.matched else None
            ),
            "issue_id": compute_issue_id(finding),
        }))
    return tuple(out)