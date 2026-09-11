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