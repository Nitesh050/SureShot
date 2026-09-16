from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from sureshot.domain.finding import SecurityFinding
from sureshot.engine.context.snippet import Snippet, SnippetKey, snippet_key
from sureshot.engine.normalize.fingerprint import compute_content_signature


@dataclass(frozen=True)
class Baseline:
    """A prior scan's issues, reduced to what reconciliation needs.

    issue_ids is the primary key: which issue_ids existed. Keying on
    issue_id (not instance_id) means a finding that shifted lines or got
    re-flagged by a different tool still reconciles as the same issue,
    matching fingerprint.compute_issue_id's intent.

    content_signatures is a secondary index, issue_id -> content signature,
    populated only where a snippet was available at baseline time. It exists
    solely so reconcile() can recognize a rename: an issue_id that vanished
    from the current scan but whose flagged code content reappears under a
    *different* issue_id (because compute_issue_id includes file_path) is
    the same finding, not a fix-plus-new pair.
    """

    scan_id: str
    issue_ids: frozenset[str]
    content_signatures: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_findings(
        scan_id: str,
        findings: tuple[SecurityFinding, ...],
        snippets: Mapping[SnippetKey, Snippet] | None = None,
    ) -> Baseline:
        snippets = snippets or {}
        signatures: dict[str, str] = {}
        for finding in findings:
            if not finding.issue_id:
                continue
            snippet = snippets.get(snippet_key(finding.location))
            signature = compute_content_signature(
                finding, snippet.matched if snippet and snippet.matched else None
            )
            if signature:
                signatures[finding.issue_id] = signature

        return Baseline(
            scan_id=scan_id,
            issue_ids=frozenset(f.issue_id for f in findings if f.issue_id),
            content_signatures=signatures,
        )
