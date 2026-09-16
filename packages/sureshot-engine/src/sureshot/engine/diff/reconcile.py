from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from sureshot.domain.finding import SecurityFinding
from sureshot.engine.context.snippet import Snippet, SnippetKey, snippet_key
from sureshot.engine.diff.baseline import Baseline
from sureshot.engine.normalize.fingerprint import compute_content_signature


@dataclass(frozen=True)
class RenameMatch:
    """A current-scan finding whose issue_id doesn't match the baseline, but
    whose flagged code content does — recognized as the same finding having
    moved (a rename, a directory reorganization) rather than one issue being
    fixed and an unrelated one appearing new."""

    finding: SecurityFinding
    previous_issue_id: str


@dataclass(frozen=True)
class ReconciliationResult:
    new: tuple[SecurityFinding, ...]
    persisting: tuple[SecurityFinding, ...]
    renamed: tuple[RenameMatch, ...]
    fixed_issue_ids: frozenset[str]

    @property
    def regressed(self) -> bool:
        """True when this scan introduced findings a prior scan didn't have.

        A rename is not a regression — carried_state_map exists precisely so
        a caller treats it as the continuation of an existing finding.
        """
        return len(self.new) > 0

    @property
    def carried_state_map(self) -> dict[str, str]:
        """new issue_id -> previous issue_id, for every recognized rename.

        Whatever triage/dismissal state a caller has stored against the
        previous issue_id (persistence for that state doesn't exist yet in
        this codebase — see sureshot-persistence — but this is the join key
        it will need) should be copied to the new issue_id rather than left
        to start over as an untriaged finding.
        """
        return {
            match.finding.issue_id: match.previous_issue_id
            for match in self.renamed
            if match.finding.issue_id
        }


def reconcile(
    current: tuple[SecurityFinding, ...],
    baseline: Baseline | None,
    current_snippets: Mapping[SnippetKey, Snippet] | None = None,
) -> ReconciliationResult:
    """Classify this scan's findings against a prior scan's baseline.

    With no baseline (first scan, or none supplied), everything is new —
    there is nothing to compare against yet.

    Three passes:
    1. Exact issue_id match — the common case, unchanged from before.
    2. Whatever's left in the baseline (issue_ids present before but not
       now) and whatever's left in current (issue_ids new) are compared by
       content signature (see compute_content_signature / Baseline). A match
       means the same flagged code reappeared under a new issue_id — almost
       always because file_path changed, which compute_issue_id treats as
       identity-affecting by design. That's a rename, not a fix-plus-new.
    3. Whatever's still unmatched after that is genuinely new or genuinely
       fixed.
    """
    if baseline is None:
        return ReconciliationResult(
            new=current, persisting=(), renamed=(), fixed_issue_ids=frozenset()
        )

    exact_new = tuple(f for f in current if f.issue_id not in baseline.issue_ids)
    persisting = tuple(f for f in current if f.issue_id in baseline.issue_ids)
    current_ids = {f.issue_id for f in current if f.issue_id}
    disappeared = baseline.issue_ids - current_ids

    disappeared_by_signature = {
        signature: issue_id
        for issue_id, signature in baseline.content_signatures.items()
        if issue_id in disappeared
    }

    current_snippets = current_snippets or {}
    renamed: list[RenameMatch] = []
    still_new: list[SecurityFinding] = []
    claimed_signatures: set[str] = set()

    for finding in exact_new:
        snippet = current_snippets.get(snippet_key(finding.location))
        signature = compute_content_signature(
            finding, snippet.matched if snippet and snippet.matched else None
        )
        previous_issue_id = (
            disappeared_by_signature.get(signature)
            if signature and signature not in claimed_signatures
            else None
        )
        if previous_issue_id:
            renamed.append(RenameMatch(finding=finding, previous_issue_id=previous_issue_id))
            claimed_signatures.add(signature)
        else:
            still_new.append(finding)

    matched_previous_ids = {match.previous_issue_id for match in renamed}
    fixed_issue_ids = disappeared - matched_previous_ids

    return ReconciliationResult(
        new=tuple(still_new),
        persisting=persisting,
        renamed=tuple(renamed),
        fixed_issue_ids=fixed_issue_ids,
    )
