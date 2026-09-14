from __future__ import annotations

from dataclasses import dataclass

from sureshot.domain.finding import SecurityFinding
from sureshot.engine.diff.baseline import Baseline


@dataclass(frozen=True)
class ReconciliationResult:
    new: tuple[SecurityFinding, ...]
    persisting: tuple[SecurityFinding, ...]
    fixed_issue_ids: frozenset[str]

    @property
    def regressed(self) -> bool:
        """True when this scan introduced findings a prior scan didn't have."""
        return len(self.new) > 0


def reconcile(
    current: tuple[SecurityFinding, ...],
    baseline: Baseline | None,
) -> ReconciliationResult:
    """Classify this scan's findings against a prior scan's baseline.

    With no baseline (first scan, or none supplied), everything is new —
    there is nothing to compare against yet.
    """
    if baseline is None:
        return ReconciliationResult(new=current, persisting=(), fixed_issue_ids=frozenset())

    new = tuple(f for f in current if f.issue_id not in baseline.issue_ids)
    persisting = tuple(f for f in current if f.issue_id in baseline.issue_ids)
    current_ids = {f.issue_id for f in current if f.issue_id}
    fixed_issue_ids = baseline.issue_ids - current_ids

    return ReconciliationResult(new=new, persisting=persisting, fixed_issue_ids=fixed_issue_ids)
