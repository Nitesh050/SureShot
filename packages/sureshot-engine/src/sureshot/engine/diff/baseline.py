from __future__ import annotations

from dataclasses import dataclass

from sureshot.domain.finding import SecurityFinding


@dataclass(frozen=True)
class Baseline:
    """A prior scan's issues, reduced to what reconciliation needs: which
    issue_ids existed. Keying on issue_id (not instance_id) means a finding
    that shifted lines or got re-flagged by a different tool still reconciles
    as the same issue, matching fingerprint.compute_issue_id's intent."""

    scan_id: str
    issue_ids: frozenset[str]

    @staticmethod
    def from_findings(scan_id: str, findings: tuple[SecurityFinding, ...]) -> Baseline:
        return Baseline(
            scan_id=scan_id,
            issue_ids=frozenset(f.issue_id for f in findings if f.issue_id),
        )
