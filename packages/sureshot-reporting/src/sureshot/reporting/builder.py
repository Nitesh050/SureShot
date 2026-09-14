from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sureshot.domain.repository import RepositoryProfile
from sureshot.domain.scan import ScanState
from sureshot.engine.normalize.dedupe import DedupedIssue, dedupe
from sureshot.engine.pipeline.steps import PipelineResult


@dataclass(frozen=True)
class ReportData:
    """Writer-agnostic report contents. Every writer renders from this."""

    scan_id: str
    org_id: str
    project_id: str
    generated_at: datetime
    state: ScanState
    profile: RepositoryProfile
    issues: tuple[DedupedIssue, ...]

    @property
    def actionable_issues(self) -> tuple[DedupedIssue, ...]:
        return tuple(i for i in self.issues if i.primary.actionable)


def build_report(result: PipelineResult, generated_at: datetime | None = None) -> ReportData:
    """Deduplicate a pipeline result's findings and package them for reporting."""
    return ReportData(
        scan_id=result.state.scan_id,
        org_id=result.state.org_id,
        project_id=result.state.project_id,
        generated_at=generated_at or datetime.now(UTC),
        state=result.state,
        profile=result.profile,
        issues=dedupe(result.triaged),
    )
