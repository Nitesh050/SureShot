from __future__ import annotations

import json

from sureshot.engine.normalize.dedupe import DedupedIssue
from sureshot.reporting.builder import ReportData


def _issue_to_dict(issue: DedupedIssue) -> dict:
    primary = issue.primary
    return {
        "issue_id": issue.issue_id,
        "occurrences": issue.occurrences,
        "tools": list(issue.tools),
        "confirmed_by_multiple_tools": issue.confirmed_by_multiple_tools,
        "finding": primary.finding.model_dump(mode="json"),
        "analysis": primary.analysis.model_dump(mode="json") if primary.analysis else None,
        "score": primary.score,
        "contributions": primary.contributions,
        "holds": [h.value for h in primary.holds],
    }


def write(report: ReportData) -> str:
    payload = {
        "scan_id": report.scan_id,
        "org_id": report.org_id,
        "project_id": report.project_id,
        "generated_at": report.generated_at.isoformat(),
        "provenance": report.state.provenance.model_dump(mode="json"),
        "coverage": [c.model_dump(mode="json") for c in report.profile.coverage],
        "issues": [_issue_to_dict(i) for i in report.issues],
    }
    return json.dumps(payload, indent=2)
