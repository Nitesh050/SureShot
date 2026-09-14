from __future__ import annotations

from sureshot.domain.enums import Domain, Severity
from sureshot.engine.normalize.dedupe import DedupedIssue


def group_by_domain(issues: tuple[DedupedIssue, ...]) -> dict[Domain, tuple[DedupedIssue, ...]]:
    return _group(issues, key=lambda i: i.primary.finding.domain)


def group_by_severity(issues: tuple[DedupedIssue, ...]) -> dict[Severity, tuple[DedupedIssue, ...]]:
    return _group(issues, key=lambda i: i.primary.finding.severity)


def group_by_file(issues: tuple[DedupedIssue, ...]) -> dict[str, tuple[DedupedIssue, ...]]:
    return _group(issues, key=lambda i: i.primary.finding.location.file_path)


def _group(issues, key):
    buckets: dict = {}
    for issue in issues:
        buckets.setdefault(key(issue), []).append(issue)
    return {k: tuple(v) for k, v in buckets.items()}
