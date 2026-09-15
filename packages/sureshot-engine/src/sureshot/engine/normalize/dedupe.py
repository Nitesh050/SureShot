from __future__ import annotations

from dataclasses import dataclass

from sureshot.domain.enums import Domain
from sureshot.domain.finding import SecurityFinding
from sureshot.domain.result import TriagedFinding
from sureshot.engine.normalize.cwe_relations import related

_SAST_LINE_PROXIMITY = 3


@dataclass(frozen=True)
class DedupedIssue:
    """One underlying issue, possibly flagged by more than one tool or line."""

    issue_id: str
    primary: TriagedFinding
    duplicates: tuple[TriagedFinding, ...]
    tools: tuple[str, ...]
    correlation_reason: str = ""

    @property
    def occurrences(self) -> int:
        return 1 + len(self.duplicates)

    @property
    def confirmed_by_multiple_tools(self) -> bool:
        return len(self.tools) > 1


def _sast_correlates(a: SecurityFinding, b: SecurityFinding) -> str | None:
    """Whether two SAST findings look like the same underlying issue even
    though their exact issue_id differs. Returns a human-readable reason if
    so, else None.

    issue_id can't be the whole story for SAST: it's computed from one
    finding at a time, keyed partly on cwe_ids[0], and two tools routinely
    disagree on which CWE a given rule maps to — a real case verified against
    live scanner output: Semgrep tagged a SQL injection rule CWE-704 where
    CodeQL tagged the identical bug CWE-89. Rejecting cross-tool correlation
    whenever CWEs differ would reject exactly that case. But CWE isn't
    dropped entirely either: a CWE *relationship* check (see
    cwe_relations.py — CWE-704 is an ancestor of CWE-89) still requires the
    two tags plausibly describe the same weakness, so two unrelated bugs that
    happen to land nearby (e.g. CWE-89 SQL injection next to CWE-79 XSS) do
    not get folded together just for being close.

    Restricted to different tools: two findings from the *same* tool nearby
    each other are not corroboration of one issue, they're two separate
    findings that tool chose to raise — proximity between them is coincidence,
    not signal.
    """
    if a.domain is not Domain.SAST or b.domain is not Domain.SAST:
        return None
    if a.tool == b.tool:
        return None
    if a.location.file_path != b.location.file_path:
        return None
    distance = abs(a.location.line_start - b.location.line_start)
    if distance > _SAST_LINE_PROXIMITY:
        return None
    if not related(a.cwe_ids, b.cwe_ids):
        return None
    return f"cwe-related findings from {a.tool} and {b.tool} within {distance} line(s)"


def _groups_correlate(a: list[TriagedFinding], b: list[TriagedFinding]) -> str | None:
    for x in a:
        for y in b:
            reason = _sast_correlates(x.finding, y.finding)
            if reason:
                return reason
    return None


def dedupe(findings: tuple[TriagedFinding, ...]) -> tuple[DedupedIssue, ...]:
    """Collapse findings that represent the same underlying issue.

    Two passes. First, exact issue_id — reliable on its own for SCA (keyed
    on package + CVE) and SECRET (keyed on location + secret kind), and for
    the same tool re-flagging its own rule. Second, a SAST-only correlation
    pass (see _sast_correlates) that catches cross-tool agreement the first
    pass can't, because it requires comparing findings to each other rather
    than hashing each one in isolation.
    """
    groups: dict[str, list[TriagedFinding]] = {}
    order: list[str] = []
    for triaged in findings:
        key = triaged.finding.issue_id
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(triaged)

    merged: list[list[TriagedFinding]] = [groups[key] for key in order]
    reasons: list[str] = ["" for _ in merged]
    changed = True
    while changed:
        changed = False
        for i in range(len(merged)):
            for j in range(i + 1, len(merged)):
                reason = _groups_correlate(merged[i], merged[j])
                if reason:
                    merged[i].extend(merged[j])
                    del merged[j]
                    if not reasons[i]:
                        reasons[i] = reason
                    del reasons[j]
                    changed = True
                    break
            if changed:
                break

    issues = []
    for group, reason in zip(merged, reasons):
        ordered = sorted(
            group, key=lambda t: (-t.score, t.finding.tool, t.finding.instance_id)
        )
        tools = tuple(sorted({t.finding.tool for t in group}))
        issues.append(DedupedIssue(
            issue_id=ordered[0].finding.issue_id,
            primary=ordered[0],
            duplicates=tuple(ordered[1:]),
            correlation_reason=reason,
            tools=tools,
        ))

    return tuple(sorted(issues, key=lambda i: (-i.primary.score, i.issue_id)))
