from __future__ import annotations

from dataclasses import dataclass

from sureshot.domain.enums import Domain
from sureshot.domain.finding import SecurityFinding
from sureshot.domain.result import TriagedFinding

_SAST_LINE_PROXIMITY = 3


@dataclass(frozen=True)
class DedupedIssue:
    """One underlying issue, possibly flagged by more than one tool or line."""

    issue_id: str
    primary: TriagedFinding
    duplicates: tuple[TriagedFinding, ...]
    tools: tuple[str, ...]

    @property
    def occurrences(self) -> int:
        return 1 + len(self.duplicates)

    @property
    def confirmed_by_multiple_tools(self) -> bool:
        return len(self.tools) > 1


def _sast_correlates(a: SecurityFinding, b: SecurityFinding) -> bool:
    """Whether two SAST findings look like the same underlying issue even
    though their exact issue_id differs.

    issue_id can't be the whole story for SAST: it's computed from one
    finding at a time, keyed partly on cwe_ids[0], and two tools routinely
    disagree on which CWE a given rule maps to — a real case verified against
    live scanner output: Semgrep tagged a SQL injection rule CWE-704 where
    CodeQL tagged the identical bug CWE-89. Requiring CWE overlap to confirm
    a correlation would reject exactly that case, since the disagreement is
    in the tools' input classification, not something a hash function can
    reconcile. So CWE is not used here at all: same file and a tight line
    window (tools anchor a multi-line statement to different sub-expressions,
    rarely the exact same line) is the correlating signal. The window is
    deliberately small — wide enough to absorb that anchoring difference,
    tight enough that two unrelated findings sharing a busy function are
    unlikely to fall inside it.
    """
    if a.domain is not Domain.SAST or b.domain is not Domain.SAST:
        return False
    if a.location.file_path != b.location.file_path:
        return False
    return abs(a.location.line_start - b.location.line_start) <= _SAST_LINE_PROXIMITY


def _groups_correlate(a: list[TriagedFinding], b: list[TriagedFinding]) -> bool:
    return any(_sast_correlates(x.finding, y.finding) for x in a for y in b)


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
    changed = True
    while changed:
        changed = False
        for i in range(len(merged)):
            for j in range(i + 1, len(merged)):
                if _groups_correlate(merged[i], merged[j]):
                    merged[i].extend(merged[j])
                    del merged[j]
                    changed = True
                    break
            if changed:
                break

    issues = []
    for group in merged:
        ordered = sorted(
            group, key=lambda t: (-t.score, t.finding.tool, t.finding.instance_id)
        )
        tools = tuple(sorted({t.finding.tool for t in group}))
        issues.append(DedupedIssue(
            issue_id=ordered[0].finding.issue_id,
            primary=ordered[0],
            duplicates=tuple(ordered[1:]),
            tools=tools,
        ))

    return tuple(sorted(issues, key=lambda i: (-i.primary.score, i.issue_id)))
