from __future__ import annotations

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.enums import GuardHold
from sureshot.engine.context.snippet import Snippet


def citations_within_window(analysis: SecurityAnalysis, snippet: Snippet) -> bool:
    """Whether every line an analysis cites as evidence falls inside the
    source the model was actually shown. A citation outside that window
    means the model is reasoning about code it never saw — hallucinated
    evidence rather than a grounded verdict. An analysis with no citations
    (e.g. NEEDS_HUMAN) trivially passes; it isn't making an evidence claim.
    """
    if not analysis.evidence:
        return True
    lower = snippet.context_start
    upper = lower + len(snippet.context.splitlines()) - 1
    return all(lower <= e.location.line_start <= upper for e in analysis.evidence)


def enforce_evidence_window(analysis: SecurityAnalysis, snippet: Snippet) -> SecurityAnalysis:
    """Hold an analysis whose citations point outside the shown source."""
    if citations_within_window(analysis, snippet):
        return analysis
    return analysis.held(GuardHold.EVIDENCE)
