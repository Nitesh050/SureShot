from __future__ import annotations

from dataclasses import dataclass

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.enums import GuardHold, Severity, Verdict
from sureshot.domain.finding import SecurityFinding


@dataclass(frozen=True)
class FloorResult:
    score: float
    floored: bool

    @property
    def holds(self) -> tuple[GuardHold, ...]:
        return (GuardHold.POLICY,) if self.floored else ()


def apply_critical_floor(
    finding: SecurityFinding,
    analysis: SecurityAnalysis | None,
    score: float,
    floor: float,
) -> FloorResult:
    """A model may not bury a CRITICAL finding below `floor` by dismissing it.

    This is a policy decision, not a risk signal: it doesn't matter how
    confident the dismissal was — a CRITICAL-severity finding a model has
    called a false positive still stays above the floor until a human signs
    off. Only CRITICAL severity plus an actual false_positive verdict
    triggers it; this is a backstop against burial, not a general severity
    boost, so a true_positive or needs_human verdict is untouched.
    """
    if (
        finding.severity is Severity.CRITICAL
        and analysis is not None
        and analysis.verdict is Verdict.FALSE_POSITIVE
        and score < floor
    ):
        return FloorResult(score=floor, floored=True)
    return FloorResult(score=score, floored=False)
