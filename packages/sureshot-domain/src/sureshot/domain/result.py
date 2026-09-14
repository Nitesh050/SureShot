from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.enums import GuardHold, Verdict
from sureshot.domain.finding import SecurityFinding


class TriagedFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding: SecurityFinding
    analysis: SecurityAnalysis | None = None
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    contributions: dict[str, float] = Field(default_factory=dict)
    holds: tuple[GuardHold, ...] = ()

    @property
    def verdict(self) -> Verdict:
        return self.analysis.verdict if self.analysis else Verdict.NEEDS_HUMAN

    @property
    def actionable(self) -> bool:
        return self.verdict is not Verdict.FALSE_POSITIVE
