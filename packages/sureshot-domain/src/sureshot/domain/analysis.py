from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sureshot.domain.enums import GuardHold, Verdict
from sureshot.domain.finding import Location


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    location: Location
    note: str = Field(min_length=1)


class SecurityAnalysis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    analysis_id: str
    instance_id: str

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1)
    evidence: tuple[Evidence, ...] = ()

    impact: str = ""
    remediation: str = ""

    model_id: str
    prompt_version: str
    prompt_hash: str

    guard_holds: tuple[GuardHold, ...] = ()
    created_at: datetime

    _aware = field_validator("created_at")(_require_aware)

    @model_validator(mode="after")
    def _guard_holds_force_review(self) -> SecurityAnalysis:
        if self.guard_holds and self.verdict is not Verdict.NEEDS_HUMAN:
            raise ValueError(
                "a held analysis must have verdict needs_human; "
                f"got {self.verdict} with holds {self.guard_holds}"
            )
        return self

    @model_validator(mode="after")
    def _decisive_verdicts_need_evidence(self) -> SecurityAnalysis:
        decisive = (Verdict.TRUE_POSITIVE, Verdict.FALSE_POSITIVE)
        if self.verdict in decisive and not self.evidence:
            raise ValueError(f"{self.verdict} requires at least one evidence citation")
        return self

    def held(self, hold: GuardHold) -> SecurityAnalysis:
        if hold in self.guard_holds:
            return self
        return self.model_copy(
            update={
                "verdict": Verdict.NEEDS_HUMAN,
                "guard_holds": self.guard_holds + (hold,),
            }
        )