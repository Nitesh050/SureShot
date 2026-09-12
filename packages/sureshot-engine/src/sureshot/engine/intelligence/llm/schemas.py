from __future__ import annotations

import json
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sureshot.domain.enums import Verdict

_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)
_HIGH_CONFIDENCE = 0.85


class Reachability(StrEnum):
    UNTRUSTED_INPUT = "untrusted_input"
    INTERNAL_ONLY = "internal_only"
    NOT_REACHABLE = "not_reachable"
    UNKNOWN = "unknown"


class TriageCitation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    note: str = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def _ordered(self) -> TriageCitation:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class TriageResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Verdict
    reachability: Reachability
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=2000)
    citations: tuple[TriageCitation, ...] = Field(default=(), max_length=20)
    impact: str = Field(default="", max_length=1000)
    remediation: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def _rationale_not_blank(self) -> TriageResponse:
        if not self.rationale.strip():
            raise ValueError("rationale must not be blank")
        return self

    @model_validator(mode="after")
    def _decisive_needs_citation(self) -> TriageResponse:
        if self.verdict is not Verdict.NEEDS_HUMAN and not self.citations:
            raise ValueError(f"{self.verdict} requires at least one citation")
        return self

    @model_validator(mode="after")
    def _dismissal_cannot_claim_untrusted_input(self) -> TriageResponse:
        if (
            self.verdict is Verdict.FALSE_POSITIVE
            and self.reachability is Reachability.UNTRUSTED_INPUT
        ):
            raise ValueError(
                "contradictory: cannot dismiss a finding reachable from untrusted input"
            )
        return self

    @model_validator(mode="after")
    def _unknown_reachability_caps_confidence(self) -> TriageResponse:
        if (
            self.reachability is Reachability.UNKNOWN
            and self.confidence > _HIGH_CONFIDENCE
        ):
            raise ValueError(
                "confidence above 0.85 requires a determinate reachability assessment"
            )
        return self


def parse_triage_response(raw: str | dict) -> TriageResponse:
    """Parse model output into a validated response, tolerating fences and preamble."""
    if isinstance(raw, dict):
        return TriageResponse(**raw)

    match = _JSON_BLOCK.search(raw)
    if match is None:
        raise ValueError(f"no JSON object found in model output: {raw[:200]!r}")

    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON in model output: {exc}") from exc

    return TriageResponse(**payload)