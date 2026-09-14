from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.finding import SecurityFinding
from sureshot.domain.repository import RepositoryProfile
from sureshot.domain.scan import ScanState
from sureshot.engine.risk.scoring import RiskResult


class ScoredFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding: SecurityFinding
    analysis: SecurityAnalysis | None
    risk: RiskResult


@dataclass(frozen=True)
class PipelineResult:
    state: ScanState
    profile: RepositoryProfile
    findings: tuple[ScoredFinding, ...]
