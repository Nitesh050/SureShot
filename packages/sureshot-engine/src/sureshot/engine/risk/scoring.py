from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sureshot.domain.analysis import SecurityAnalysis
from sureshot.domain.enums import Domain, GuardHold, Verdict
from sureshot.domain.finding import SecurityFinding
from sureshot.engine.guards.policy import apply_critical_floor
from sureshot.engine.risk.signals import PathRole, collect_signals

_POLICY_PATH = Path(__file__).parent / "policy.yaml"


class RiskPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int
    severity_base: dict[str, float]
    verdict_multiplier: dict[str, float]
    path_multiplier: dict[str, float]
    sca_fix_bonus: float
    sca_direct_bonus: float
    confidence_pull: float = Field(ge=0.0, le=1.0)
    critical_floor: float

    @property
    def hash(self) -> str:
        payload = self.model_dump_json()
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @staticmethod
    @lru_cache(maxsize=1)
    def default() -> "RiskPolicy":
        return RiskPolicy(**yaml.safe_load(_POLICY_PATH.read_text()))


class RiskResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    score: float = Field(ge=0.0, le=100.0)
    contributions: dict[str, float]
    holds: tuple[GuardHold, ...] = ()
    policy_hash: str


def _blend(multiplier: float, confidence: float, pull: float) -> float:
    """Pull a verdict multiplier toward neutral when the model is unsure."""
    neutral = 1.0
    weight = confidence + (1.0 - confidence) * (1.0 - pull)
    return multiplier * weight + neutral * (1.0 - weight)


def score_finding(
    finding: SecurityFinding,
    analysis: SecurityAnalysis | None,
    policy: RiskPolicy | None = None,
) -> RiskResult:
    policy = policy or RiskPolicy.default()
    signals = collect_signals(finding)
    contributions: dict[str, float] = {}

    base = policy.severity_base[finding.severity.value]
    contributions["severity"] = base
    score = base

    path_factor = policy.path_multiplier[signals.path_role.value]
    contributions["path_role"] = score * (path_factor - 1.0)
    score *= path_factor

    if analysis is None:
        verdict_factor = policy.verdict_multiplier[Verdict.NEEDS_HUMAN.value]
    else:
        raw = policy.verdict_multiplier[analysis.verdict.value]
        verdict_factor = _blend(raw, analysis.confidence, policy.confidence_pull)
    contributions["verdict"] = score * (verdict_factor - 1.0)
    score *= verdict_factor

    if finding.domain is Domain.SCA:
        bonus = 0.0
        if signals.fix_available == 1.0:
            bonus += policy.sca_fix_bonus
        if signals.dependency_weight == 1.0:
            bonus += policy.sca_direct_bonus
        contributions["dependency"] = bonus
        score += bonus

    floor = apply_critical_floor(finding, analysis, score, policy.critical_floor)
    holds: tuple[GuardHold, ...] = floor.holds
    if floor.floored:
        contributions["policy_floor"] = floor.score - score
        score = floor.score

    return RiskResult(
        score=round(max(0.0, min(100.0, score)), 2),
        contributions={k: round(v, 2) for k, v in contributions.items()},
        holds=holds,
        policy_hash=policy.hash,
    )