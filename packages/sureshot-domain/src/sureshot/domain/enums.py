from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Domain(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"
    IAC = "iac"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN = "needs_human"


class FindingState(StrEnum):
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class StepStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"


class GuardHold(StrEnum):
    INJECTION = "injection"
    REDACTION = "redaction"
    POLICY = "policy"
    EVIDENCE = "evidence"
    BUDGET = "budget"


class Coverage(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"