from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sureshot.domain.enums import Domain
from sureshot.domain.finding import SecurityFinding
from sureshot.domain.scan import ToolRecord


class ScanRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    source: Path
    output: Path
    include_paths: tuple[str, ...] = ()
    timeout_seconds: int = Field(default=900, gt=0)

    @field_validator("source", "output")
    @classmethod
    def _must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError(f"scan paths must be absolute, got {value}")
        return value


class ScanOutcome(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    findings: tuple[SecurityFinding, ...]
    raw_results: tuple[dict, ...] = ()
    tool: ToolRecord
    duration_ms: int = Field(ge=0)
    partial_reason: str | None = None

    @property
    def degraded(self) -> bool:
        return self.partial_reason is not None


@runtime_checkable
class Scanner(Protocol):
    """A deterministic security scanner that produces normalized findings."""

    name: str
    domains: tuple[Domain, ...]

    def version(self) -> ToolRecord: ...

    def scan(self, request: ScanRequest) -> ScanOutcome: ...


class ScannerUnavailable(Exception):
    """The scanner binary is missing or unusable."""