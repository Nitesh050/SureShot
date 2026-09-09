from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sureshot.domain.enums import StepStatus


def _require_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value


class ToolRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str
    ruleset_id: str | None = None
    ruleset_hash: str | None = None
    db_timestamp: datetime | None = None

    @field_validator("db_timestamp")
    @classmethod
    def _aware_if_present(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware(value)


class ScanProvenance(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tools: tuple[ToolRecord, ...] = ()
    model_id: str | None = None
    prompt_versions: tuple[str, ...] = ()
    risk_policy_hash: str | None = None
    engine_version: str

    def with_tool(self, record: ToolRecord) -> ScanProvenance:
        return self.model_copy(update={"tools": self.tools + (record,)})


class StepResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    step: str
    status: StepStatus
    detail: str = ""
    duration_ms: int = Field(ge=0)

    @property
    def blocks_pipeline(self) -> bool:
        return self.status is StepStatus.FAILED


class ScanState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    org_id: str
    project_id: str
    workdir: str

    started_at: datetime
    provenance: ScanProvenance
    steps: tuple[StepResult, ...] = ()

    _aware = field_validator("started_at")(_require_aware)

    def record(self, result: StepResult) -> ScanState:
        return self.model_copy(update={"steps": self.steps + (result,)})

    @property
    def degraded(self) -> bool:
        return any(s.status is not StepStatus.OK for s in self.steps)