from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sureshot.domain.enums import Domain, Severity


class Location(BaseModel):
    model_config = ConfigDict(frozen=True)

    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)

    @field_validator("file_path")
    @classmethod
    def _must_be_repo_relative(cls, value: str) -> str:
        path = PurePosixPath(value.replace("\\", "/"))
        if path.is_absolute():
            raise ValueError(f"file_path must be repo-relative, got {value!r}")
        if ".." in path.parts:
            raise ValueError(f"file_path must not escape the repo root, got {value!r}")
        return str(path)

    @model_validator(mode="after")
    def _lines_ordered(self) -> Location:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class Package(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    installed_version: str
    fixed_version: str | None = None
    is_direct: bool | None = None


class SecretRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str
    last_four: str = Field(max_length=4)


class SecurityFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    instance_id: str | None = None
    issue_id: str | None = None

    tool: str
    tool_version: str
    rule_id: str
    domain: Domain

    title: str
    description: str = ""
    severity: Severity
    cwe_ids: tuple[str, ...] = ()
    cve_id: str | None = None

    location: Location
    package: Package | None = None
    secret: SecretRef | None = None

    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @field_validator("cwe_ids")
    @classmethod
    def _cwe_format(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for cwe in value:
            if not cwe.startswith("CWE-") or not cwe[4:].isdigit():
                raise ValueError(f"cwe id must look like 'CWE-89', got {cwe!r}")
        return value

    @model_validator(mode="after")
    def _domain_invariants(self) -> SecurityFinding:
        if self.domain is Domain.SCA and self.package is None:
            raise ValueError("sca findings must carry package metadata")
        if self.domain is Domain.SECRET:
            if self.secret is None:
                raise ValueError("secret findings must carry a redacted SecretRef")
            if self.raw:
                raise ValueError("secret findings must not retain raw scanner output")
        return self