from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from sureshot.domain.enums import Coverage, Domain


class LanguageStat(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    files: int = Field(ge=0)
    bytes: int = Field(ge=0)


class Ecosystem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    manifests: tuple[str, ...] = ()
    lockfiles: tuple[str, ...] = ()

    @property
    def has_lockfile(self) -> bool:
        return bool(self.lockfiles)


class CoverageNote(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    domain: Domain
    coverage: Coverage
    reason: str = Field(min_length=1)


class RepositoryProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_files: int = Field(ge=0)
    scanned_files: int = Field(ge=0)
    skipped_files: int = Field(ge=0)
    total_bytes: int = Field(ge=0)

    languages: tuple[LanguageStat, ...] = ()
    ecosystems: tuple[Ecosystem, ...] = ()
    coverage: tuple[CoverageNote, ...] = ()

    @property
    def primary_language(self) -> str | None:
        if not self.languages:
            return None
        return max(self.languages, key=lambda l: l.bytes).name

    def coverage_for(self, domain: Domain) -> Coverage:
        for note in self.coverage:
            if note.domain is domain:
                return note.coverage
        return Coverage.NONE