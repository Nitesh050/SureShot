from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanSource(BaseModel):
    kind: Literal["url", "upload"]
    label: str
    url: str | None = None
    ref: str | None = None
    commit: str | None = None
    filename: str | None = None


class ScanOptions(BaseModel):
    scanners: list[str] | None = None  # None = auto-detect from the repo profile
    triage: bool = True
    llm: Literal["anthropic", "ollama"] = "anthropic"


class StepRecord(BaseModel):
    step: str
    status: str
    detail: str = ""
    duration_ms: int = 0


class ScanSummary(BaseModel):
    raw_findings: int = 0
    issues: int = 0
    actionable: int = 0
    dismissed: int = 0
    needs_review: int = 0
    multi_tool: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    id: str
    status: ScanStatus = ScanStatus.QUEUED
    source: ScanSource
    options: ScanOptions
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    current_step: str | None = None
    progress: str | None = None  # e.g. "37/104 findings" within the current step
    steps: list[StepRecord] = Field(default_factory=list)
    profile: dict[str, Any] | None = None
    summary: ScanSummary | None = None
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    reports: list[str] = Field(default_factory=list)


REPORT_FILES = {
    "json": ("report.json", "application/json"),
    "sarif": ("report.sarif", "application/sarif+json"),
    "html": ("report.html", "text/html"),
    "pdf": ("report.pdf", "application/pdf"),
}


class ScanStore:
    """Scan records kept in memory and mirrored to `<data_dir>/<id>/meta.json`.

    A stand-in for the persistence package until Postgres is wired in: good
    enough for one API process, and it survives restarts.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records: dict[str, ScanRecord] = {}
        self._load()

    def _load(self) -> None:
        for meta in self.data_dir.glob("*/meta.json"):
            try:
                record = ScanRecord.model_validate_json(meta.read_text())
            except ValueError:
                continue
            # Anything still in flight belonged to a process that is gone.
            if record.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
                record.status = ScanStatus.FAILED
                record.error = "interrupted: the API restarted while this scan was running"
                record.current_step = None
                self._write(record)
            self._records[record.id] = record

    def dir_for(self, scan_id: str) -> Path:
        path = self.data_dir / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _write(self, record: ScanRecord) -> None:
        meta = self.dir_for(record.id) / "meta.json"
        tmp = meta.with_suffix(".tmp")
        tmp.write_text(record.model_dump_json(indent=2))
        tmp.replace(meta)

    def add(self, record: ScanRecord) -> ScanRecord:
        with self._lock:
            self._records[record.id] = record
            self._write(record)
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        with self._lock:
            record = self._records.get(scan_id)
            return record.model_copy(deep=True) if record else None

    def list(self) -> list[ScanRecord]:
        with self._lock:
            records = [r.model_copy(deep=True) for r in self._records.values()]
        return sorted(records, key=lambda r: r.created_at, reverse=True)

    def update(self, scan_id: str, **changes: Any) -> ScanRecord:
        with self._lock:
            record = self._records[scan_id].model_copy(update=changes)
            self._records[scan_id] = record
            self._write(record)
            return record

    def report_path(self, scan_id: str, fmt: str) -> Path | None:
        name, _ = REPORT_FILES[fmt]
        path = self.data_dir / scan_id / name
        return path if path.is_file() else None

    def findings(self, scan_id: str) -> dict[str, Any] | None:
        path = self.report_path(scan_id, "json")
        return json.loads(path.read_text()) if path else None


def now() -> datetime:
    return datetime.now(UTC)
