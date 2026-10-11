from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from sureshot.api.deps import get_store
from sureshot.api.store import REPORT_FILES, ScanRecord, ScanStore

router = APIRouter(prefix="/scans", tags=["reports"])


def _record(store: ScanStore, scan_id: str) -> ScanRecord:
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    return record


def _filename(record: ScanRecord, fmt: str) -> str:
    safe_label = "".join(c if c.isalnum() or c in "-_." else "-" for c in record.source.label)
    return f"sureshot-{safe_label}-{record.id}.{fmt}"


@router.get("/{scan_id}/reports")
def list_reports(scan_id: str, store: ScanStore = Depends(get_store)) -> list[dict]:
    """The report files this scan produced, with their sizes, for the download list."""
    record = _record(store, scan_id)
    out = []
    for fmt in REPORT_FILES:
        path = store.report_path(scan_id, fmt)
        if path is not None:
            out.append({"format": fmt, "filename": _filename(record, fmt),
                        "size_bytes": path.stat().st_size})
    return out


@router.get("/{scan_id}/report/{fmt}")
def download_report(
    scan_id: str,
    fmt: Literal["json", "sarif", "html", "pdf"],
    inline: bool = False,
    store: ScanStore = Depends(get_store),
) -> FileResponse:
    """Download a report; `?inline=true` opens HTML/PDF in the browser instead."""
    record = _record(store, scan_id)
    path = store.report_path(scan_id, fmt)
    if path is None:
        raise HTTPException(404, f"no {fmt} report for this scan")

    _, media_type = REPORT_FILES[fmt]
    viewable = inline and fmt in ("html", "pdf")
    return FileResponse(path, media_type=media_type, filename=_filename(record, fmt),
                        content_disposition_type="inline" if viewable else "attachment")
