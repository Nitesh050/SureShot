from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from sureshot.api.deps import get_store
from sureshot.api.store import REPORT_FILES, ScanStore

router = APIRouter(prefix="/scans", tags=["reports"])


@router.get("/{scan_id}/report/{fmt}")
def download_report(
    scan_id: str,
    fmt: Literal["json", "sarif", "html", "pdf"],
    store: ScanStore = Depends(get_store),
) -> FileResponse:
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    path = store.report_path(scan_id, fmt)
    if path is None:
        raise HTTPException(404, f"no {fmt} report for this scan")

    _, media_type = REPORT_FILES[fmt]
    safe_label = "".join(c if c.isalnum() or c in "-_." else "-" for c in record.source.label)
    return FileResponse(path, media_type=media_type,
                        filename=f"sureshot-{safe_label}-{scan_id}.{fmt}")
