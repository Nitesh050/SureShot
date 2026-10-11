from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

from sureshot.api.deps import get_store
from sureshot.api.store import ScanStatus, ScanStore

router = APIRouter(prefix="/scans", tags=["findings"])


@router.get("/{scan_id}/findings")
def get_findings(scan_id: str, store: ScanStore = Depends(get_store)) -> dict:
    """The deduplicated report, plus the redacted code context per issue."""
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    if record.status is not ScanStatus.COMPLETED:
        raise HTTPException(409, f"scan is {record.status.value}")

    report = store.findings(scan_id)
    if report is None:
        raise HTTPException(404, "report not available for this scan")

    snippets_path = store.data_dir / scan_id / "snippets.json"
    snippets = json.loads(snippets_path.read_text()) if snippets_path.is_file() else {}
    for issue in report["issues"]:
        issue["snippet"] = snippets.get(issue["finding"].get("instance_id"))
    return report
