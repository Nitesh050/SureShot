from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from sureshot.api.deps import get_runner, get_store
from sureshot.api.runner import UPLOAD_NAME, ScanRunner
from sureshot.api.store import ScanOptions, ScanRecord, ScanSource, ScanStore, now
from sureshot.api.uploads import save_upload
from sureshot.engine.ingest.fetch import FetchError, parse_repo_url
from sureshot.engine.scanners.registry import available_scanners

router = APIRouter(prefix="/scans", tags=["scans"])


class UrlScanRequest(BaseModel):
    repo_url: str
    ref: str | None = None
    scanners: list[str] | None = None
    triage: bool = True
    llm: Literal["anthropic", "ollama"] = "anthropic"


def _options(scanners: list[str] | None, triage: bool, llm: str) -> ScanOptions:
    known = set(available_scanners())
    unknown = [s for s in scanners or [] if s not in known]
    if unknown:
        raise HTTPException(400, f"unknown scanners: {unknown}")
    return ScanOptions(scanners=scanners or None, triage=triage, llm=llm)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


@router.post("", status_code=202)
def create_url_scan(
    body: UrlScanRequest,
    store: ScanStore = Depends(get_store),
    runner: ScanRunner = Depends(get_runner),
) -> ScanRecord:
    try:
        repo = parse_repo_url(body.repo_url, body.ref)
    except FetchError as exc:
        raise HTTPException(400, str(exc)) from None

    record = store.add(ScanRecord(
        id=_new_id(), created_at=now(),
        source=ScanSource(kind="url", label=repo.display, url=body.repo_url.strip(), ref=repo.ref),
        options=_options(body.scanners, body.triage, body.llm),
    ))
    runner.submit(record.id)
    return record


@router.post("/upload", status_code=202)
async def create_upload_scan(
    file: UploadFile = File(...),
    scanners: str | None = Form(None),
    triage: bool = Form(True),
    llm: Literal["anthropic", "ollama"] = Form("anthropic"),
    store: ScanStore = Depends(get_store),
    runner: ScanRunner = Depends(get_runner),
) -> ScanRecord:
    names = [s.strip() for s in scanners.split(",") if s.strip()] if scanners else None
    options = _options(names, triage, llm)

    scan_id = _new_id()
    await save_upload(file, store.dir_for(scan_id) / UPLOAD_NAME)

    filename = file.filename or "upload"
    label = filename
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"):
        if label.lower().endswith(suffix):
            label = label[: -len(suffix)]
            break

    record = store.add(ScanRecord(
        id=scan_id, created_at=now(), options=options,
        source=ScanSource(kind="upload", label=label or filename, filename=filename),
    ))
    runner.submit(record.id)
    return record


@router.get("")
def list_scans(store: ScanStore = Depends(get_store)) -> list[ScanRecord]:
    return store.list()


@router.get("/{scan_id}")
def get_scan(scan_id: str, store: ScanStore = Depends(get_store)) -> ScanRecord:
    record = store.get(scan_id)
    if record is None:
        raise HTTPException(404, "scan not found")
    return record
