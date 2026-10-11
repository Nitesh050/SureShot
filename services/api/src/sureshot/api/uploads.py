from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException, UploadFile

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
ALLOWED_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
_CHUNK = 1024 * 1024


async def save_upload(upload: UploadFile, dest: Path) -> int:
    """Stream an uploaded archive to disk, refusing anything over the size cap.

    The format itself is checked by magic bytes when the scan unpacks it; the
    suffix check here only gives the user an early, readable error.
    """
    name = (upload.filename or "").lower()
    if not name.endswith(ALLOWED_SUFFIXES):
        raise HTTPException(400, f"upload must be one of: {', '.join(ALLOWED_SUFFIXES)}")

    written = 0
    with open(dest, "wb") as out:
        while chunk := await upload.read(_CHUNK):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
            out.write(chunk)
    if written == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "upload is empty")
    return written
