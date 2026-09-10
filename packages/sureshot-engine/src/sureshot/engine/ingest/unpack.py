from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from sureshot.engine.ingest.safety import (
    ExtractionLimits,
    ExtractionReport,
    UnsafeArchiveError,
    extract_tar,
    extract_zip,
)

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_TAR_MAGICS = (
    b"\x1f\x8b",          # gzip
    b"BZh",               # bzip2
    b"\xfd7zXZ\x00",      # xz
    b"\x28\xb5\x2f\xfd",  # zstd
)
_USTAR_OFFSET = 257
_USTAR_MAGIC = b"ustar"


class ArchiveFormat(StrEnum):
    ZIP = "zip"
    TAR = "tar"


def detect_format(stream: BinaryIO) -> ArchiveFormat:
    """Identify an archive by magic bytes, leaving the stream position unchanged."""
    start = stream.tell()
    header = stream.read(512)
    stream.seek(start)

    if header.startswith(_ZIP_MAGICS):
        return ArchiveFormat.ZIP
    if header.startswith(_TAR_MAGICS):
        return ArchiveFormat.TAR
    if header[_USTAR_OFFSET : _USTAR_OFFSET + 5] == _USTAR_MAGIC:
        return ArchiveFormat.TAR

    raise UnsafeArchiveError(
        f"unrecognized archive format; leading bytes: {header[:8]!r}"
    )


def unpack(
    archive: Path,
    root: Path,
    limits: ExtractionLimits | None = None,
) -> ExtractionReport:
    """Extract an archive into root, enforcing all safety limits."""
    with open(archive, "rb") as stream:
        fmt = detect_format(stream)
        if fmt is ArchiveFormat.ZIP:
            return extract_zip(stream, root, limits)
        return extract_tar(stream, root, limits)