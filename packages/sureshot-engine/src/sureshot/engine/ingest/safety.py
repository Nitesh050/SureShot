from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

CHUNK = 1 << 20


class UnsafeArchiveError(Exception):
    """Raised when an archive member violates an extraction safety rule."""


@dataclass(frozen=True)
class ExtractionLimits:
    max_files: int = 50_000
    max_total_bytes: int = 2 << 30
    max_file_bytes: int = 100 << 20
    max_path_length: int = 4096


@dataclass
class ExtractionReport:
    files: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)


def _safe_target(root: Path, name: str, limits: ExtractionLimits) -> Path:
    if not name or name in (".", "./"):
        raise UnsafeArchiveError("empty member name")
    if "\x00" in name:
        raise UnsafeArchiveError(f"member name contains NUL: {name!r}")
    if len(name) > limits.max_path_length:
        raise UnsafeArchiveError(f"member path too long: {len(name)} chars")

    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise UnsafeArchiveError(f"member path is absolute: {name!r}")

    target = Path(os.path.normpath(os.path.join(root, normalized)))
    if target != root and not target.is_relative_to(root):
        raise UnsafeArchiveError(f"member escapes extraction root: {name!r}")
    return target


def _account(report: ExtractionReport, written: int, limits: ExtractionLimits) -> None:
    report.total_bytes += written
    if report.total_bytes > limits.max_total_bytes:
        raise UnsafeArchiveError(
            f"archive exceeds total size limit of {limits.max_total_bytes} bytes"
        )


def _stream_to_disk(
    source: BinaryIO,
    target: Path,
    report: ExtractionReport,
    limits: ExtractionLimits,
) -> None:
    written = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            if written > limits.max_file_bytes:
                raise UnsafeArchiveError(
                    f"member exceeds per-file limit of {limits.max_file_bytes} bytes: "
                    f"{target.name}"
                )
            _account(report, len(chunk), limits)
            out.write(chunk)


def extract_zip(
    source: BinaryIO,
    root: Path,
    limits: ExtractionLimits | None = None,
) -> ExtractionReport:
    limits = limits or ExtractionLimits()
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    report = ExtractionReport()

    with zipfile.ZipFile(source) as zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise UnsafeArchiveError(
                f"archive exceeds file count limit of {limits.max_files}"
            )

        for info in infos:
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise UnsafeArchiveError(f"symlink members are rejected: {info.filename}")

            target = _safe_target(root, info.filename, limits)

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if info.file_size > limits.max_file_bytes:
                raise UnsafeArchiveError(
                    f"member exceeds per-file limit of {limits.max_file_bytes} bytes: "
                    f"{info.filename}"
                )

            with zf.open(info) as member:
                _stream_to_disk(member, target, report, limits)
            report.files += 1

    return report


_ALLOWED_TAR_TYPES = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}


def extract_tar(
    source: BinaryIO,
    root: Path,
    limits: ExtractionLimits | None = None,
) -> ExtractionReport:
    limits = limits or ExtractionLimits()
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    report = ExtractionReport()

    with tarfile.open(fileobj=source, mode="r:*") as tf:
        for info in tf:
            if info.issym() or info.islnk():
                raise UnsafeArchiveError(f"symlink members are rejected: {info.name}")
            if info.type not in _ALLOWED_TAR_TYPES:
                raise UnsafeArchiveError(
                    f"unsupported member type {info.type!r}: {info.name}"
                )

            target = _safe_target(root, info.name, limits)

            if info.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if report.files >= limits.max_files:
                raise UnsafeArchiveError(
                    f"archive exceeds file count limit of {limits.max_files}"
                )
            if info.size > limits.max_file_bytes:
                raise UnsafeArchiveError(
                    f"member exceeds per-file limit of {limits.max_file_bytes} bytes: "
                    f"{info.name}"
                )

            member = tf.extractfile(info)
            if member is None:
                report.skipped.append(info.name)
                continue
            _stream_to_disk(member, target, report, limits)
            report.files += 1

    return report