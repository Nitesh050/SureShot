from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


def _default_cache_dir() -> Path:
    """Mirror Trivy's own (Go os.UserCacheDir-based) per-OS cache default."""
    override = os.environ.get("TRIVY_CACHE_DIR")
    if override:
        return Path(override)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "trivy"
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home()))
        return Path(base) / "trivy"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".cache") / "trivy"


DEFAULT_CACHE_DIR = _default_cache_dir()


@dataclass(frozen=True)
class DBStatus:
    cache_dir: Path
    present: bool
    stale: bool
    updated_at: datetime | None = None
    next_update: datetime | None = None


def _metadata_path(cache_dir: Path) -> Path:
    return cache_dir / "db" / "metadata.json"


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def check_db(cache_dir: Path | None = None) -> DBStatus:
    """Report whether Trivy's vulnerability DB is present and due for a refresh.

    Trivy stamps its own db/metadata.json with UpdatedAt/NextUpdate, so staleness
    is read from Trivy's own schedule rather than a guessed TTL.
    """
    cache_dir = cache_dir or DEFAULT_CACHE_DIR
    metadata_path = _metadata_path(cache_dir)

    if not metadata_path.is_file():
        return DBStatus(cache_dir=cache_dir, present=False, stale=True)

    try:
        raw = json.loads(metadata_path.read_text())
        updated_at = _parse_timestamp(raw["UpdatedAt"])
        next_update = _parse_timestamp(raw["NextUpdate"])
    except (OSError, ValueError, KeyError):
        return DBStatus(cache_dir=cache_dir, present=True, stale=True)

    return DBStatus(
        cache_dir=cache_dir,
        present=True,
        stale=datetime.now(UTC) > next_update,
        updated_at=updated_at,
        next_update=next_update,
    )
