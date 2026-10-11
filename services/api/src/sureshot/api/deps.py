from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from sureshot.api.runner import ScanRunner
from sureshot.api.store import ScanStore


def data_dir() -> Path:
    return Path(os.environ.get("SURESHOT_DATA_DIR", Path.home() / ".sureshot" / "scans"))


@lru_cache
def get_store() -> ScanStore:
    return ScanStore(data_dir())


@lru_cache
def get_runner() -> ScanRunner:
    return ScanRunner(get_store())
