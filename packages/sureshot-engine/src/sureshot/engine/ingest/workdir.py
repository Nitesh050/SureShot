from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from types import TracebackType


def _on_rmtree_error(func, path: str, exc: BaseException) -> None:
    parent = os.path.dirname(path) or path
    os.chmod(parent, stat.S_IRWXU)
    func(path)


class Workdir:
    """An isolated, scan-scoped directory tree that is torn down on exit."""

    def __init__(self, scan_id: str, base: Path, keep: bool = False) -> None:
        self.scan_id = scan_id
        self.base = Path(base)
        self.keep = keep

    def __enter__(self) -> "Workdir":
        self.base.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix=f"scan-{self.scan_id}-", dir=self.base))
        self.source = self.root / "source"
        self.output = self.root / "output"
        self.source.mkdir()
        self.output.mkdir()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if not self.keep:
            shutil.rmtree(self.root, onexc=_on_rmtree_error)

    def relative(self, path: Path) -> str:
        path = Path(path)
        try:
            return path.relative_to(self.source).as_posix()
        except ValueError as exc:
            raise ValueError(f"path is outside the workdir source tree: {path}") from exc
