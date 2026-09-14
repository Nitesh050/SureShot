from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sureshot.domain.enums import Domain
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.base import ScanOutcome, ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.sandbox import (
    ProcessLimits,
    SandboxError,
    SandboxTimeout,
    run_sandboxed,
)
from sureshot.engine.scanners.trivy.adapter import adapt_results
from sureshot.engine.scanners.trivy.dbcache import check_db

EXIT_CLEAN = 0


class TrivyScanner:
    """SCA and secret scanning over a filesystem tree via `trivy fs`."""

    name = "trivy"
    domains = (Domain.SCA, Domain.SECRET)

    def __init__(self, binary: str = "trivy", cache_dir: Path | None = None) -> None:
        self._binary = binary
        self._cache_dir = cache_dir

    def _cache_args(self) -> list[str]:
        return ["--cache-dir", str(self._cache_dir)] if self._cache_dir else []

    def _check_version(self):
        return run_sandboxed(
            [self._binary, "--version", "--format", "json"],
            cwd=Path.cwd(),
            limits=ProcessLimits(timeout_seconds=30),
        )

    def _tool_record(self, version_stdout: str) -> ToolRecord:
        try:
            version = str(json.loads(version_stdout).get("Version") or "unknown")
        except json.JSONDecodeError:
            version = version_stdout.strip() or "unknown"

        db = check_db(self._cache_dir)
        return ToolRecord(
            name=self.name,
            version=version,
            db_timestamp=db.updated_at if db.present else None,
        )

    def version(self) -> ToolRecord:
        try:
            result = self._check_version()
        except SandboxError as exc:
            raise ScannerUnavailable(f"trivy is unavailable: {exc}") from exc
        return self._tool_record(result.stdout)

    def scan(self, request: ScanRequest) -> ScanOutcome:
        try:
            version_result = self._check_version()
        except SandboxTimeout as exc:
            tool = ToolRecord(name=self.name, version="unknown")
            return ScanOutcome(
                findings=(),
                tool=tool,
                duration_ms=0,
                partial_reason=f"trivy timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"trivy is unavailable: {exc}") from exc

        tool = self._tool_record(version_result.stdout)

        argv = [
            self._binary, "fs",
            "--scanners", "vuln,secret",
            "--format", "json",
            "--quiet",
            "--timeout", f"{request.timeout_seconds}s",
            *self._cache_args(),
            str(request.source),
        ]

        try:
            result = run_sandboxed(
                argv,
                cwd=request.source,
                limits=ProcessLimits(timeout_seconds=request.timeout_seconds),
            )
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(),
                tool=tool,
                duration_ms=request.timeout_seconds * 1000,
                partial_reason=f"trivy timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"trivy could not run: {exc}") from exc

        if result.truncated:
            return ScanOutcome(
                findings=(),
                tool=tool,
                duration_ms=result.duration_ms,
                partial_reason="trivy output was truncated; results discarded",
            )

        if result.exit_code != EXIT_CLEAN:
            raise ScannerUnavailable(
                f"trivy exited fatally ({result.exit_code}): {result.stderr.strip()[:400]}"
            )

        try:
            payload: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerUnavailable(f"could not parse trivy output: {exc}") from exc

        return ScanOutcome(
            findings=adapt_results(payload, tool),
            tool=tool,
            duration_ms=result.duration_ms,
            partial_reason=None,
        )
