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

    def version(self) -> ToolRecord:
        try:
            result = run_sandboxed(
                [self._binary, "--version", "--format", "json"],
                cwd=Path.cwd(),
                limits=ProcessLimits(timeout_seconds=30),
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"trivy is unavailable: {exc}") from exc

        try:
            version = str(json.loads(result.stdout).get("Version") or "unknown")
        except json.JSONDecodeError:
            version = result.stdout.strip() or "unknown"
        return ToolRecord(name=self.name, version=version)

    def scan(self, request: ScanRequest) -> ScanOutcome:
        tool = self.version()

        argv = [
            self._binary, "fs",
            "--scanners", "vuln,secret",
            "--format", "json",
            "--quiet",
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
