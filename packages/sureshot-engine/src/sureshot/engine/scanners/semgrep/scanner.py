from __future__ import annotations

import hashlib
import json
from typing import Any

from sureshot.domain.enums import Domain
from sureshot.domain.repository import RepositoryProfile
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.base import ScanOutcome, ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.sandbox import (
    ProcessLimits,
    SandboxError,
    SandboxTimeout,
    run_sandboxed,
)

EXIT_CLEAN = 0
EXIT_FINDINGS = 1

OFFLINE_ENV = {
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
}


class SemgrepScanner:
    name = "semgrep"
    domains = (Domain.SAST,)

    def __init__(
        self,
        profile: RepositoryProfile | None = None,
        binary: str = "semgrep",
    ) -> None:
        self._profile = profile
        self._binary = binary

    def _check_version(self):
        return run_sandboxed(
            [self._binary, "--version"],
            cwd=_anywhere(),
            limits=ProcessLimits(timeout_seconds=30),
        )

    def version(self) -> ToolRecord:
        try:
            result = self._check_version()
        except SandboxError as exc:
            raise ScannerUnavailable(f"semgrep is unavailable: {exc}") from exc
        return ToolRecord(name=self.name, version=result.stdout.strip() or "unknown")

    def _ruleset_record(self, version: str, rulesets: tuple[str, ...]) -> ToolRecord:
        digest = hashlib.sha256("\n".join(rulesets).encode()).hexdigest()[:16]
        return ToolRecord(
            name=self.name,
            version=version,
            ruleset_id=",".join(rulesets),
            ruleset_hash=digest,
        )

    def scan(self, request: ScanRequest) -> ScanOutcome:
        from sureshot.engine.scanners.semgrep.rulesets import select_rulesets

        rulesets = select_rulesets(self._profile)

        try:
            version_result = self._check_version()
        except SandboxTimeout as exc:
            tool = self._ruleset_record("unknown", rulesets)
            return ScanOutcome(
                findings=(),
                raw_results=(),
                tool=tool,
                duration_ms=0,
                partial_reason=f"semgrep timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"semgrep is unavailable: {exc}") from exc

        tool_version = version_result.stdout.strip() or "unknown"
        tool = self._ruleset_record(tool_version, rulesets)

        argv = [self._binary, "scan", "--json", "--quiet"]
        for pack in rulesets:
            argv += ["--config", pack]
        argv += [
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            f"--timeout={max(request.timeout_seconds // 10, 30)}",
            "--max-target-bytes=1000000",
            str(request.source),
        ]

        try:
            result = run_sandboxed(
                argv,
                cwd=request.source,
                env=OFFLINE_ENV,
                limits=ProcessLimits(timeout_seconds=request.timeout_seconds),
            )
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(),
                raw_results=(),
                tool=tool,
                duration_ms=request.timeout_seconds * 1000,
                partial_reason=f"semgrep timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"semgrep could not run: {exc}") from exc

        if result.truncated:
            return ScanOutcome(
                findings=(),
                raw_results=(),
                tool=tool,
                duration_ms=result.duration_ms,
                partial_reason="semgrep output was truncated; results discarded",
            )

        if result.exit_code not in (EXIT_CLEAN, EXIT_FINDINGS):
            raise ScannerUnavailable(
                f"semgrep exited fatally ({result.exit_code}): "
                f"{result.stderr.strip()[:400]}"
            )

        try:
            payload: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerUnavailable(f"could not parse semgrep output: {exc}") from exc

        errors = payload.get("errors") or []
        partial = None
        if errors:
            partial = (
                f"semgrep could not analyze {len(errors)} file(s): "
                f"{errors[0].get('message', 'unknown error')[:200]}"
            )

        return ScanOutcome(
            findings=(),
            raw_results=tuple(payload.get("results") or []),
            tool=tool,
            duration_ms=result.duration_ms,
            partial_reason=partial,
        )


def _anywhere():
    from pathlib import Path
    return Path.cwd()