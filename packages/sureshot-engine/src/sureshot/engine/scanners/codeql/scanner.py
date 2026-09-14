from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sureshot.domain.enums import Domain
from sureshot.domain.repository import RepositoryProfile
from sureshot.domain.scan import ToolRecord
from sureshot.engine.scanners.base import ScanOutcome, ScanRequest, ScannerUnavailable
from sureshot.engine.scanners.codeql.adapter import adapt_results
from sureshot.engine.scanners.sandbox import (
    ProcessLimits,
    SandboxError,
    SandboxTimeout,
    run_sandboxed,
)

EXIT_CLEAN = 0
MIN_PHASE_SECONDS = 30

# Only languages this bundle has an extractor for (confirmed via
# `codeql resolve languages`), mapped from the profiler's language names.
LANGUAGE_MAP: dict[str, str] = {
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "javascript",
    "Java": "java",
    "Go": "go",
    "Rust": "rust",
    "Ruby": "ruby",
    "C#": "csharp",
    "C": "cpp",
    "C++": "cpp",
    "Swift": "swift",
}


class CodeQLScanner:
    """SAST via CodeQL: builds a database for the repo's primary language,
    then runs that language's extended security query suite against it."""

    name = "codeql"
    domains = (Domain.SAST,)

    def __init__(
        self,
        profile: RepositoryProfile | None = None,
        binary: str = "codeql",
    ) -> None:
        self._profile = profile
        self._binary = binary

    def _select_language(self) -> str | None:
        if self._profile is None:
            return None
        primary = self._profile.primary_language
        if primary is None:
            return None
        return LANGUAGE_MAP.get(primary)

    def _check_version(self):
        return run_sandboxed(
            [self._binary, "version", "--format=json"],
            cwd=Path.cwd(),
            limits=ProcessLimits(timeout_seconds=30),
        )

    def _parse_version(self, stdout: str) -> str:
        try:
            return str(json.loads(stdout).get("version") or "unknown")
        except json.JSONDecodeError:
            return stdout.strip() or "unknown"

    def _suite(self, language: str) -> str:
        return f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls"

    def _tool_record(self, version: str, language: str | None) -> ToolRecord:
        if language is None:
            return ToolRecord(name=self.name, version=version)
        suite = self._suite(language)
        digest = hashlib.sha256(suite.encode()).hexdigest()[:16]
        return ToolRecord(name=self.name, version=version, ruleset_id=suite, ruleset_hash=digest)

    def version(self) -> ToolRecord:
        try:
            result = self._check_version()
        except SandboxError as exc:
            raise ScannerUnavailable(f"codeql is unavailable: {exc}") from exc
        return self._tool_record(self._parse_version(result.stdout), None)

    def scan(self, request: ScanRequest) -> ScanOutcome:
        language = self._select_language()
        if language is None:
            return ScanOutcome(
                findings=(),
                tool=ToolRecord(name=self.name, version="unknown"),
                duration_ms=0,
                partial_reason="no CodeQL-supported language detected in profile",
            )

        try:
            version_result = self._check_version()
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(),
                tool=ToolRecord(name=self.name, version="unknown"),
                duration_ms=0,
                partial_reason=f"codeql timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"codeql is unavailable: {exc}") from exc

        tool = self._tool_record(self._parse_version(version_result.stdout), language)

        request.output.mkdir(parents=True, exist_ok=True)
        db_path = request.output / "codeql-db"
        sarif_path = request.output / "codeql-results.sarif"
        phase_timeout = max(request.timeout_seconds // 2, MIN_PHASE_SECONDS)

        create_argv = [
            self._binary, "database", "create", str(db_path),
            f"--language={language}",
            f"--source-root={request.source}",
            "--overwrite",
        ]
        try:
            create_result = run_sandboxed(
                create_argv, cwd=request.source,
                limits=ProcessLimits(timeout_seconds=phase_timeout),
            )
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(), tool=tool, duration_ms=phase_timeout * 1000,
                partial_reason=f"codeql database create timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"codeql could not run: {exc}") from exc

        if create_result.exit_code != EXIT_CLEAN:
            raise ScannerUnavailable(
                f"codeql database create failed ({create_result.exit_code}): "
                f"{create_result.stderr.strip()[:400]}"
            )

        analyze_argv = [
            self._binary, "database", "analyze", str(db_path),
            self._suite(language),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--threads=0",
        ]
        try:
            analyze_result = run_sandboxed(
                analyze_argv, cwd=request.source,
                limits=ProcessLimits(timeout_seconds=phase_timeout),
            )
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(), tool=tool,
                duration_ms=create_result.duration_ms + phase_timeout * 1000,
                partial_reason=f"codeql analysis timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"codeql could not run: {exc}") from exc

        if analyze_result.exit_code != EXIT_CLEAN:
            raise ScannerUnavailable(
                f"codeql database analyze failed ({analyze_result.exit_code}): "
                f"{analyze_result.stderr.strip()[:400]}"
            )

        try:
            sarif_text = sarif_path.read_text()
        except OSError as exc:
            raise ScannerUnavailable(f"could not read codeql SARIF output: {exc}") from exc

        try:
            payload: dict[str, Any] = json.loads(sarif_text)
        except json.JSONDecodeError as exc:
            raise ScannerUnavailable(f"could not parse codeql SARIF output: {exc}") from exc

        return ScanOutcome(
            findings=adapt_results(payload, tool),
            tool=tool,
            duration_ms=create_result.duration_ms + analyze_result.duration_ms,
            partial_reason=None,
        )
