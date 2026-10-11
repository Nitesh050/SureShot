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

# semgrep-core (OCaml) reserves a large virtual-address-space range as a
# fixed cost of starting up, well beyond what RLIMIT_AS can distinguish from
# a genuine runaway process — confirmed live: even an 8GB RLIMIT_AS killed a
# 3-ruleset scan that peaks nowhere near that in actual RSS. So the OS-level
# memory limit is disabled for this call (ProcessLimits.max_memory_bytes=None)
# and semgrep's own RSS-aware --max-memory is used instead.
MAX_MEMORY_MB = 4000


def _error_detail(result) -> str:
    """Prefer semgrep's own JSON error payload over stderr — a fatal exit
    (e.g. the engine killed for memory) reports its real diagnostic on
    stdout as {"errors": [...]}, leaving stderr empty."""
    try:
        payload = json.loads(result.stdout)
        errors = payload.get("errors") or []
        if errors:
            return str(errors[0].get("message", "")).strip()[:400]
    except json.JSONDecodeError:
        pass
    return result.stderr.strip()[:400]


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
            f"--max-memory={MAX_MEMORY_MB}",
            str(request.source),
        ]

        try:
            result = run_sandboxed(
                argv,
                cwd=request.source,
                env=OFFLINE_ENV,
                limits=ProcessLimits(
                    timeout_seconds=request.timeout_seconds, max_memory_bytes=None
                ),
            )
        except SandboxTimeout as exc:
            return ScanOutcome(
                findings=(),
                tool=tool,
                duration_ms=request.timeout_seconds * 1000,
                partial_reason=f"semgrep timed out: {exc}",
            )
        except SandboxError as exc:
            raise ScannerUnavailable(f"semgrep could not run: {exc}") from exc

        if result.truncated:
            return ScanOutcome(
                findings=(),
                tool=tool,
                duration_ms=result.duration_ms,
                partial_reason="semgrep output was truncated; results discarded",
            )

        if result.exit_code not in (EXIT_CLEAN, EXIT_FINDINGS):
            raise ScannerUnavailable(
                f"semgrep exited fatally ({result.exit_code}): {_error_detail(result)}"
            )

        try:
            payload: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerUnavailable(f"could not parse semgrep output: {exc}") from exc

        partial = _describe_errors(payload.get("errors") or [])

        from sureshot.engine.scanners.semgrep.adapter import adapt_results

        return ScanOutcome(
            findings=adapt_results(
                payload.get("results") or [], request.source, tool
            ),
            tool=tool,
            duration_ms=result.duration_ms,
            partial_reason=partial,
        )


def _anywhere():
    from pathlib import Path
    return Path.cwd()


def _describe_errors(errors: list[dict[str, Any]]) -> str | None:
    """Summarise semgrep's per-error list into one honest partial reason.

    Semgrep reports one error per (rule, file) pair. When a handful of rules
    crash inside the engine, that shows up as dozens of "files" even though
    every other rule analysed every file — so group by rule and say so,
    rather than claiming the files themselves went unscanned.
    """
    if not errors:
        return None
    rule_errors: dict[str, set[str]] = {}
    file_errors: list[dict[str, Any]] = []
    for err in errors:
        rule_id = err.get("rule_id")
        if rule_id:
            rule_errors.setdefault(rule_id, set()).add(str(err.get("path", "")))
        else:
            file_errors.append(err)

    parts = []
    if rule_errors:
        names = ", ".join(sorted(r.rsplit(".", 1)[-1] for r in rule_errors)[:3])
        more = f" (+{len(rule_errors) - 3} more)" if len(rule_errors) > 3 else ""
        parts.append(
            f"{len(rule_errors)} rule(s) failed inside the semgrep engine and were "
            f"skipped: {names}{more}; all other rules ran"
        )
    if file_errors:
        parts.append(
            f"{len(file_errors)} file(s) could not be analysed: "
            f"{str(file_errors[0].get('message', 'unknown error'))[:160]}"
        )
    return "; ".join(parts)
