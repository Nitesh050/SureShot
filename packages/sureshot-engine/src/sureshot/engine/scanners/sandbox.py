from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_POSIX = sys.platform != "win32"

SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")


class SandboxError(Exception):
    """A sandboxed process could not be started or supervised."""


class SandboxTimeout(SandboxError):
    """A sandboxed process exceeded its wall-clock budget and was killed."""


@dataclass(frozen=True)
class ProcessLimits:
    timeout_seconds: int = 900
    # None skips the OS-level RLIMIT_AS check entirely. That's deliberate,
    # not just "no limit": RLIMIT_AS caps virtual address space, and some
    # runtimes (OCaml's GC, semgrep-core's included) reserve a large VA
    # range as a fixed cost of starting up, unrelated to actual memory used.
    # A tool with that behavior needs its own RSS-aware self-limiting
    # (semgrep's own --max-memory) instead — see SemgrepScanner.
    max_memory_bytes: int | None = 4 << 30
    max_output_bytes: int = 256 << 20
    max_open_files: int = 4096


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    timed_out: bool = False


def _try_setrlimit(res: int, value: int) -> None:
    try:
        resource.setrlimit(res, (value, value))
    except (ValueError, OSError):
        pass


def _preexec(limits: ProcessLimits):
    def apply() -> None:
        os.setsid()
        # RLIMIT_AS is not enforced on macOS/Darwin; setting it raises.
        # It's also skipped outright when max_memory_bytes is None — see
        # ProcessLimits.
        if limits.max_memory_bytes is not None:
            _try_setrlimit(resource.RLIMIT_AS, limits.max_memory_bytes)
        _try_setrlimit(resource.RLIMIT_NOFILE, limits.max_open_files)
        _try_setrlimit(resource.RLIMIT_CORE, 0)

    return apply


def _terminate_group(process: subprocess.Popen) -> None:
    if not _POSIX:
        process.kill()
        return
    try:
        group = os.getpgid(process.pid)
    except ProcessLookupError:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def run_sandboxed(
    argv: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    limits: ProcessLimits | None = None,
    stdin_data: str | None = None,
) -> ProcessResult:
    """Run an external tool with an explicit environment, rlimits, and a hard timeout."""
    limits = limits or ProcessLimits()

    if shutil.which(argv[0]) is None and not Path(argv[0]).exists():
        raise SandboxError(f"executable not found on PATH: {argv[0]}")

    child_env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    child_env.update(env or {})

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=child_env,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            preexec_fn=_preexec(limits) if _POSIX else None,
            start_new_session=not _POSIX,
        )
    except OSError as exc:
        raise SandboxError(f"failed to start {argv[0]}: {exc}") from exc

    try:
        stdout, stderr = process.communicate(
            input=stdin_data, timeout=limits.timeout_seconds
        )
    except subprocess.TimeoutExpired:
        _terminate_group(process)
        process.communicate()
        elapsed = int((time.monotonic() - started) * 1000)
        raise SandboxTimeout(
            f"{argv[0]} exceeded {limits.timeout_seconds}s and was killed"
        ) from None

    elapsed = int((time.monotonic() - started) * 1000)
    out, out_truncated = _truncate(stdout or "", limits.max_output_bytes)
    err, err_truncated = _truncate(stderr or "", limits.max_output_bytes)

    return ProcessResult(
        exit_code=process.returncode,
        stdout=out,
        stderr=err,
        duration_ms=elapsed,
        truncated=out_truncated or err_truncated,
    )