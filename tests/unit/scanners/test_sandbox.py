import sys
from pathlib import Path

import pytest

from sureshot.engine.scanners.sandbox import (
    ProcessLimits,
    SandboxError,
    SandboxTimeout,
    run_sandboxed,
)


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_captures_stdout_and_exit_code(tmp_path: Path):
    result = run_sandboxed(_py("print('hello')"), cwd=tmp_path)
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert result.timed_out is False


def test_nonzero_exit_is_returned_not_raised(tmp_path: Path):
    result = run_sandboxed(_py("import sys; sys.exit(3)"), cwd=tmp_path)
    assert result.exit_code == 3


def test_timeout_kills_process(tmp_path: Path):
    limits = ProcessLimits(timeout_seconds=1)
    with pytest.raises(SandboxTimeout):
        run_sandboxed(_py("import time; time.sleep(30)"), cwd=tmp_path, limits=limits)


def test_timeout_kills_orphaned_children(tmp_path: Path):
    """A child that outlives its parent must still be reaped."""
    code = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        "time.sleep(60)"
    )
    limits = ProcessLimits(timeout_seconds=1)
    with pytest.raises(SandboxTimeout):
        run_sandboxed(_py(code), cwd=tmp_path, limits=limits)


def test_stdout_truncated_at_limit(tmp_path: Path):
    limits = ProcessLimits(max_output_bytes=1024)
    result = run_sandboxed(
        _py("print('A' * 100000)"), cwd=tmp_path, limits=limits
    )
    assert len(result.stdout) <= 1024
    assert result.truncated is True


def test_environment_is_scrubbed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SURESHOT_DB_PASSWORD", "hunter2")
    result = run_sandboxed(
        _py("import os; print(os.environ.get('SURESHOT_DB_PASSWORD', 'ABSENT'))"),
        cwd=tmp_path,
    )
    assert result.stdout.strip() == "ABSENT"


def test_explicit_env_passthrough(tmp_path: Path):
    result = run_sandboxed(
        _py("import os; print(os.environ['TRIVY_CACHE_DIR'])"),
        cwd=tmp_path,
        env={"TRIVY_CACHE_DIR": "/cache"},
    )
    assert result.stdout.strip() == "/cache"


def test_missing_binary_raises_sandbox_error(tmp_path: Path):
    with pytest.raises(SandboxError, match="not found"):
        run_sandboxed(["sureshot-no-such-binary"], cwd=tmp_path)


def test_duration_is_recorded(tmp_path: Path):
    result = run_sandboxed(_py("pass"), cwd=tmp_path)
    assert result.duration_ms >= 0


def test_stderr_captured_separately(tmp_path: Path):
    result = run_sandboxed(
        _py("import sys; sys.stderr.write('warn'); print('out')"), cwd=tmp_path
    )
    assert result.stdout.strip() == "out"
    assert "warn" in result.stderr


@pytest.mark.skipif(
    sys.platform in ("win32", "darwin"),
    reason="RLIMIT_AS is POSIX-only and unenforced on macOS/Darwin",
)
def test_memory_limit_kills_runaway_allocation(tmp_path: Path):
    limits = ProcessLimits(max_memory_bytes=64 << 20, timeout_seconds=20)
    result = run_sandboxed(
        _py("x = bytearray(512 * 1024 * 1024)"), cwd=tmp_path, limits=limits
    )
    assert result.exit_code != 0