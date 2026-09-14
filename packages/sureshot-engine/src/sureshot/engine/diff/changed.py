from __future__ import annotations

from sureshot.domain.finding import SecurityFinding


def filter_to_changed_files(
    findings: tuple[SecurityFinding, ...],
    changed_paths: frozenset[str],
) -> tuple[SecurityFinding, ...]:
    """Keep only findings in files a diff (e.g. a PR) actually touched.

    Lets a scan report only what's newly relevant instead of every
    pre-existing finding in files the change never touched.
    """
    return tuple(f for f in findings if f.location.file_path in changed_paths)
