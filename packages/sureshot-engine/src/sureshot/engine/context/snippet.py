from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from sureshot.domain.finding import Location, SecurityFinding

SnippetKey = tuple[str, int, int]


def snippet_key(location: Location) -> SnippetKey:
    return (location.file_path, location.line_start, location.line_end)


@dataclass(frozen=True)
class SnippetLimits:
    context_lines: int = 8
    max_chars: int = 4000
    max_file_bytes: int = 2 << 20


@dataclass(frozen=True)
class Snippet:
    matched: str
    context: str
    context_start: int
    truncated: bool = False


_EMPTY = Snippet(matched="", context="", context_start=1, truncated=True)


def _read_lines(root: Path, file_path: str, limits: SnippetLimits) -> list[str] | None:
    target = (root / file_path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError(f"snippet path is outside the scan root: {file_path}")
    try:
        if target.stat().st_size > limits.max_file_bytes:
            return None
        raw = target.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace").splitlines()


def _slice(lines: list[str], location: Location, limits: SnippetLimits) -> Snippet:
    total = len(lines)
    start = location.line_start
    end = min(location.line_end, total)

    if start > total:
        return _EMPTY

    matched = "\n".join(lines[start - 1 : end])
    truncated = False
    if len(matched) > limits.max_chars:
        matched = matched[: limits.max_chars]
        truncated = True

    ctx_start = max(1, start - limits.context_lines)
    ctx_end = min(total, end + limits.context_lines)
    context = "\n".join(lines[ctx_start - 1 : ctx_end])
    if len(context) > limits.max_chars * 2:
        context = context[: limits.max_chars * 2]
        truncated = True

    return Snippet(matched=matched, context=context, context_start=ctx_start,
                   truncated=truncated)


def extract_snippet(
    root: Path,
    location: Location,
    limits: SnippetLimits | None = None,
    _override: str | None = None,
) -> Snippet:
    limits = limits or SnippetLimits()
    lines = _read_lines(root, _override or location.file_path, limits)
    return _EMPTY if lines is None else _slice(lines, location, limits)


def extract_snippets(
    root: Path,
    findings: Iterable[SecurityFinding],
    limits: SnippetLimits | None = None,
) -> dict[SnippetKey, Snippet]:
    limits = limits or SnippetLimits()
    cache: dict[str, list[str] | None] = {}
    out: dict[SnippetKey, Snippet] = {}

    for finding in findings:
        path = finding.location.file_path
        if path not in cache:
            cache[path] = _read_lines(root, path, limits)
        lines = cache[path]
        out[snippet_key(finding.location)] = (
            _EMPTY if lines is None else _slice(lines, finding.location, limits)
        )
    return out
