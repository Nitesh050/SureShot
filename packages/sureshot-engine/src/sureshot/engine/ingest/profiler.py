from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from sureshot.domain.enums import Coverage, Domain
from sureshot.domain.repository import (
    CoverageNote,
    Ecosystem,
    LanguageStat,
    RepositoryProfile,
)

EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    "venv", ".venv", "env", "virtualenv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "target", "out",
    ".tox", ".nox", ".gradle", ".idea", ".vscode",
    "site-packages", ".next", ".nuxt",
})

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala",
    ".go": "Go", ".rs": "Rust",
    ".rb": "Ruby", ".php": "PHP",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".cs": "C#", ".swift": "Swift",
    ".sh": "Shell", ".bash": "Shell",
    ".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML",
}

_ECOSYSTEMS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "pip": (
        frozenset({"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"}),
        frozenset({"requirements.lock", "poetry.lock", "Pipfile.lock", "uv.lock"}),
    ),
    "npm": (
        frozenset({"package.json"}),
        frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}),
    ),
    "go": (frozenset({"go.mod"}), frozenset({"go.sum"})),
    "cargo": (frozenset({"Cargo.toml"}), frozenset({"Cargo.lock"})),
    "maven": (frozenset({"pom.xml"}), frozenset()),
    "gradle": (frozenset({"build.gradle", "build.gradle.kts"}), frozenset({"gradle.lockfile"})),
    "bundler": (frozenset({"Gemfile"}), frozenset({"Gemfile.lock"})),
    "composer": (frozenset({"composer.json"}), frozenset({"composer.lock"})),
}

SAST_LANGUAGES = frozenset({
    "Python", "JavaScript", "TypeScript", "Java", "Go", "Rust",
    "Ruby", "PHP", "C", "C++", "C#", "Kotlin", "Scala", "Swift",
})


@dataclass(frozen=True)
class ProfilerLimits:
    max_file_bytes: int = 5 << 20
    max_files: int = 200_000


def _is_probably_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return b"\x00" in handle.read(8192)
    except OSError:
        return True


def _sca_coverage(ecosystems: tuple[Ecosystem, ...]) -> CoverageNote:
    if not ecosystems:
        return CoverageNote(
            domain=Domain.SCA,
            coverage=Coverage.NONE,
            reason="no dependency manifests found",
        )

    locked = [e for e in ecosystems if e.has_lockfile]
    if len(locked) == len(ecosystems):
        return CoverageNote(
            domain=Domain.SCA,
            coverage=Coverage.FULL,
            reason=f"lockfiles present for {', '.join(e.name for e in ecosystems)}",
        )

    missing = sorted(e.name for e in ecosystems if not e.has_lockfile)
    return CoverageNote(
        domain=Domain.SCA,
        coverage=Coverage.PARTIAL,
        reason=(
            f"no lockfile for {', '.join(missing)}; "
            "dependency versions cannot be resolved and vulnerabilities may be missed"
        ),
    )


def _sast_coverage(languages: tuple[LanguageStat, ...]) -> CoverageNote:
    supported = [l.name for l in languages if l.name in SAST_LANGUAGES]
    if not supported:
        return CoverageNote(
            domain=Domain.SAST,
            coverage=Coverage.NONE,
            reason="no files in a supported source language",
        )
    return CoverageNote(
        domain=Domain.SAST,
        coverage=Coverage.FULL,
        reason=f"source detected for {', '.join(sorted(supported))}",
    )


def profile_repository(
    root: Path,
    limits: ProfilerLimits | None = None,
) -> RepositoryProfile:
    limits = limits or ProfilerLimits()
    root = root.resolve()

    lang_files: dict[str, int] = {}
    lang_bytes: dict[str, int] = {}
    manifests: dict[str, set[str]] = {}
    lockfiles: dict[str, set[str]] = {}

    total = scanned = skipped = 0
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDED_DIRS and not os.path.islink(os.path.join(dirpath, d))
        ]

        current = Path(dirpath)
        for name in filenames:
            path = current / name
            if path.is_symlink():
                skipped += 1
                continue

            total += 1
            if total > limits.max_files:
                skipped += 1
                continue

            try:
                size = path.stat().st_size
            except OSError:
                skipped += 1
                continue

            if size > limits.max_file_bytes:
                skipped += 1
                continue

            scanned += 1
            total_bytes += size

            for eco, (manifest_names, lock_names) in _ECOSYSTEMS.items():
                if name in manifest_names:
                    manifests.setdefault(eco, set()).add(name)
                if name in lock_names:
                    lockfiles.setdefault(eco, set()).add(name)

            language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
            if language and not _is_probably_binary(path):
                lang_files[language] = lang_files.get(language, 0) + 1
                lang_bytes[language] = lang_bytes.get(language, 0) + size

    skipped += _count_excluded(root)

    languages = tuple(
        LanguageStat(name=name, files=lang_files[name], bytes=lang_bytes[name])
        for name in sorted(lang_bytes, key=lambda n: -lang_bytes[n])
    )
    ecosystems = tuple(
        Ecosystem(
            name=eco,
            manifests=tuple(sorted(manifests.get(eco, ()))),
            lockfiles=tuple(sorted(lockfiles.get(eco, ()))),
        )
        for eco in sorted(set(manifests) | set(lockfiles))
        if eco in manifests
    )

    return RepositoryProfile(
        total_files=total,
        scanned_files=scanned,
        skipped_files=skipped,
        total_bytes=total_bytes,
        languages=languages,
        ecosystems=ecosystems,
        coverage=(_sast_coverage(languages), _sca_coverage(ecosystems)),
    )


def _count_excluded(root: Path) -> int:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        parts = set(Path(dirpath).relative_to(root).parts)
        if parts & EXCLUDED_DIRS:
            count += len(filenames)
    return count