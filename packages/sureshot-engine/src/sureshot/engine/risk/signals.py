from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sureshot.domain.finding import Package, SecurityFinding


class PathRole(StrEnum):
    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    TOOLING = "tooling"


_TEST_DIRS = frozenset({"test", "tests", "spec", "specs", "__tests__", "testing",
                        "fixtures", "testdata"})
_EXAMPLE_DIRS = frozenset({"example", "examples", "demo", "demos", "samples",
                           "docs", "doc", "sample"})
_TOOLING_DIRS = frozenset({"scripts", "script", "tools", "tooling", "bin",
                           "migrations", "migration", "ci", "hack"})

_TEST_FILE = re.compile(r"(^test_|_test\.|\.test\.|_spec\.|\.spec\.|^conftest\.)",
                        re.IGNORECASE)


@dataclass(frozen=True)
class RiskSignals:
    path_role: PathRole
    fix_available: float
    dependency_weight: float


def classify_path(file_path: str) -> PathRole:
    parts = [p.lower() for p in file_path.split("/")]
    directories, filename = set(parts[:-1]), parts[-1]

    if directories & _TEST_DIRS or _TEST_FILE.search(filename):
        return PathRole.TEST
    if directories & _EXAMPLE_DIRS:
        return PathRole.EXAMPLE
    if directories & _TOOLING_DIRS:
        return PathRole.TOOLING
    return PathRole.PRODUCTION


def fix_availability(package: Package | None) -> float:
    if package is None:
        return 0.5
    return 1.0 if package.fixed_version else 0.0


def dependency_depth(package: Package | None) -> float:
    if package is None or package.is_direct is None:
        return 0.5
    return 1.0 if package.is_direct else 0.25


def collect_signals(finding: SecurityFinding) -> RiskSignals:
    return RiskSignals(
        path_role=classify_path(finding.location.file_path),
        fix_available=fix_availability(finding.package),
        dependency_weight=dependency_depth(finding.package),
    )