from __future__ import annotations

from typing import Callable

from sureshot.domain.repository import RepositoryProfile
from sureshot.engine.scanners.base import Scanner
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner
from sureshot.engine.scanners.trivy.scanner import TrivyScanner

_FACTORIES: dict[str, Callable[..., Scanner]] = {
    "semgrep": SemgrepScanner,
    "trivy": TrivyScanner,
}


class UnknownScanner(Exception):
    """No scanner is registered under the requested name."""


def available_scanners() -> tuple[str, ...]:
    return tuple(sorted(_FACTORIES))


def build_scanner(name: str, **kwargs: object) -> Scanner:
    try:
        factory = _FACTORIES[name]
    except KeyError:
        raise UnknownScanner(
            f"no scanner registered as {name!r}; available: {available_scanners()}"
        ) from None
    return factory(**kwargs)


def default_scanners(profile: RepositoryProfile | None = None) -> tuple[Scanner, ...]:
    """Select the scanners applicable to a profiled repository.

    Semgrep always runs — it degrades to a base ruleset with no profile.
    Trivy only runs when the profile shows at least one dependency ecosystem,
    since scanning a repo with no manifests can't find any SCA findings.
    """
    scanners: list[Scanner] = [SemgrepScanner(profile=profile)]
    if profile is None or profile.ecosystems:
        scanners.append(TrivyScanner())
    return tuple(scanners)
