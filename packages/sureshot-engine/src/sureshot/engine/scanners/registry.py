from __future__ import annotations

from typing import Callable

from sureshot.domain.repository import RepositoryProfile
from sureshot.engine.scanners.base import Scanner
from sureshot.engine.scanners.codeql.scanner import LANGUAGE_MAP as CODEQL_LANGUAGES
from sureshot.engine.scanners.codeql.scanner import CodeQLScanner
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner
from sureshot.engine.scanners.trivy.scanner import TrivyScanner

_FACTORIES: dict[str, Callable[..., Scanner]] = {
    "semgrep": SemgrepScanner,
    "trivy": TrivyScanner,
    "codeql": CodeQLScanner,
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

    Semgrep and Trivy always run. Trivy is not just an SCA tool — it also
    does secret scanning, which needs no dependency manifest at all, so it
    can't be gated on profile.ecosystems the way SCA-only logic would
    suggest (a repo with just a stray .env and no requirements.txt still
    needs it). CodeQL only runs when the profile's primary language has an
    extractor — building a database is expensive, and there's nothing to
    build one from otherwise.
    """
    scanners: list[Scanner] = [SemgrepScanner(profile=profile), TrivyScanner()]
    if profile is None or profile.primary_language in CODEQL_LANGUAGES:
        scanners.append(CodeQLScanner(profile=profile))
    return tuple(scanners)
