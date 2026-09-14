import pytest

from sureshot.domain.repository import Ecosystem, RepositoryProfile
from sureshot.engine.scanners.registry import (
    UnknownScanner,
    available_scanners,
    build_scanner,
    default_scanners,
)
from sureshot.engine.scanners.semgrep.scanner import SemgrepScanner
from sureshot.engine.scanners.trivy.scanner import TrivyScanner


def _profile(**overrides) -> RepositoryProfile:
    base = dict(total_files=1, scanned_files=1, skipped_files=0, total_bytes=1)
    return RepositoryProfile(**(base | overrides))


def test_available_scanners_lists_both():
    assert available_scanners() == ("semgrep", "trivy")


def test_build_scanner_by_name():
    assert isinstance(build_scanner("semgrep"), SemgrepScanner)
    assert isinstance(build_scanner("trivy"), TrivyScanner)


def test_unknown_scanner_name_raises():
    with pytest.raises(UnknownScanner):
        build_scanner("nope")


def test_default_scanners_always_includes_semgrep():
    names = {s.name for s in default_scanners(_profile())}
    assert "semgrep" in names


def test_trivy_skipped_when_no_ecosystems():
    names = {s.name for s in default_scanners(_profile())}
    assert names == {"semgrep"}


def test_trivy_included_when_ecosystem_present():
    profile = _profile(
        ecosystems=(Ecosystem(name="pip", manifests=("requirements.txt",)),)
    )
    names = {s.name for s in default_scanners(profile)}
    assert names == {"semgrep", "trivy"}


def test_default_scanners_with_no_profile_includes_trivy():
    names = {s.name for s in default_scanners(None)}
    assert names == {"semgrep", "trivy"}
