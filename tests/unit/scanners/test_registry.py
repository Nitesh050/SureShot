import pytest

from sureshot.domain.repository import Ecosystem, LanguageStat, RepositoryProfile
from sureshot.engine.scanners.codeql.scanner import CodeQLScanner
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


def test_available_scanners_lists_all_three():
    assert available_scanners() == ("codeql", "semgrep", "trivy")


def test_build_scanner_by_name():
    assert isinstance(build_scanner("semgrep"), SemgrepScanner)
    assert isinstance(build_scanner("trivy"), TrivyScanner)
    assert isinstance(build_scanner("codeql"), CodeQLScanner)


def test_unknown_scanner_name_raises():
    with pytest.raises(UnknownScanner):
        build_scanner("nope")


def test_default_scanners_always_includes_semgrep():
    names = {s.name for s in default_scanners(_profile())}
    assert "semgrep" in names


def test_codeql_skipped_with_no_language_signal():
    names = {s.name for s in default_scanners(_profile())}
    assert names == {"semgrep", "trivy"}


def test_trivy_runs_regardless_of_ecosystems():
    """Trivy also does secret scanning, which needs no dependency manifest —
    it must not be gated on profile.ecosystems."""
    profile = _profile()
    assert profile.ecosystems == ()
    names = {s.name for s in default_scanners(profile)}
    assert "trivy" in names


def test_trivy_included_when_ecosystem_present():
    profile = _profile(
        ecosystems=(Ecosystem(name="pip", manifests=("requirements.txt",)),)
    )
    names = {s.name for s in default_scanners(profile)}
    assert "trivy" in names


def test_codeql_included_when_supported_language_present():
    profile = _profile(languages=(LanguageStat(name="Python", files=1, bytes=100),))
    names = {s.name for s in default_scanners(profile)}
    assert "codeql" in names


def test_codeql_skipped_for_unsupported_language():
    profile = _profile(languages=(LanguageStat(name="PHP", files=1, bytes=100),))
    names = {s.name for s in default_scanners(profile)}
    assert "codeql" not in names


def test_default_scanners_with_no_profile_includes_all_three():
    names = {s.name for s in default_scanners(None)}
    assert names == {"semgrep", "trivy", "codeql"}
