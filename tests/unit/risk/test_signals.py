import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, Package, SecretRef, SecurityFinding
from sureshot.engine.risk.signals import (
    PathRole,
    classify_path,
    fix_availability,
    dependency_depth,
    collect_signals,
)


def _finding(path="app/users.py", **overrides) -> SecurityFinding:
    base = dict(
        tool="semgrep", tool_version="1.0", rule_id="r", domain=Domain.SAST,
        title="t", severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=1, line_end=1),
    )
    return SecurityFinding(**(base | overrides))


@pytest.mark.parametrize("path,role", [
    ("app/users.py", PathRole.PRODUCTION),
    ("src/api/routes.py", PathRole.PRODUCTION),
    ("tests/test_users.py", PathRole.TEST),
    ("app/tests/helpers.py", PathRole.TEST),
    ("spec/user_spec.rb", PathRole.TEST),
    ("users_test.go", PathRole.TEST),
    ("examples/demo.py", PathRole.EXAMPLE),
    ("docs/snippets/sample.js", PathRole.EXAMPLE),
    ("scripts/migrate.py", PathRole.TOOLING),
    ("tools/build.sh", PathRole.TOOLING),
    ("migrations/0003_add.py", PathRole.TOOLING),
])
def test_path_roles(path: str, role: PathRole):
    assert classify_path(path) is role


def test_test_directory_beats_production_suffix():
    assert classify_path("tests/api/routes.py") is PathRole.TEST


def test_fixture_directory_is_test():
    assert classify_path("tests/fixtures/vulnerable_app.py") is PathRole.TEST


def test_fix_available_when_version_present():
    pkg = Package(name="flask", installed_version="2.0.0", fixed_version="2.0.1")
    assert fix_availability(pkg) == 1.0


def test_no_fix_available():
    pkg = Package(name="flask", installed_version="2.0.0")
    assert fix_availability(pkg) == 0.0


def test_direct_dependency_ranks_above_transitive():
    direct = Package(name="a", installed_version="1", is_direct=True)
    transitive = Package(name="b", installed_version="1", is_direct=False)
    assert dependency_depth(direct) > dependency_depth(transitive)


def test_unknown_directness_is_between():
    unknown = Package(name="c", installed_version="1")
    direct = Package(name="a", installed_version="1", is_direct=True)
    transitive = Package(name="b", installed_version="1", is_direct=False)
    assert dependency_depth(transitive) < dependency_depth(unknown) < dependency_depth(direct)


def test_signals_include_path_role():
    assert collect_signals(_finding("tests/test_a.py")).path_role is PathRole.TEST


def test_secret_in_test_is_still_flagged_as_secret():
    signals = collect_signals(_finding(
        "tests/conftest.py", domain=Domain.SECRET,
        secret=SecretRef(kind="aws-key", last_four="ABCD"), raw={},
    ))
    assert signals.path_role is PathRole.TEST