import pytest

from sureshot.engine.ingest.fetch import FetchError, parse_repo_url


def test_parses_plain_github_url():
    ref = parse_repo_url("https://github.com/Nitesh050/ecommerce-platform")
    assert ref.host == "github.com"
    assert ref.display == "Nitesh050/ecommerce-platform"
    assert ref.clone_url == "https://github.com/Nitesh050/ecommerce-platform.git"
    assert ref.ref is None


def test_strips_dot_git_and_www():
    ref = parse_repo_url("https://www.github.com/acme/api.git")
    assert ref.host == "github.com"
    assert ref.name == "api"


def test_branch_taken_from_tree_url():
    assert parse_repo_url("https://github.com/acme/api/tree/feature/login").ref == "feature/login"


def test_explicit_ref_wins_over_tree_url():
    assert parse_repo_url("https://github.com/acme/api/tree/main", ref="dev").ref == "dev"


@pytest.mark.parametrize("url", [
    "http://github.com/acme/api",
    "git@github.com:acme/api.git",
    "file:///etc/passwd",
    "https://internal.example.com/acme/api",
    "https://user:token@github.com/acme/api",
    "https://github.com:8443/acme/api",
    "https://github.com/acme",
    "https://github.com/-upload-pack/api",
])
def test_rejects_unsafe_or_malformed_urls(url):
    with pytest.raises(FetchError):
        parse_repo_url(url)


@pytest.mark.parametrize("ref", ["--upload-pack=x", "../etc", "a..b"])
def test_rejects_unsafe_refs(ref):
    with pytest.raises(FetchError):
        parse_repo_url("https://github.com/acme/api", ref=ref)
