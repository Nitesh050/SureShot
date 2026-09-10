from pathlib import Path

from sureshot.domain.enums import Coverage, Domain
from sureshot.engine.ingest.profiler import ProfilerLimits, profile_repository


def _write(root: Path, rel: str, content: str = "x") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_counts_files_and_detects_language(tmp_path: Path):
    _write(tmp_path, "app/main.py", "print(1)\n" * 10)
    _write(tmp_path, "app/util.py", "x = 1\n")
    profile = profile_repository(tmp_path)
    assert profile.scanned_files == 2
    assert profile.primary_language == "Python"


def test_ranks_languages_by_bytes_not_file_count(tmp_path: Path):
    _write(tmp_path, "a.js", "x")
    _write(tmp_path, "b.js", "x")
    _write(tmp_path, "big.py", "y" * 5000)
    assert profile_repository(tmp_path).primary_language == "Python"


def test_vendor_directories_excluded(tmp_path: Path):
    _write(tmp_path, "app/main.py")
    _write(tmp_path, "node_modules/left-pad/index.js")
    _write(tmp_path, ".git/objects/ab/cdef")
    _write(tmp_path, "venv/lib/site.py")
    profile = profile_repository(tmp_path)
    assert profile.scanned_files == 1
    assert profile.skipped_files == 3


def test_binary_files_counted_but_not_language_typed(tmp_path: Path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    _write(tmp_path, "app.py")
    profile = profile_repository(tmp_path)
    assert profile.scanned_files == 2
    assert [l.name for l in profile.languages] == ["Python"]


def test_lockfile_present_means_full_sca_coverage(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "flask==2.0.0")
    _write(tmp_path, "requirements.lock", "flask==2.0.0")
    profile = profile_repository(tmp_path)
    assert profile.coverage_for(Domain.SCA) is Coverage.FULL


def test_manifest_without_lockfile_is_partial_coverage(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "flask")
    profile = profile_repository(tmp_path)
    assert profile.coverage_for(Domain.SCA) is Coverage.PARTIAL
    note = next(n for n in profile.coverage if n.domain is Domain.SCA)
    assert "lockfile" in note.reason


def test_no_manifests_means_no_sca_coverage(tmp_path: Path):
    _write(tmp_path, "app/main.py")
    profile = profile_repository(tmp_path)
    assert profile.coverage_for(Domain.SCA) is Coverage.NONE


def test_mixed_ecosystems_detected(tmp_path: Path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, "pyproject.toml", "")
    names = {e.name for e in profile_repository(tmp_path).ecosystems}
    assert names == {"npm", "pip"}


def test_partial_coverage_when_only_some_ecosystems_locked(tmp_path: Path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "package-lock.json", "{}")
    _write(tmp_path, "requirements.txt", "flask")
    assert profile_repository(tmp_path).coverage_for(Domain.SCA) is Coverage.PARTIAL


def test_sast_coverage_requires_a_supported_language(tmp_path: Path):
    _write(tmp_path, "notes.txt", "hello")
    assert profile_repository(tmp_path).coverage_for(Domain.SAST) is Coverage.NONE


def test_oversized_files_skipped(tmp_path: Path):
    _write(tmp_path, "huge.py", "x" * 5000)
    _write(tmp_path, "small.py", "x")
    profile = profile_repository(tmp_path, ProfilerLimits(max_file_bytes=1000))
    assert profile.scanned_files == 1
    assert profile.skipped_files == 1


def test_walk_does_not_follow_symlinked_directories(tmp_path: Path):
    outside = tmp_path.parent / "outside_tree"
    outside.mkdir(exist_ok=True)
    (outside / "secret.py").write_text("x")
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, "app.py")
    (root / "link").symlink_to(outside, target_is_directory=True)
    assert profile_repository(root).scanned_files == 1


def test_empty_repository_profiles_cleanly(tmp_path: Path):
    profile = profile_repository(tmp_path)
    assert profile.scanned_files == 0
    assert profile.primary_language is None
    assert profile.coverage_for(Domain.SAST) is Coverage.NONE