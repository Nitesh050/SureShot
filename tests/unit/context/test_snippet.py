from pathlib import Path

import pytest

from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.context.snippet import (
    SnippetLimits,
    extract_snippet,
    extract_snippets,
    snippet_key,
)

SOURCE = "\n".join(f"line {i}" for i in range(1, 21)) + "\n"


def _finding(path="a.py", start=10, end=10) -> SecurityFinding:
    return SecurityFinding(
        tool="semgrep", tool_version="1.0", rule_id="r", domain=Domain.SAST,
        title="t", severity=Severity.HIGH,
        location=Location(file_path=path, line_start=start, line_end=end),
    )


def test_extracts_matched_lines(tmp_path: Path):
    (tmp_path / "a.py").write_text(SOURCE)
    snippet = extract_snippet(tmp_path, Location(file_path="a.py", line_start=10, line_end=12))
    assert snippet.matched == "line 10\nline 11\nline 12"


def test_includes_surrounding_context(tmp_path: Path):
    (tmp_path / "a.py").write_text(SOURCE)
    snippet = extract_snippet(
        tmp_path, Location(file_path="a.py", line_start=10, line_end=10),
        SnippetLimits(context_lines=3),
    )
    assert "line 7" in snippet.context
    assert "line 13" in snippet.context
    assert snippet.context_start == 7


def test_context_clamped_at_file_start(tmp_path: Path):
    (tmp_path / "a.py").write_text(SOURCE)
    snippet = extract_snippet(
        tmp_path, Location(file_path="a.py", line_start=2, line_end=2),
        SnippetLimits(context_lines=10),
    )
    assert snippet.context_start == 1


def test_context_clamped_at_file_end(tmp_path: Path):
    (tmp_path / "a.py").write_text(SOURCE)
    snippet = extract_snippet(
        tmp_path, Location(file_path="a.py", line_start=19, line_end=20),
        SnippetLimits(context_lines=10),
    )
    assert snippet.context.strip().endswith("line 20")


def test_line_beyond_end_of_file_returns_empty_match(tmp_path: Path):
    (tmp_path / "a.py").write_text("one\ntwo\n")
    snippet = extract_snippet(tmp_path, Location(file_path="a.py", line_start=99, line_end=99))
    assert snippet.matched == ""
    assert snippet.truncated is True


def test_missing_file_returns_empty_snippet(tmp_path: Path):
    snippet = extract_snippet(tmp_path, Location(file_path="gone.py", line_start=1, line_end=1))
    assert snippet.matched == ""


def test_path_escape_is_refused(tmp_path: Path):
    with pytest.raises(ValueError, match="outside"):
        extract_snippet(tmp_path, Location(file_path="sub/ok.py", line_start=1, line_end=1),
                        SnippetLimits(), _override="../../etc/passwd")


def test_oversized_match_is_truncated(tmp_path: Path):
    (tmp_path / "a.py").write_text("x" * 200 + "\n")
    snippet = extract_snippet(
        tmp_path, Location(file_path="a.py", line_start=1, line_end=1),
        SnippetLimits(max_chars=50),
    )
    assert len(snippet.matched) <= 50
    assert snippet.truncated is True


def test_binary_file_yields_empty(tmp_path: Path):
    (tmp_path / "a.py").write_bytes(b"\x00\x01\x02" * 50)
    assert extract_snippet(tmp_path, Location(file_path="a.py", line_start=1, line_end=1)).matched == ""


def test_two_findings_in_one_file_get_distinct_snippets(tmp_path: Path):
    (tmp_path / "a.py").write_text(SOURCE)
    findings = (_finding(start=3, end=3), _finding(start=15, end=15))
    snippets = extract_snippets(tmp_path, findings)
    assert snippets[snippet_key(findings[0].location)].matched == "line 3"
    assert snippets[snippet_key(findings[1].location)].matched == "line 15"


def test_file_is_read_once_per_file(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text(SOURCE)
    reads = []
    original = Path.read_bytes
    monkeypatch.setattr(
        Path, "read_bytes",
        lambda self, *a, **k: (reads.append(self), original(self, *a, **k))[1],
    )
    extract_snippets(tmp_path, tuple(_finding(start=i, end=i) for i in range(1, 11)))
    assert len(reads) == 1