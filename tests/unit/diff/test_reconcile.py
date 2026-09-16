from sureshot.domain.enums import Domain, Severity
from sureshot.domain.finding import Location, SecurityFinding
from sureshot.engine.context.snippet import Snippet, snippet_key
from sureshot.engine.diff.baseline import Baseline
from sureshot.engine.diff.changed import filter_to_changed_files
from sureshot.engine.diff.reconcile import reconcile
from sureshot.engine.normalize.fingerprint import apply_fingerprints


def _finding(issue_id, path="app.py") -> SecurityFinding:
    return SecurityFinding(
        instance_id=f"in_{issue_id}", issue_id=issue_id,
        tool="semgrep", tool_version="1.0", rule_id="r1",
        domain=Domain.SAST, title="t", severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=1, line_end=1),
    )


def _raw(path="app.py", line=1, tool="semgrep", rule_id="python.sqli") -> SecurityFinding:
    """A finding with no issue_id yet, for fingerprinting through the real
    pipeline machinery — needed for rename tests, where issue_id must
    actually change with file_path the way compute_issue_id really behaves,
    not just however the _finding() fixture's caller happens to set it."""
    return SecurityFinding(
        tool=tool, tool_version="1.0", rule_id=rule_id,
        domain=Domain.SAST, title="t", severity=Severity.HIGH, cwe_ids=("CWE-89",),
        location=Location(file_path=path, line_start=line, line_end=line),
    )


def _fingerprinted(finding: SecurityFinding, code: str) -> SecurityFinding:
    key = snippet_key(finding.location)
    snippet = Snippet(matched=code, context=code, context_start=finding.location.line_start)
    return apply_fingerprints((finding,), {key: snippet})[0]


def test_no_baseline_means_everything_is_new():
    result = reconcile((_finding("is_1"),), None)
    assert result.new == (_finding("is_1"),)
    assert result.persisting == ()
    assert result.fixed_issue_ids == frozenset()


def test_issue_in_both_is_persisting():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.persisting == (_finding("is_1"),)
    assert result.new == ()


def test_issue_only_in_current_is_new():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"), _finding("is_2")), baseline)
    assert {f.issue_id for f in result.new} == {"is_2"}
    assert {f.issue_id for f in result.persisting} == {"is_1"}


def test_issue_only_in_baseline_is_fixed():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"), _finding("is_2")))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.fixed_issue_ids == frozenset({"is_2"})


def test_empty_current_with_baseline_fixes_everything():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((), baseline)
    assert result.fixed_issue_ids == frozenset({"is_1"})
    assert result.new == ()


def test_regressed_true_when_new_findings_exist():
    baseline = Baseline.from_findings("sc_0", ())
    result = reconcile((_finding("is_1"),), baseline)
    assert result.regressed is True


def test_regressed_false_when_nothing_new():
    baseline = Baseline.from_findings("sc_0", (_finding("is_1"),))
    result = reconcile((_finding("is_1"),), baseline)
    assert result.regressed is False


def test_identical_scan_twice_is_fully_persisting():
    findings = (_finding("is_1"), _finding("is_2"))
    baseline = Baseline.from_findings("sc_0", findings)
    result = reconcile(findings, baseline)
    assert len(result.persisting) == 2
    assert result.new == ()
    assert result.fixed_issue_ids == frozenset()


def test_filter_to_changed_files_keeps_only_matching_paths():
    findings = (_finding("is_1", path="a.py"), _finding("is_2", path="b.py"))
    filtered = filter_to_changed_files(findings, frozenset({"a.py"}))
    assert len(filtered) == 1
    assert filtered[0].location.file_path == "a.py"


def test_filter_to_changed_files_empty_set_drops_everything():
    findings = (_finding("is_1"),)
    assert filter_to_changed_files(findings, frozenset()) == ()


# ---- rename detection ----
# A plain git mv changes compute_issue_id (it's keyed partly on file_path,
# verified against real GitHub alert behavior earlier in this project), so
# naive reconciliation sees a renamed file as one issue fixed plus one new
# issue — silently discarding whatever triage state was attached to the old
# issue_id. These tests cover the content-signature fallback that recognizes
# the rename instead.

CODE = "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\""

def test_identical_code_moved_to_new_file_is_recognized_as_renamed():
    before = _fingerprinted(_raw(path="old/users.py"), CODE)
    after = _fingerprinted(_raw(path="new/users.py"), CODE)
    assert before.issue_id != after.issue_id  # sanity: rename really does change issue_id

    baseline = Baseline.from_findings(
        "sc_0", (before,), {snippet_key(before.location): Snippet(CODE, CODE, 1)}
    )
    current_snippets = {snippet_key(after.location): Snippet(CODE, CODE, 1)}
    result = reconcile((after,), baseline, current_snippets)

    assert result.new == ()
    assert result.fixed_issue_ids == frozenset()
    assert len(result.renamed) == 1
    assert result.renamed[0].finding.issue_id == after.issue_id
    assert result.renamed[0].previous_issue_id == before.issue_id


def test_rename_does_not_count_as_regressed():
    before = _fingerprinted(_raw(path="old/users.py"), CODE)
    after = _fingerprinted(_raw(path="new/users.py"), CODE)
    baseline = Baseline.from_findings(
        "sc_0", (before,), {snippet_key(before.location): Snippet(CODE, CODE, 1)}
    )
    current_snippets = {snippet_key(after.location): Snippet(CODE, CODE, 1)}
    result = reconcile((after,), baseline, current_snippets)
    assert result.regressed is False


def test_carried_state_map_points_new_issue_id_at_old_one():
    before = _fingerprinted(_raw(path="old/users.py"), CODE)
    after = _fingerprinted(_raw(path="new/users.py"), CODE)
    baseline = Baseline.from_findings(
        "sc_0", (before,), {snippet_key(before.location): Snippet(CODE, CODE, 1)}
    )
    current_snippets = {snippet_key(after.location): Snippet(CODE, CODE, 1)}
    result = reconcile((after,), baseline, current_snippets)
    assert result.carried_state_map == {after.issue_id: before.issue_id}


def test_rename_plus_real_content_change_is_not_matched():
    """A moved file whose flagged code also genuinely changed is a real fix
    plus a real new finding — not a rename to recognize."""
    before = _fingerprinted(_raw(path="old/users.py"), CODE)
    changed_code = "query = db.safe_query(username)"
    after = _fingerprinted(_raw(path="new/users.py"), changed_code)

    baseline = Baseline.from_findings(
        "sc_0", (before,), {snippet_key(before.location): Snippet(CODE, CODE, 1)}
    )
    current_snippets = {snippet_key(after.location): Snippet(changed_code, changed_code, 1)}
    result = reconcile((after,), baseline, current_snippets)

    assert result.renamed == ()
    assert {f.issue_id for f in result.new} == {after.issue_id}
    assert result.fixed_issue_ids == frozenset({before.issue_id})


def test_baseline_without_snippets_falls_back_to_exact_matching_only():
    """A baseline built without snippet data (content_signatures empty)
    can't recognize renames — it degrades to the original exact-match
    behavior rather than crashing or matching spuriously."""
    before = _fingerprinted(_raw(path="old/users.py"), CODE)
    after = _fingerprinted(_raw(path="new/users.py"), CODE)
    baseline = Baseline.from_findings("sc_0", (before,))  # no snippets passed
    result = reconcile((after,), baseline)  # no current_snippets passed either

    assert result.renamed == ()
    assert {f.issue_id for f in result.new} == {after.issue_id}
    assert result.fixed_issue_ids == frozenset({before.issue_id})


def test_two_identical_disappearances_only_consume_one_match_each():
    """Two baseline findings with identical content (e.g. copy-pasted code
    in two files) and one reappearing must not double-match."""
    before_a = _fingerprinted(_raw(path="old/a.py"), CODE)
    before_b = _fingerprinted(_raw(path="old/b.py"), CODE)
    after = _fingerprinted(_raw(path="new/a.py"), CODE)

    snippets_before = {
        snippet_key(before_a.location): Snippet(CODE, CODE, 1),
        snippet_key(before_b.location): Snippet(CODE, CODE, 1),
    }
    baseline = Baseline.from_findings("sc_0", (before_a, before_b), snippets_before)
    current_snippets = {snippet_key(after.location): Snippet(CODE, CODE, 1)}
    result = reconcile((after,), baseline, current_snippets)

    assert len(result.renamed) == 1
    assert result.renamed[0].finding.issue_id == after.issue_id
    # exactly one of the two identical originals is treated as fixed; the
    # other is claimed by the rename match
    assert len(result.fixed_issue_ids) == 1
    assert result.fixed_issue_ids | {result.renamed[0].previous_issue_id} == {
        before_a.issue_id, before_b.issue_id,
    }
