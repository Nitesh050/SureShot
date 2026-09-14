import pytest

from sureshot.persistence import rls


def test_enable_rls_produces_alter_table():
    sql = rls.enable_rls("scans")
    assert sql == "ALTER TABLE scans ENABLE ROW LEVEL SECURITY;"


def test_org_isolation_policy_default_column():
    sql = rls.org_isolation_policy("scans")
    assert "CREATE POLICY scans_org_isolation ON scans" in sql
    assert "org_id = current_setting('app.current_org_id', true)" in sql


def test_org_isolation_policy_custom_column():
    sql = rls.org_isolation_policy("findings", org_column="tenant_id")
    assert "tenant_id = current_setting" in sql


def test_drop_policy_default_name():
    sql = rls.drop_policy("scans")
    assert sql == "DROP POLICY IF EXISTS scans_org_isolation ON scans;"


def test_drop_policy_explicit_name():
    sql = rls.drop_policy("scans", policy_name="custom_policy")
    assert sql == "DROP POLICY IF EXISTS custom_policy ON scans;"


@pytest.mark.parametrize("bad_table", [
    "scans; DROP TABLE users;--",
    "scans WHERE 1=1",
    "scans--",
    "'; DROP TABLE scans;--",
    "scans OR 1=1",
    "",
    "123scans",
])
def test_malicious_table_name_is_rejected(bad_table):
    with pytest.raises(rls.InvalidIdentifier):
        rls.enable_rls(bad_table)


def test_malicious_column_name_is_rejected():
    with pytest.raises(rls.InvalidIdentifier):
        rls.org_isolation_policy("scans", org_column="org_id; DROP TABLE scans;--")


def test_valid_identifiers_with_underscores_pass():
    # must not raise
    rls.enable_rls("scan_findings")
    rls.org_isolation_policy("scan_findings", org_column="tenant_org_id")


def test_set_current_org_issues_set_config():
    class FakeCursor:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params=()):
            self.calls.append((sql, params))

    cursor = FakeCursor()
    rls.set_current_org(cursor, "org_1")
    assert len(cursor.calls) == 1
    sql, params = cursor.calls[0]
    assert "set_config" in sql
    assert "app.current_org_id" in sql
    assert params == ("org_1",)
