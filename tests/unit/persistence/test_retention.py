import sqlite3
from datetime import UTC, datetime

import pytest

from sureshot.persistence import retention

NOW = datetime(2026, 2, 1, tzinfo=UTC)


@pytest.fixture
def cursor():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(retention.DDL)
    yield cur
    conn.close()


def _insert(cursor, scan_id, org_id, started_at):
    cursor.execute(
        "INSERT INTO scans (scan_id, org_id, started_at) VALUES (?, ?, ?)",
        (scan_id, org_id, started_at),
    )


def test_scan_older_than_window_is_due(cursor):
    _insert(cursor, "sc_old", "org_1", "2020-01-01T00:00:00+00:00")
    due = retention.scans_due_for_purge(cursor, "org_1", retention_days=30, now=NOW)
    assert due == ["sc_old"]


def test_scan_within_window_is_not_due(cursor):
    _insert(cursor, "sc_new", "org_1", "2026-01-28T00:00:00+00:00")
    due = retention.scans_due_for_purge(cursor, "org_1", retention_days=30, now=NOW)
    assert due == []


def test_purge_only_deletes_due_scans(cursor):
    _insert(cursor, "sc_old", "org_1", "2020-01-01T00:00:00+00:00")
    _insert(cursor, "sc_new", "org_1", "2026-01-28T00:00:00+00:00")
    deleted = retention.purge_expired_scans(cursor, "org_1", retention_days=30, now=NOW)
    assert deleted == 1
    cursor.execute("SELECT scan_id FROM scans")
    assert cursor.fetchall() == [("sc_new",)]


def test_purge_is_scoped_to_org(cursor):
    _insert(cursor, "sc_1", "org_1", "2020-01-01T00:00:00+00:00")
    _insert(cursor, "sc_2", "org_2", "2020-01-01T00:00:00+00:00")
    deleted = retention.purge_expired_scans(cursor, "org_1", retention_days=30, now=NOW)
    assert deleted == 1
    cursor.execute("SELECT scan_id FROM scans")
    assert cursor.fetchall() == [("sc_2",)]


def test_purge_returns_zero_when_nothing_due(cursor):
    _insert(cursor, "sc_new", "org_1", "2026-01-28T00:00:00+00:00")
    assert retention.purge_expired_scans(cursor, "org_1", retention_days=30, now=NOW) == 0


def test_empty_table_purges_nothing(cursor):
    assert retention.purge_expired_scans(cursor, "org_1", retention_days=30, now=NOW) == 0
