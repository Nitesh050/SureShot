import sqlite3

import pytest

from sureshot.persistence import outbox


@pytest.fixture
def cursor():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(outbox.DDL)
    yield cur
    conn.close()


def test_enqueue_returns_an_event_id(cursor):
    event_id = outbox.enqueue(cursor, "org_1", "scan.completed", {"scan_id": "sc_1"})
    assert event_id.startswith("evt_")


def test_enqueued_event_is_unpublished(cursor):
    outbox.enqueue(cursor, "org_1", "scan.completed", {"scan_id": "sc_1"})
    pending = outbox.fetch_unpublished(cursor)
    assert len(pending) == 1
    assert pending[0].event_type == "scan.completed"
    assert pending[0].payload == {"scan_id": "sc_1"}
    assert pending[0].published_at is None


def test_mark_published_removes_from_unpublished(cursor):
    event_id = outbox.enqueue(cursor, "org_1", "scan.completed", {})
    outbox.mark_published(cursor, event_id)
    assert outbox.fetch_unpublished(cursor) == []


def test_fetch_unpublished_respects_limit(cursor):
    for i in range(5):
        outbox.enqueue(cursor, "org_1", "scan.completed", {"i": i})
    assert len(outbox.fetch_unpublished(cursor, limit=2)) == 2


def test_fetch_unpublished_orders_oldest_first(cursor):
    first = outbox.enqueue(cursor, "org_1", "a", {})
    second = outbox.enqueue(cursor, "org_1", "b", {})
    pending = outbox.fetch_unpublished(cursor)
    assert [e.event_id for e in pending] == [first, second]


def test_payload_round_trips_nested_structure(cursor):
    payload = {"scan_id": "sc_1", "findings": [{"rule_id": "r1"}, {"rule_id": "r2"}]}
    outbox.enqueue(cursor, "org_1", "scan.completed", payload)
    pending = outbox.fetch_unpublished(cursor)
    assert pending[0].payload == payload


def test_empty_outbox_has_nothing_unpublished(cursor):
    assert outbox.fetch_unpublished(cursor) == []
