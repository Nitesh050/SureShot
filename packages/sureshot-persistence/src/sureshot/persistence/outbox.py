from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

DDL = """
CREATE TABLE IF NOT EXISTS outbox_events (
    event_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    published_at TEXT
)
"""


class Cursor(Protocol):
    """The subset of DB-API 2.0 a cursor needs. Statements here use
    qmark-style `?` placeholders (sqlite3's native style, and how this
    module is verified — see tests/unit/persistence). DB-API 2.0 does not
    standardize paramstyle: psycopg uses `%s` instead, so a Postgres
    deployment needs these SQL strings adapted, not dropped in as-is."""

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any: ...
    def fetchall(self) -> list[tuple[Any, ...]]: ...
    rowcount: int


@dataclass(frozen=True)
class OutboxEvent:
    event_id: str
    org_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
    published_at: datetime | None = None


def enqueue(cursor: Cursor, org_id: str, event_type: str, payload: dict[str, Any]) -> str:
    """Insert an outbox row. Call this in the SAME transaction as the write
    it's reporting on — that's the entire point of the outbox pattern: the
    event can never be committed without the state change it describes, or
    vice versa, even if the publisher crashes before relaying it."""
    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    cursor.execute(
        "INSERT INTO outbox_events (event_id, org_id, event_type, payload, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (event_id, org_id, event_type, json.dumps(payload), datetime.now(UTC).isoformat()),
    )
    return event_id


def fetch_unpublished(cursor: Cursor, limit: int = 100) -> list[OutboxEvent]:
    cursor.execute(
        "SELECT event_id, org_id, event_type, payload, created_at, published_at "
        "FROM outbox_events WHERE published_at IS NULL ORDER BY created_at LIMIT ?",
        (limit,),
    )
    return [
        OutboxEvent(
            event_id=row[0], org_id=row[1], event_type=row[2],
            payload=json.loads(row[3]),
            created_at=datetime.fromisoformat(row[4]),
            published_at=datetime.fromisoformat(row[5]) if row[5] else None,
        )
        for row in cursor.fetchall()
    ]


def mark_published(cursor: Cursor, event_id: str) -> None:
    cursor.execute(
        "UPDATE outbox_events SET published_at = ? WHERE event_id = ?",
        (datetime.now(UTC).isoformat(), event_id),
    )
