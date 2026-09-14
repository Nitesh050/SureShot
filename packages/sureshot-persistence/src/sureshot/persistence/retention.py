from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sureshot.persistence.outbox import Cursor

DDL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    started_at TEXT NOT NULL
)
"""


def purge_expired_scans(cursor: Cursor, org_id: str, retention_days: int, now: datetime | None = None) -> int:
    """Delete scans older than an org's retention window. Returns the number
    of rows deleted, so a caller can log/alert on unexpectedly large purges.

    Deletion, not archival — that's a deliberate choice: retention exists to
    bound how long a customer's scanned source and findings are held, and
    an archived-but-not-deleted copy would defeat that.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    cursor.execute(
        "DELETE FROM scans WHERE org_id = ? AND started_at < ?",
        (org_id, cutoff.isoformat()),
    )
    return cursor.rowcount


def scans_due_for_purge(cursor: Cursor, org_id: str, retention_days: int, now: datetime | None = None) -> list[str]:
    """Preview what purge_expired_scans would delete, without deleting it."""
    cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    cursor.execute(
        "SELECT scan_id FROM scans WHERE org_id = ? AND started_at < ? ORDER BY started_at",
        (org_id, cutoff.isoformat()),
    )
    return [row[0] for row in cursor.fetchall()]
