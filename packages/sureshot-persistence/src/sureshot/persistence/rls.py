from __future__ import annotations

import re

from sureshot.persistence.outbox import Cursor

_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

_ORG_SETTING = "app.current_org_id"


class InvalidIdentifier(Exception):
    """A table or column name isn't a safe, bare SQL identifier."""


def _check_identifier(name: str) -> str:
    """DDL can't be parameterized like a query value, so table/column names
    that end up in these SQL strings get validated here instead — this is
    what keeps _sql-generation_ safe even though the strings are f-formatted."""
    if not _IDENTIFIER.match(name):
        raise InvalidIdentifier(f"not a safe SQL identifier: {name!r}")
    return name


def enable_rls(table: str) -> str:
    """Postgres-only: DDL to turn on row-level security for a table. Until a
    policy is also created, RLS with no policy denies all rows to everyone
    except the table owner — enabling it is the first step, not the whole one.
    """
    table = _check_identifier(table)
    return f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;"


def org_isolation_policy(table: str, org_column: str = "org_id") -> str:
    """Postgres-only: a policy restricting every row operation on `table` to
    rows whose org_column matches the session's current_org_id setting (see
    set_current_org). This is the actual multi-tenancy boundary — application
    code forgetting a WHERE org_id = ... clause fails safe instead of leaking
    another tenant's rows.
    """
    table = _check_identifier(table)
    org_column = _check_identifier(org_column)
    policy_name = f"{table}_org_isolation"
    return (
        f"CREATE POLICY {policy_name} ON {table} "
        f"USING ({org_column} = current_setting('{_ORG_SETTING}', true));"
    )


def drop_policy(table: str, policy_name: str | None = None) -> str:
    table = _check_identifier(table)
    name = _check_identifier(policy_name or f"{table}_org_isolation")
    return f"DROP POLICY IF EXISTS {name} ON {table};"


def set_current_org(cursor: Cursor, org_id: str) -> None:
    """Set the session-local GUC that org_isolation_policy checks against.
    Must be called on every connection/session before it touches
    RLS-protected tables — Postgres, not this code, then enforces the rest.

    set_config/current_setting are Postgres-only (no SQLite equivalent), so
    unlike outbox.py/retention.py this can't be verified against SQLite here
    — only that this function issues the right statement, via a mock cursor.
    Uses %s (psycopg's paramstyle), since a real cursor for this call is
    necessarily a Postgres one.
    """
    cursor.execute(f"SELECT set_config('{_ORG_SETTING}', %s, false)", (org_id,))
