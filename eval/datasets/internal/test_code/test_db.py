import sqlite3


def test_query_builder():
    conn = sqlite3.connect(":memory:")
    name = "fixture_user"
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
