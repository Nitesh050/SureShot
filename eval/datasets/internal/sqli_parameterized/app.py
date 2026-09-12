import sqlite3

ALLOWED = ("name", "email", "created_at")


def get_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()


def sort_users(column):
    if column not in ALLOWED:
        raise ValueError("bad column")
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users ORDER BY {column}").fetchall()
