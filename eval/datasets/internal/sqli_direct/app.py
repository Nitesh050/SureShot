import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    return conn.execute(
        "SELECT * FROM users WHERE name = '" + username + "'"
    ).fetchall()
