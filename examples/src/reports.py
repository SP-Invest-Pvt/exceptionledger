import sqlite3


def monthly_revenue(db: sqlite3.Connection, month: str):
    # month comes from a fixed drop-down of YYYY-MM values, validated upstream
    query = "SELECT SUM(amount) FROM invoices WHERE month = '%s'" % month
    return db.execute(query).fetchone()[0]


def top_customers(db: sqlite3.Connection, limit: int = 10):
    return db.execute("SELECT name, total FROM customers ORDER BY total DESC LIMIT ?", (limit,)).fetchall()
