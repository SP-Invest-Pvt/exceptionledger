"""SQLite storage. The schema is fixed; every state change is written with its ledger row in one transaction."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS exceptions(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, title TEXT NOT NULL,
  justification TEXT NOT NULL, requested_by TEXT NOT NULL, approver TEXT,
  status TEXT NOT NULL DEFAULT 'requested', created_at TEXT NOT NULL, expires_at TEXT NOT NULL, closed_at TEXT);
CREATE TABLE IF NOT EXISTS ledger(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, exception_id TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""

COLUMNS = ("id", "fingerprint", "title", "justification", "requested_by", "approver", "status",
           "created_at", "expires_at", "closed_at")


@dataclass
class Exception_:
    id: str
    fingerprint: str
    title: str
    justification: str
    requested_by: str
    approver: str | None
    status: str
    created_at: str
    expires_at: str
    closed_at: str | None

    def to_dict(self) -> dict:
        return {c: getattr(self, c) for c in COLUMNS}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), isolation_level=None)  # explicit BEGIN/COMMIT below
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def get(conn: sqlite3.Connection, exception_id: str) -> Exception_ | None:
    row = conn.execute("SELECT * FROM exceptions WHERE id = ?", (exception_id,)).fetchone()
    return Exception_(**dict(row)) if row else None


def all_exceptions(conn: sqlite3.Connection, status: str | None = None) -> list[Exception_]:
    if status:
        rows = conn.execute("SELECT * FROM exceptions WHERE status = ? ORDER BY id", (status,))
    else:
        rows = conn.execute("SELECT * FROM exceptions ORDER BY id")
    return [Exception_(**dict(r)) for r in rows]


def next_id(conn: sqlite3.Connection) -> str:
    n = conn.execute("SELECT COUNT(*) FROM exceptions").fetchone()[0]
    return f"EX-{n + 1:04d}"
