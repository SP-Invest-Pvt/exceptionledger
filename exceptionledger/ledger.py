"""Hash-chained audit ledger.

hash = sha256(prev_hash + canonical_json({seq, ts, actor, action, exception_id})), genesis prev_hash "GENESIS".
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass

GENESIS = "GENESIS"

# The status each ledger action leaves an exception in, used to replay the ledger during verify.
ACTION_STATUS = {"request": "requested", "approve": "approved", "close": "closed",
                 "expire": "expired", "reopen": "reopened"}


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev_hash: str, seq: int, ts: str, actor: str, action: str, exception_id: str) -> str:
    body = canonical_json({"seq": seq, "ts": ts, "actor": actor, "action": action, "exception_id": exception_id})
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def append(conn: sqlite3.Connection, ts: str, actor: str, action: str, exception_id: str) -> int:
    """Append one entry. Call inside the transaction that makes the state change."""
    last = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    seq = (conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'ledger'").fetchone() or [0])[0] + 1
    conn.execute("INSERT INTO ledger(seq, ts, actor, action, exception_id, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                 (seq, ts, actor, action, exception_id, prev, entry_hash(prev, seq, ts, actor, action, exception_id)))
    return seq


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    broken_seq: int | None = None
    problem: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "entries": self.entries, "head": self.head,
                "broken_seq": self.broken_seq, "problem": self.problem}


def verify(conn: sqlite3.Connection) -> VerifyResult:
    """Recompute the chain, then replay it against the exceptions table.

    Detects edited or deleted entries (hash, prev_hash and sequence gaps) and exception rows whose
    status no longer matches what the ledger says happened.
    """
    rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    prev, expected_seq = GENESIS, 1
    replay: dict[str, str] = {}
    for r in rows:
        if r["seq"] != expected_seq:
            return VerifyResult(False, len(rows), prev, r["seq"], f"sequence gap: expected {expected_seq}")
        if r["prev_hash"] != prev:
            return VerifyResult(False, len(rows), prev, r["seq"], "prev_hash does not match the previous entry")
        if entry_hash(prev, r["seq"], r["ts"], r["actor"], r["action"], r["exception_id"]) != r["hash"]:
            return VerifyResult(False, len(rows), prev, r["seq"], "hash does not match the entry's contents")
        if r["action"] not in ACTION_STATUS:
            return VerifyResult(False, len(rows), prev, r["seq"], f"unknown action {r['action']!r}")
        replay[r["exception_id"]] = ACTION_STATUS[r["action"]]
        prev, expected_seq = r["hash"], expected_seq + 1
    for ex in conn.execute("SELECT id, status FROM exceptions ORDER BY id"):
        if replay.get(ex["id"]) != ex["status"]:
            return VerifyResult(False, len(rows), prev, None,
                                f"{ex['id']}: status {ex['status']!r} but the ledger says "
                                f"{replay.get(ex['id'], 'no entries')!r}")
    return VerifyResult(True, len(rows), prev)
