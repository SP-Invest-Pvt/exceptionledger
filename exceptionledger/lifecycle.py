"""Exception lifecycle: request -> approve -> expire | close | reopen, each step ledgered.

  requested --approve--> approved --sweep--> expired
      |                     |  \\--rescan (fingerprint gone)--> reopened --approve--> approved
      +--close--> closed <--+-------------------------------------+
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from . import LedgerError, TransitionError
from . import ledger, store
from .store import Exception_, iso

# action -> (allowed from-statuses, resulting status)
TRANSITIONS = {
    "approve": ({"requested", "reopened"}, "approved"),
    "close": ({"requested", "approved", "reopened", "expired"}, "closed"),
    "expire": ({"requested", "approved", "reopened"}, "expired"),
    "reopen": ({"approved"}, "reopened"),
}


def normalize(snippet: str) -> str:
    return snippet.strip().lower()


def fingerprint(rule_id: str, file: str, line: int, snippet: str) -> str:
    return hashlib.sha256(f"{rule_id}|{file}|{line}|{normalize(snippet)}".encode("utf-8")).hexdigest()


def _now(now: datetime | None) -> datetime:
    return (now or store.utc_now()).replace(microsecond=0)


def request(conn: sqlite3.Connection, fp: str, title: str, justification: str, requested_by: str,
            days: int, now: datetime | None = None) -> Exception_:
    for name, value in (("fingerprint", fp), ("title", title), ("justification", justification),
                        ("requested-by", requested_by)):
        if not value or not value.strip():
            raise LedgerError(f"{name} must not be empty")
    if days <= 0:
        raise LedgerError(f"days must be a positive number, got {days}")
    t = _now(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        ex_id = store.next_id(conn)
        conn.execute("INSERT INTO exceptions(id, fingerprint, title, justification, requested_by, status, "
                     "created_at, expires_at) VALUES (?,?,?,?,?, 'requested', ?, ?)",
                     (ex_id, fp.strip(), title.strip(), justification.strip(), requested_by.strip(), iso(t),
                      iso(t + timedelta(days=days))))
        ledger.append(conn, iso(t), requested_by.strip(), "request", ex_id)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return store.get(conn, ex_id)


def transition(conn: sqlite3.Connection, ex_id: str, action: str, actor: str,
               now: datetime | None = None) -> Exception_:
    """Apply one lifecycle action. Raises LedgerError for an unknown id, TransitionError for a broken rule."""
    if not actor or not actor.strip():
        raise LedgerError("actor must not be empty")
    allowed, target = TRANSITIONS[action]
    t = _now(now)
    conn.execute("BEGIN IMMEDIATE")
    try:
        ex = store.get(conn, ex_id)
        if ex is None:
            raise LedgerError(f"no exception with id {ex_id}")
        if ex.status not in allowed:
            raise TransitionError(f"{ex_id} is {ex.status}; cannot {action} (allowed from: {', '.join(sorted(allowed))})")
        if action == "approve" and actor.strip().lower() == ex.requested_by.lower():
            raise TransitionError(f"{ex_id} was requested by {ex.requested_by}; an exception needs a different approver")
        sets, args = ["status = ?"], [target]
        if action == "approve":
            sets.append("approver = ?")
            args.append(actor.strip())
        if target in ("closed", "expired"):
            sets.append("closed_at = ?")
            args.append(iso(t))
        conn.execute(f"UPDATE exceptions SET {', '.join(sets)} WHERE id = ?", (*args, ex_id))
        ledger.append(conn, iso(t), actor.strip(), action, ex_id)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return store.get(conn, ex_id)


def sweep(conn: sqlite3.Connection, now: datetime | None = None) -> list[Exception_]:
    """Expire every open exception whose expires_at is in the past."""
    t = _now(now)
    due = [e for e in store.all_exceptions(conn)
           if e.status in TRANSITIONS["expire"][0] and store.parse_iso(e.expires_at) <= t]
    return [transition(conn, e.id, "expire", "sweep", now=t) for e in due]


def sarif_results(path: str | Path, source_root: str | Path = ".") -> list[dict]:
    """rule_id, file, line and fingerprint for every result in a SARIF file.

    The snippet is region.snippet.text when the scanner provides it, otherwise the line read from
    source_root/<uri>. A result whose snippet cannot be found fingerprints with an empty snippet.
    """
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise LedgerError(f"file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise LedgerError(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise LedgerError(f"{path}: not a SARIF log (no 'runs' array)")
    root = Path(source_root)
    cache: dict[str, list[str]] = {}
    out = []
    for run in doc["runs"]:
        for r in (run or {}).get("results") or []:
            loc = ((r.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
            file = ((loc.get("artifactLocation") or {}).get("uri") or "").removeprefix("./")
            region = loc.get("region") or {}
            try:
                line = int(region.get("startLine") or 0)
            except (TypeError, ValueError):
                raise LedgerError(f"{path}: non-numeric startLine for {r.get('ruleId')}") from None
            snippet = (region.get("snippet") or {}).get("text")
            if snippet is None:
                if file not in cache:
                    try:
                        cache[file] = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
                    except OSError:
                        cache[file] = []
                lines = cache[file]
                snippet = lines[line - 1] if 1 <= line <= len(lines) else ""
            rule_id = r.get("ruleId") or ""
            out.append({"rule_id": rule_id, "file": file, "line": line,
                        "fingerprint": fingerprint(rule_id, file, line, snippet)})
    return out


def rescan(conn: sqlite3.Connection, sarif: str | Path, source_root: str | Path = ".",
           now: datetime | None = None) -> list[Exception_]:
    """Reopen every approved exception whose fingerprint is absent from the new scan.

    The schema stores only the fingerprint, so "absent" covers both changed code under the exception
    and a finding that moved or disappeared. Either way the approval no longer provably covers the
    code, so a person re-reviews it (approve again, or close it).
    """
    current = {r["fingerprint"] for r in sarif_results(sarif, source_root)}
    return [transition(conn, e.id, "reopen", "rescan", now=now)
            for e in store.all_exceptions(conn, "approved") if e.fingerprint not in current]
