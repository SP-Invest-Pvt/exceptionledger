"""Command line: python -m exceptionledger [--db PATH] <command> ...

Exit codes: 0 success, 1 lifecycle rule broken / ledger verification failed / rescan reopened
exceptions, 2 usage or input error. Logs go to stderr; results go to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import LedgerError, TransitionError, __version__
from . import ledger, lifecycle, store

STATUSES = ("requested", "approved", "expired", "closed", "reopened")


def _log(msg: str) -> None:
    sys.stdout.flush()
    print(f"exceptionledger: {msg}", file=sys.stderr)


def _print_exceptions(rows: list[store.Exception_], fmt: str, empty: str = "no exceptions") -> None:
    if fmt == "json":
        print(json.dumps([r.to_dict() for r in rows], indent=2))
        return
    if not rows:
        print(empty)
        return
    print(f"{'id':<8} {'status':<9} {'expires_at':<20} {'requested_by':<14} {'approver':<12} title")
    for r in rows:
        print(f"{r.id:<8} {r.status:<9} {r.expires_at:<20} {r.requested_by:<14} {r.approver or '-':<12} {r.title}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exceptionledger",
                                description="Tamper-evident ledger for security policy exceptions.")
    p.add_argument("--version", action="version", version=f"exceptionledger {__version__}")
    p.add_argument("--db", default=os.environ.get("EXCEPTIONLEDGER_DB", "exceptions.db"),
                   help="SQLite file (default: $EXCEPTIONLEDGER_DB or exceptions.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    fp = sub.add_parser("fingerprint", help="fingerprint one finding, or every result in a SARIF file",
                        description="Either --sarif, or all of --rule --file --line --snippet.")
    fp.add_argument("--sarif", help="list the fingerprint of every result in this SARIF file")
    fp.add_argument("--source-root", default=".", help="where to read flagged lines when SARIF has no snippet")
    fp.add_argument("--rule")
    fp.add_argument("--file")
    fp.add_argument("--line", type=int)
    fp.add_argument("--snippet", help="the flagged source line")
    fp.add_argument("--format", choices=["table", "json"], default="table")

    rq = sub.add_parser("request", help="request an exception")
    rq.add_argument("--fingerprint", required=True)
    rq.add_argument("--title", required=True)
    rq.add_argument("--justification", required=True)
    rq.add_argument("--requested-by", required=True)
    rq.add_argument("--days", type=int, default=90, help="validity in days (default: 90)")

    for name, helptext, who in (("approve", "approve a requested or reopened exception", "--approver"),
                                ("close", "close an exception (fixed, withdrawn or no longer needed)", "--by")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--id", required=True)
        sp.add_argument(who, required=True, dest="actor")

    ls = sub.add_parser("list", help="list exceptions")
    ls.add_argument("--status", choices=STATUSES)
    ls.add_argument("--format", choices=["table", "json"], default="table")

    hs = sub.add_parser("history", help="every ledger entry for one exception")
    hs.add_argument("--id", required=True)
    hs.add_argument("--format", choices=["table", "json"], default="table")

    vf = sub.add_parser("verify", help="recompute the hash chain and replay it against the exceptions")
    vf.add_argument("--format", choices=["text", "json"], default="text")

    rs = sub.add_parser("rescan", help="reopen approved exceptions whose fingerprint is gone from a new scan")
    rs.add_argument("--sarif", required=True)
    rs.add_argument("--source-root", default=".", help="where to read flagged lines when SARIF has no snippet")
    rs.add_argument("--format", choices=["table", "json"], default="table")

    sw = sub.add_parser("sweep", help="expire open exceptions past their expiry date")
    sw.add_argument("--format", choices=["table", "json"], default="table")
    return p


def run(a: argparse.Namespace) -> int:
    if a.cmd == "fingerprint":
        if a.sarif:
            rows = lifecycle.sarif_results(a.sarif, a.source_root)
            if a.format == "json":
                print(json.dumps(rows, indent=2))
            else:
                for r in rows:
                    print(f"{r['fingerprint']}  {r['rule_id']}  {r['file']}:{r['line']}")
            return 0
        if None in (a.rule, a.file, a.line, a.snippet):
            raise LedgerError("fingerprint needs --sarif, or all of --rule, --file, --line and --snippet")
        print(lifecycle.fingerprint(a.rule, a.file, a.line, a.snippet))
        return 0
    conn = store.connect(a.db)
    try:
        if a.cmd == "request":
            ex = lifecycle.request(conn, a.fingerprint, a.title, a.justification, a.requested_by, a.days)
            print(ex.id)
            _log(f"{ex.id} requested by {ex.requested_by}, expires {ex.expires_at}")
        elif a.cmd in ("approve", "close"):
            ex = lifecycle.transition(conn, a.id, a.cmd, a.actor)
            print(f"{ex.id} {ex.status}")
        elif a.cmd == "list":
            _print_exceptions(store.all_exceptions(conn, a.status), a.format)
        elif a.cmd == "history":
            if store.get(conn, a.id) is None:
                raise LedgerError(f"no exception with id {a.id}")
            entries = ledger.history(conn, a.id)
            if a.format == "json":
                print(json.dumps(entries, indent=2))
            else:
                for e in entries:
                    print(f"{e['seq']:>4}  {e['ts']}  {e['action']:<8} {e['actor']:<14} {e['hash'][:12]}")
        elif a.cmd == "verify":
            res = ledger.verify(conn)
            if a.format == "json":
                print(json.dumps(res.to_dict(), indent=2))
            elif res.ok:
                print(f"OK: {res.entries} ledger entries, chain intact, statuses match. head {res.head}")
            else:
                where = f"seq {res.broken_seq}" if res.broken_seq is not None else "exceptions table"
                print(f"FAILED at {where}: {res.problem}")
            return 0 if res.ok else 1
        elif a.cmd == "rescan":
            reopened = lifecycle.rescan(conn, a.sarif, a.source_root)
            _print_exceptions(reopened, a.format, "no approved exception reopened")
            _log(f"{len(reopened)} approved exception(s) reopened for review")
            return 1 if reopened else 0
        elif a.cmd == "sweep":
            expired = lifecycle.sweep(conn)
            _print_exceptions(expired, a.format, "no exception expired")
            _log(f"{len(expired)} exception(s) expired")
        return 0
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        a = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        return run(a)
    except TransitionError as e:
        _log(f"rejected: {e}")
        return 1
    except LedgerError as e:
        _log(f"error: {e}")
        return 2
    except Exception as e:  # sqlite3.DatabaseError for a file that is not a database, and similar
        if e.__class__.__module__ == "sqlite3":
            _log(f"error: {a.db}: {e}")
            return 2
        raise
