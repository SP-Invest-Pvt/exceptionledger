import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from exceptionledger import LedgerError, TransitionError
from exceptionledger import ledger, lifecycle, store
from exceptionledger.cli import main

FX = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
SNIPPET = '    query = "SELECT * FROM orders WHERE id = " + order_id'
FP = lifecycle.fingerprint("java.sql-injection", "src/OrderRepo.java", 42, SNIPPET)


@pytest.fixture
def db(tmp_path):
    return tmp_path / "exceptions.db"


def cli(capsys, db, *argv):
    code = main(["--db", str(db), *[str(a) for a in argv]])
    out, err = capsys.readouterr()
    return code, out, err


def sarif(tmp_path, results, name="scan.sarif"):
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": [
        {"ruleId": rule, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f}, "region": {"startLine": line, **({"snippet": {"text": s}} if s else {})}}}]}
        for rule, f, line, s in results]}]}
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def approved(conn, now=T0):
    ex = lifecycle.request(conn, FP, "Legacy report query", "Parameterised in Q4 rewrite", "dev.alice", 90, now=now)
    return lifecycle.transition(conn, ex.id, "approve", "sec.bob", now=now)


# --- the five required tests -------------------------------------------------------------

def test_happy_path(capsys, db):
    code, out, _ = cli(capsys, db, "request", "--fingerprint", FP, "--title", "Legacy report query",
                       "--justification", "Parameterised in the Q4 rewrite", "--requested-by", "dev.alice",
                       "--days", "90")
    assert code == 0 and out.strip() == "EX-0001"
    code, out, _ = cli(capsys, db, "approve", "--id", "EX-0001", "--approver", "sec.bob")
    assert code == 0 and out.strip() == "EX-0001 approved"
    code, out, _ = cli(capsys, db, "list", "--status", "approved", "--format", "json")
    rows = json.loads(out)
    assert code == 0 and len(rows) == 1
    assert rows[0]["id"] == "EX-0001" and rows[0]["status"] == "approved" and rows[0]["approver"] == "sec.bob"
    code, out, _ = cli(capsys, db, "verify")
    assert code == 0 and out.startswith("OK: 2 ledger entries")


def test_illegal_transition(capsys, db):
    conn = store.connect(db)
    ex = lifecycle.request(conn, FP, "t", "j", "dev.alice", 30)
    lifecycle.transition(conn, ex.id, "close", "dev.alice")
    with pytest.raises(TransitionError, match="EX-0001 is closed; cannot approve"):
        lifecycle.transition(conn, ex.id, "approve", "sec.bob")
    conn.close()
    code, _, err = cli(capsys, db, "approve", "--id", "EX-0001", "--approver", "sec.bob")
    assert code == 1 and "cannot approve" in err
    conn = store.connect(db)
    assert store.get(conn, "EX-0001").status == "closed"
    assert conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0] == 2  # no entry for the rejected step


def test_tamper_detected(capsys, db):
    conn = store.connect(db)
    approved(conn)
    lifecycle.request(conn, FP, "second", "j", "dev.carol", 30)
    conn.execute("UPDATE ledger SET action='forged' WHERE seq = 2")
    conn.close()
    code, out, _ = cli(capsys, db, "verify")
    assert code == 1
    assert "seq 2" in out and "hash does not match" in out
    code, out, _ = cli(capsys, db, "verify", "--format", "json")
    assert code == 1 and json.loads(out)["broken_seq"] == 2


def test_reopen_on_change(tmp_path, capsys, db):
    conn = store.connect(db)
    approved(conn)
    same = sarif(tmp_path, [("java.sql-injection", "src/OrderRepo.java", 42, SNIPPET)], "same.sarif")
    assert lifecycle.rescan(conn, same) == []
    assert store.get(conn, "EX-0001").status == "approved"
    conn.close()

    altered = SNIPPET.replace("order_id", "request.getParameter(\"id\")")
    changed = sarif(tmp_path, [("java.sql-injection", "src/OrderRepo.java", 42, altered)], "changed.sarif")
    code, out, err = cli(capsys, db, "rescan", "--sarif", changed, "--format", "json")
    assert code == 1 and "1 approved exception(s) reopened" in err
    assert json.loads(out)[0]["status"] == "reopened"
    conn = store.connect(db)
    last = conn.execute("SELECT actor, action, exception_id FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    assert tuple(last) == ("rescan", "reopen", "EX-0001")
    assert ledger.verify(conn).ok


def test_sweep_expiry(db):
    conn = store.connect(db)
    old = approved(conn, now=T0 - timedelta(days=120))       # expired 30 days before T0
    fresh = approved(conn, now=T0)                            # expires T0 + 90 days
    expired = lifecycle.sweep(conn, now=T0)
    assert [e.id for e in expired] == [old.id]
    assert store.get(conn, old.id).status == "expired"
    assert store.get(conn, old.id).closed_at == "2026-09-01T09:00:00Z"
    assert store.get(conn, fresh.id).status == "approved"
    assert lifecycle.sweep(conn, now=T0) == []                # idempotent
    assert ledger.verify(conn).ok


# --- fingerprint --------------------------------------------------------------------------

def test_fingerprint_normalises_case_and_outer_whitespace():
    assert lifecycle.fingerprint("r", "a.py", 1, "  X = 1\t") == lifecycle.fingerprint("r", "a.py", 1, "x = 1")
    assert lifecycle.fingerprint("r", "a.py", 1, "x = 1") != lifecycle.fingerprint("r", "a.py", 2, "x = 1")
    assert len(FP) == 64


def test_fingerprint_command(capsys, db):
    code, out, _ = cli(capsys, db, "fingerprint", "--rule", "java.sql-injection", "--file", "src/OrderRepo.java",
                       "--line", "42", "--snippet", SNIPPET)
    assert code == 0 and out.strip() == FP


def test_rescan_reads_source_when_sarif_has_no_snippet(tmp_path, db):
    src = tmp_path / "src"
    src.mkdir()
    (src / "OrderRepo.java").write_text("\n" * 41 + SNIPPET + "\n")
    conn = store.connect(db)
    approved(conn)
    no_snippet = sarif(tmp_path, [("java.sql-injection", "src/OrderRepo.java", 42, None)])
    assert lifecycle.rescan(conn, no_snippet, source_root=tmp_path) == []
    (src / "OrderRepo.java").write_text("\n" * 41 + SNIPPET + " // changed\n")
    assert [e.id for e in lifecycle.rescan(conn, no_snippet, source_root=tmp_path)] == ["EX-0001"]


# --- lifecycle rules ----------------------------------------------------------------------

def test_requester_cannot_approve_own_exception(db):
    conn = store.connect(db)
    ex = lifecycle.request(conn, FP, "t", "j", "dev.alice", 30)
    with pytest.raises(TransitionError, match="needs a different approver"):
        lifecycle.transition(conn, ex.id, "approve", "Dev.Alice")


def test_reopened_can_be_reapproved_or_closed(tmp_path, db):
    conn = store.connect(db)
    ex = approved(conn)
    lifecycle.rescan(conn, sarif(tmp_path, []))
    assert lifecycle.transition(conn, ex.id, "approve", "sec.bob").status == "approved"
    lifecycle.rescan(conn, sarif(tmp_path, []))
    closed = lifecycle.transition(conn, ex.id, "close", "dev.alice")
    assert closed.status == "closed" and closed.closed_at
    assert [r["action"] for r in conn.execute("SELECT action FROM ledger ORDER BY seq")] == \
        ["request", "approve", "reopen", "approve", "reopen", "close"]
    assert ledger.verify(conn).ok


@pytest.mark.parametrize("kwargs, message", [
    ({"fp": ""}, "fingerprint must not be empty"),
    ({"title": "  "}, "title must not be empty"),
    ({"days": 0}, "days must be a positive number"),
])
def test_request_validation(db, kwargs, message):
    args = {"fp": FP, "title": "t", "justification": "j", "requested_by": "a", "days": 30} | kwargs
    with pytest.raises(LedgerError, match=message):
        lifecycle.request(store.connect(db), args["fp"], args["title"], args["justification"],
                          args["requested_by"], args["days"])


def test_unknown_id_is_usage_error(capsys, db):
    code, _, err = cli(capsys, db, "approve", "--id", "EX-9999", "--approver", "sec.bob")
    assert code == 2 and "no exception with id EX-9999" in err


# --- ledger verification ------------------------------------------------------------------

def test_hash_chain_links(db):
    conn = store.connect(db)
    approved(conn)
    rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    assert rows[0]["prev_hash"] == "GENESIS"
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert rows[0]["hash"] == ledger.entry_hash("GENESIS", 1, rows[0]["ts"], "dev.alice", "request", "EX-0001")


def test_deleted_entry_detected(db):
    conn = store.connect(db)
    approved(conn)
    lifecycle.request(conn, FP, "second", "j", "dev.carol", 30)
    conn.execute("DELETE FROM ledger WHERE seq = 2")
    res = ledger.verify(conn)
    assert not res.ok and res.broken_seq == 3 and "sequence gap" in res.problem


def test_status_tampering_in_exceptions_table_detected(capsys, db):
    conn = store.connect(db)
    lifecycle.request(conn, FP, "t", "j", "dev.alice", 30)
    conn.execute("UPDATE exceptions SET status = 'approved', approver = 'nobody' WHERE id = 'EX-0001'")
    conn.close()
    code, out, _ = cli(capsys, db, "verify")
    assert code == 1 and "EX-0001: status 'approved' but the ledger says 'requested'" in out


def test_rewritten_chain_with_valid_hashes_still_breaks_at_the_edit(db):
    conn = store.connect(db)
    approved(conn)
    r = conn.execute("SELECT * FROM ledger WHERE seq = 1").fetchone()
    forged = ledger.entry_hash("GENESIS", 1, r["ts"], "mallory", "request", "EX-0001")
    conn.execute("UPDATE ledger SET actor = 'mallory', hash = ? WHERE seq = 1", (forged,))
    res = ledger.verify(conn)
    assert not res.ok and res.broken_seq == 2 and "prev_hash" in res.problem


# --- empty, malformed and missing input -----------------------------------------------------

def test_empty_database(capsys, db):
    code, out, _ = cli(capsys, db, "list")
    assert code == 0 and out.strip() == "no exceptions"
    code, out, _ = cli(capsys, db, "verify")
    assert code == 0 and "0 ledger entries" in out
    code, out, _ = cli(capsys, db, "sweep", "--format", "json")
    assert code == 0 and json.loads(out) == []


def test_empty_sarif_reopens_all_approved(tmp_path, capsys, db):
    conn = store.connect(db)
    approved(conn)
    conn.close()
    code, out, _ = cli(capsys, db, "rescan", "--sarif", FX / "empty.sarif")
    assert code == 1 and "EX-0001" in out and "reopened" in out


@pytest.mark.parametrize("content, message", [
    ('{"runs": [', "not valid JSON"),
    ('{"version": "2.1.0"}', "no 'runs' array"),
])
def test_malformed_sarif(tmp_path, capsys, db, content, message):
    p = tmp_path / "bad.sarif"
    p.write_text(content)
    code, _, err = cli(capsys, db, "rescan", "--sarif", p)
    assert code == 2 and message in err


def test_missing_sarif(capsys, db, tmp_path):
    code, _, err = cli(capsys, db, "rescan", "--sarif", tmp_path / "nope.sarif")
    assert code == 2 and "file not found" in err


def test_not_a_database(tmp_path, capsys):
    bogus = tmp_path / "notes.txt"
    bogus.write_text("this is not sqlite " * 100)
    code, _, err = cli(capsys, bogus, "list")
    assert code == 2 and "notes.txt" in err


def test_help_and_usage(capsys):
    assert main(["--help"]) == 0
    assert "rescan" in capsys.readouterr().out
    assert main(["approve", "--id", "EX-0001"]) == 2  # --approver is required


def test_fingerprint_from_sarif_matches_manual(tmp_path, capsys, db):
    scan = sarif(tmp_path, [("java.sql-injection", "src/OrderRepo.java", 42, SNIPPET)])
    code, out, _ = cli(capsys, db, "fingerprint", "--sarif", scan, "--format", "json")
    assert code == 0 and json.loads(out) == [
        {"rule_id": "java.sql-injection", "file": "src/OrderRepo.java", "line": 42, "fingerprint": FP}]
    code, out, _ = cli(capsys, db, "fingerprint", "--sarif", scan)
    assert out.strip() == f"{FP}  java.sql-injection  src/OrderRepo.java:42"


def test_fingerprint_needs_all_manual_fields(capsys, db):
    code, _, err = cli(capsys, db, "fingerprint", "--rule", "r", "--file", "a.py")
    assert code == 2 and "needs --sarif, or all of" in err


def test_deleting_the_newest_entry_is_caught_by_replay(db):
    conn = store.connect(db)
    approved(conn)
    conn.execute("DELETE FROM ledger WHERE seq = 2")
    res = ledger.verify(conn)
    assert not res.ok and res.broken_seq is None
    assert "EX-0001: status 'approved' but the ledger says 'requested'" in res.problem
