# exceptionledger

A tamper-evident register for security policy exceptions. It knows when an exception expires, who approved it, and when the code it covers has changed.

[![ci](https://github.com/sp-kernel-stack/exceptionledger/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## The problem

Every security programme grants exceptions: this finding is accepted until the Q4 rewrite, that library stays until the vendor ships a fix. They usually live in a spreadsheet or a ticket comment. Nobody knows which ones have quietly expired, anyone with edit rights can change the approver column, and nothing notices when a developer rewrites the exact line an exception was granted for. At that point the approval covers code nobody reviewed.

exceptionledger keeps exceptions in SQLite with a fixed lifecycle, writes every state change to a hash-chained ledger in the same transaction, ties each exception to a fingerprint of the flagged code, and reopens it when a new scan no longer contains that fingerprint.

## How it works

**Fingerprint.** `sha256(rule_id + "|" + file + "|" + str(line) + "|" + normalize(snippet))`, where `normalize` strips surrounding whitespace and lowercases. `fingerprint --sarif scan.sarif` prints one per scan result, so nobody has to copy source lines by hand.

**Lifecycle.** Illegal transitions are rejected with exit code 1 and leave no ledger entry.

```
requested --approve--> approved --sweep (past expires_at)--> expired --close--> closed
    |                     |
    |                     +--rescan (fingerprint gone)--> reopened --approve--> approved
    +--close--> closed    +--close--> closed                  +--close--> closed
```

`sweep` also expires requested and reopened exceptions that pass their date. An exception cannot be approved by the person who requested it.

**Ledger.** Every state change appends exactly one row inside the same transaction:

```
hash = sha256(prev_hash + canonical_json({seq, ts, actor, action, exception_id}))    # first prev_hash: "GENESIS"
```

`canonical_json` is sorted keys with no whitespace. `verify` recomputes every hash, checks each `prev_hash` link and that `seq` has no gaps, then replays the ledger and compares the result with the `exceptions` table. It catches an edited ledger row, a deleted row, and a status changed directly in the exceptions table.

**Schema** (exactly):

```sql
CREATE TABLE exceptions(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, title TEXT NOT NULL, justification TEXT NOT NULL,
  requested_by TEXT NOT NULL, approver TEXT, status TEXT NOT NULL DEFAULT 'requested', created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, closed_at TEXT);
CREATE TABLE ledger(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  exception_id TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
```

## Demo

A real run. `examples/src/reports.py` has one SQL string built with `%`, [Bandit](https://github.com/PyCQA/bandit) flags it as B608, and the team accepts it for 90 days. Then someone edits the line. Timestamps and hashes are from the actual run.

```
$ bandit -q -r src -f sarif -o scan1.sarif
$ python -m exceptionledger --db ledger.db fingerprint --sarif scan1.sarif
cb4d1848a091590e663bf16dc54288041c8322eb3013eb7ec426f6a48c19292a  B608  src/reports.py:6

$ python -m exceptionledger --db ledger.db request --fingerprint cb4d1848a091590e663bf16dc54288041c8322eb3013eb7ec426f6a48c19292a \
    --title "Month filter in revenue report" --justification "Value comes from a fixed drop-down; moving to a parameterised query in Q4" \
    --requested-by dev.alice --days 90
EX-0001
exceptionledger: EX-0001 requested by dev.alice, expires 2026-12-26T02:13:27Z
$ python -m exceptionledger --db ledger.db approve --id EX-0001 --approver dev.alice
exceptionledger: rejected: EX-0001 was requested by dev.alice; an exception needs a different approver
$ echo $?
1
$ python -m exceptionledger --db ledger.db approve --id EX-0001 --approver sec.bob
EX-0001 approved
$ python -m exceptionledger --db ledger.db list
id       status    expires_at           requested_by   approver     title
EX-0001  approved  2026-12-26T02:13:27Z dev.alice      sec.bob      Month filter in revenue report

# Same code, new scan: the exception still covers it.
$ python -m exceptionledger --db ledger.db rescan --sarif scan1.sarif
no approved exception reopened
exceptionledger: 0 approved exception(s) reopened for review
$ echo $?
0

# Someone changes the flagged line to take the month straight from the request.
$ sed -i 's/% month/% request.args["month"]/' src/reports.py && bandit -q -r src -f sarif -o scan2.sarif
$ python -m exceptionledger --db ledger.db rescan --sarif scan2.sarif
id       status    expires_at           requested_by   approver     title
EX-0001  reopened  2026-12-26T02:13:27Z dev.alice      sec.bob      Month filter in revenue report
exceptionledger: 1 approved exception(s) reopened for review
$ echo $?
1
$ python -m exceptionledger --db ledger.db verify
OK: 3 ledger entries, chain intact, statuses match. head 69343d9dfb685cf9e69072df42178ad271836f7f6ad6c09c4ad6560e9a55df3d

# Tamper with the audit trail directly in SQLite.
$ python -c "import sqlite3; c = sqlite3.connect('ledger.db'); c.execute(\"UPDATE ledger SET action='forged' WHERE seq=2\"); c.commit()"
$ python -m exceptionledger --db ledger.db verify
FAILED at seq 2: hash does not match the entry's contents
$ echo $?
1
```

The edit that reopened EX-0001 is the one that matters: the approved justification ("value comes from a fixed drop-down") stopped being true when the month started coming from the request, and the approval was withdrawn automatically instead of silently covering new code.

## Install

Python 3.11 or newer, standard library only (`sqlite3`, `hashlib`, `json`).

```bash
git clone https://github.com/sp-kernel-stack/exceptionledger && cd exceptionledger
pip install -e ".[test]"
pytest
python -m exceptionledger --help
```

## Usage

```
python -m exceptionledger [--db exceptions.db] <command>

fingerprint --sarif scan.sarif [--source-root .] [--format table|json]
fingerprint --rule R --file F --line N --snippet "flagged line"
request     --fingerprint FP --title T --justification J --requested-by X [--days 90]
approve     --id ID --approver Y
close       --id ID --by Z
list        [--status requested|approved|expired|closed|reopened] [--format table|json]
history     --id ID [--format table|json]
verify      [--format text|json]
rescan      --sarif new.sarif [--source-root .] [--format table|json]
sweep       [--format table|json]
```

The database defaults to `$EXCEPTIONLEDGER_DB`, else `exceptions.db`. When a SARIF result has no `region.snippet`, the flagged line is read from `--source-root`/`uri`.

Exit codes: `0` success; `1` a lifecycle rule was broken (illegal transition, self-approval), `verify` found tampering, or `rescan` reopened at least one exception; `2` usage or input error (unknown id, malformed or missing SARIF, a file that is not a database). Logs go to stderr; results go to stdout.

In CI, run `rescan` against each new scan and `sweep` on a schedule; a non-zero `rescan` means an approval needs a human again. Run `verify` before any audit export.

## Limitations

* **The schema stores a fingerprint, not a location.** `rescan` therefore cannot tell "the code under this exception changed" from "the finding was fixed or moved". It treats any approved exception whose fingerprint is absent from the new scan as reopened, and a person then re-approves or closes it. A change in line number also changes the fingerprint, so inserting lines above a finding reopens its exception.
* **Hash chains detect edits, not a consistent rewrite.** Deleting the newest ledger entries is caught only because the exceptions table no longer matches the replay; someone who also edits the exceptions table to match, or rebuilds the whole chain with valid hashes, cannot be detected from inside the database. Record the `head` hash printed by `verify` somewhere the database's editors cannot write (a signed commit, a ticket, a WORM bucket) and compare it later.
* **Identities are strings.** `--approver sec.bob` is whatever the caller types. Put the CLI behind your CI identity or a wrapper that injects the authenticated user; the self-approval rule compares names case-insensitively and nothing more.
* **SQLite is single-writer.** Fine for a team register driven from CI; not a multi-tenant service.
* **Normalisation is deliberately narrow.** Only surrounding whitespace and case are ignored. Reformatting the inside of a line changes the fingerprint and reopens the exception, which errs on the side of re-review.

## Licence

MIT.
