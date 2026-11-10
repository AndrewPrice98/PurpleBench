"""SQLite storage for campaigns, rule set versions, runs, executions, rule hits and gaps.

Coverage scores are never stored: they are derived from ``executions`` (and ``hits``). Rule YAML stays in the
repository; a rule set stores the ids of its rules plus a content hash. All SQL is parameterized.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    techniques_json  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS rulesets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    version         TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    rules_json_hash TEXT NOT NULL,
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ruleset_rules (
    ruleset_id  INTEGER NOT NULL REFERENCES rulesets(id) ON DELETE CASCADE,
    rule_id     TEXT NOT NULL,
    rule_file   TEXT NOT NULL,
    origin      TEXT NOT NULL CHECK (origin IN ('sigmahq','custom')),
    title       TEXT NOT NULL,
    added_in    TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ruleset_id, rule_id)
);

CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    ruleset_id   INTEGER NOT NULL REFERENCES rulesets(id),
    mode         TEXT NOT NULL CHECK (mode IN ('recorded','lab')),
    source       TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL,
    notes        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS executions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    technique_id  TEXT NOT NULL,
    test_guid     TEXT,
    started_at    TEXT,
    ended_at      TEXT,
    status        TEXT NOT NULL
                  CHECK (status IN ('detected','partial','missed','telemetry_gap','untested','did_not_run')),
    ttd_ms        INTEGER,
    events_ref    TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hits (
    execution_id    INTEGER NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    first_ts        TEXT NOT NULL,
    count           INTEGER NOT NULL,
    relation        TEXT NOT NULL DEFAULT 'none'
                    CHECK (relation IN ('exact','parent','related','none')),
    noisy           INTEGER NOT NULL DEFAULT 0 CHECK (noisy IN (0,1)),
    noise_hits      INTEGER NOT NULL DEFAULT 0,
    record_ids_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (execution_id, rule_id)
);

CREATE TABLE IF NOT EXISTS rule_noise (
    run_id   INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id  TEXT NOT NULL,
    status   TEXT NOT NULL,
    hits     INTEGER NOT NULL,
    noisy    INTEGER NOT NULL CHECK (noisy IN (0,1)),
    PRIMARY KEY (run_id, rule_id)
);

CREATE TABLE IF NOT EXISTS gaps (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    technique_id      TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('missed','telemetry_gap','partial')),
    notes             TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    telemetry_needed  TEXT NOT NULL DEFAULT '',
    rule_idea         TEXT NOT NULL DEFAULT '',
    closed_in_run     INTEGER REFERENCES runs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_campaign     ON runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_executions_run    ON executions(run_id);
CREATE INDEX IF NOT EXISTS idx_hits_execution    ON hits(execution_id);
CREATE INDEX IF NOT EXISTS idx_gaps_run          ON gaps(run_id);
CREATE INDEX IF NOT EXISTS idx_ruleset_rules_set ON ruleset_rules(ruleset_id);
"""

SCHEMA_VERSION = 2  # 2: executions.status also allows 'did_not_run'
BUSY_TIMEOUT_SECONDS = 15.0
GAP_KINDS = ("missed", "telemetry_gap", "partial")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tx(conn: sqlite3.Connection, commit: bool):
    """Commit on success when ``commit`` is true; otherwise leave the surrounding
    transaction (opened by the caller) alone."""
    return conn if commit else nullcontext()


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the database, creating it and its schema if needed."""
    path = Path(path or config.db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    # FastAPI may run a dependency and its endpoint on different worker threads;
    # each request still gets its own connection.
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    _use_wal(conn)
    _migrate(conn)
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring a database created by an older version up to date, keeping its rows.

    Version 2 widened the CHECK on ``executions.status`` (SQLite cannot alter a CHECK in place, so the
    table is rebuilt: create new, copy, drop old, rename; child tables keep pointing at the name).
    """
    def stale() -> bool:
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'executions'").fetchone()
        return row is not None and "did_not_run" not in row[0]

    if not stale():
        return
    conn.execute("PRAGMA foreign_keys = OFF")  # cannot change inside a transaction
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if stale():  # another process may have migrated while we waited for the lock
                ddl = SCHEMA[SCHEMA.index("CREATE TABLE IF NOT EXISTS executions"):]
                ddl = ddl[:ddl.index(");") + 2].replace("CREATE TABLE IF NOT EXISTS executions",
                                                         "CREATE TABLE executions_new", 1)
                conn.execute("DROP TABLE IF EXISTS executions_new")
                conn.execute(ddl)
                cols = "id, run_id, technique_id, test_guid, started_at, ended_at, status, ttd_ms, events_ref, reason"
                conn.execute(f"INSERT INTO executions_new ({cols}) SELECT {cols} FROM executions")
                conn.execute("DROP TABLE executions")
                conn.execute("ALTER TABLE executions_new RENAME TO executions")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def _use_wal(conn: sqlite3.Connection) -> None:
    """Switch a new database to WAL. The switch needs an exclusive lock and SQLite does not
    wait for it, so concurrent first connections retry briefly instead of failing with
    "database is locked". WAL is persistent: later connections see it already set."""
    deadline = time.monotonic() + BUSY_TIMEOUT_SECONDS
    while True:
        try:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(0.02)


# -- writes (all take ``commit``: False inside a transaction the caller opened) -----------------

def add_campaign(conn: sqlite3.Connection, name: str, description: str, techniques: list[str], *,
                 id: int | None = None, commit: bool = True) -> int:
    with _tx(conn, commit):
        cur = conn.execute(
            "INSERT INTO campaigns (id, name, description, techniques_json) VALUES (?, ?, ?, ?)",
            (id, name, description, json.dumps(techniques)))
    return int(cur.lastrowid)


def add_ruleset(conn: sqlite3.Connection, version: str, created_at: str, rules_json_hash: str, notes: str,
                rules: list[dict[str, Any]], *, id: int | None = None, commit: bool = True) -> int:
    with _tx(conn, commit):
        ruleset_id = conn.execute(
            "INSERT INTO rulesets (id, version, created_at, rules_json_hash, notes) VALUES (?, ?, ?, ?, ?)",
            (id, version, created_at, rules_json_hash, notes)).lastrowid
        conn.executemany(
            "INSERT INTO ruleset_rules (ruleset_id, rule_id, rule_file, origin, title, added_in, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(ruleset_id, r["rule_id"], r["file"], r["origin"], r["title"], r["added_in"], r["note"]) for r in rules])
    return int(ruleset_id)


def add_run(conn: sqlite3.Connection, campaign_id: int, ruleset_id: int, mode: str, source: str, started_at: str,
            notes: str = "", *, id: int | None = None, commit: bool = True) -> int:
    with _tx(conn, commit):
        cur = conn.execute(
            "INSERT INTO runs (id, campaign_id, ruleset_id, mode, source, started_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (id, campaign_id, ruleset_id, mode, source, started_at, notes))
    return int(cur.lastrowid)


def add_execution(conn: sqlite3.Connection, run_id: int, ex: dict[str, Any], *, commit: bool = True) -> int:
    """Store one execution and its rule hits."""
    with _tx(conn, commit):
        eid = conn.execute(
            "INSERT INTO executions (run_id, technique_id, test_guid, started_at, ended_at, status, ttd_ms, "
            "events_ref, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, ex["technique_id"], ex["test_guid"], ex["started_at"], ex["ended_at"], ex["status"],
             ex["ttd_ms"], ex["events_ref"], ex["reason"])).lastrowid
        conn.executemany(
            "INSERT INTO hits (execution_id, rule_id, first_ts, count, relation, noisy, noise_hits, record_ids_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(eid, h["rule_id"], h["first_ts"], h["count"], h["relation"], int(h["noisy"]), h["noise_hits"],
              json.dumps(h["record_ids"])) for h in ex["hits"]])
    return int(eid)


def add_rule_noise(conn: sqlite3.Connection, run_id: int, rows: list[dict[str, Any]], *, commit: bool = True) -> None:
    with _tx(conn, commit):
        conn.executemany(
            "INSERT INTO rule_noise (run_id, rule_id, status, hits, noisy) VALUES (?, ?, ?, ?, ?)",
            [(run_id, r["rule_id"], r["status"], r["hits"], int(r["noisy"])) for r in rows])


def add_gap(conn: sqlite3.Connection, run_id: int, gap: dict[str, Any], *, commit: bool = True) -> int:
    if gap["kind"] not in GAP_KINDS:
        raise ValueError(f"unknown gap kind {gap['kind']!r}")
    with _tx(conn, commit):
        cur = conn.execute(
            "INSERT INTO gaps (run_id, technique_id, kind, notes, status, telemetry_needed, rule_idea, closed_in_run) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, gap["technique_id"], gap["kind"], gap["notes"], gap["status"], gap["telemetry_needed"],
             gap["rule_idea"], gap.get("closed_in_run")))
    return int(cur.lastrowid)


# -- reads --------------------------------------------------------------------------------------

def _campaign(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["techniques"] = json.loads(out.pop("techniques_json"))
    return out


def list_campaigns(conn: sqlite3.Connection) -> list[dict]:
    return [_campaign(r) for r in conn.execute("SELECT * FROM campaigns ORDER BY id")]


def get_campaign(conn: sqlite3.Connection, campaign_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
    return _campaign(row) if row else None


def list_rulesets(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM ruleset_rules r WHERE r.ruleset_id = s.id) AS rule_count "
        "FROM rulesets s ORDER BY s.id")
    return [dict(r) for r in rows]


def get_ruleset(conn: sqlite3.Connection, ruleset_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM rulesets WHERE id = ?", (ruleset_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["rules"] = [dict(r) for r in conn.execute(
        "SELECT rule_id, rule_file, origin, title, added_in, note FROM ruleset_rules "
        "WHERE ruleset_id = ? ORDER BY rule_file", (ruleset_id,))]
    return out


_RUN_SELECT = (
    "SELECT r.*, c.name AS campaign_name, s.version AS ruleset_version FROM runs r "
    "JOIN campaigns c ON c.id = r.campaign_id JOIN rulesets s ON s.id = r.ruleset_id")


def list_runs(conn: sqlite3.Connection, campaign_id: int | None = None) -> list[dict]:
    where, args = ("WHERE r.campaign_id = ?", (campaign_id,)) if campaign_id is not None else ("", ())
    rows = conn.execute(f"{_RUN_SELECT} {where} ORDER BY r.started_at, r.id", args).fetchall()
    return [dict(r) for r in rows]


def get_run(conn: sqlite3.Connection, run_id: int) -> dict | None:
    row = conn.execute(f"{_RUN_SELECT} WHERE r.id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_executions(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM executions WHERE run_id = ? ORDER BY id", (run_id,))]


def get_execution(conn: sqlite3.Connection, execution_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM executions WHERE id = ?", (execution_id,)).fetchone()
    return dict(row) if row else None


def list_hits(conn: sqlite3.Connection, execution_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT h.*, r.title, r.origin FROM hits h JOIN executions e ON e.id = h.execution_id "
        "JOIN runs u ON u.id = e.run_id "
        "LEFT JOIN ruleset_rules r ON r.ruleset_id = u.ruleset_id AND r.rule_id = h.rule_id "
        "WHERE h.execution_id = ? ORDER BY h.noisy, h.first_ts, h.rule_id", (execution_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["record_ids"] = json.loads(d.pop("record_ids_json"))
        d["noisy"] = bool(d["noisy"])
        out.append(d)
    return out


def list_gaps(conn: sqlite3.Connection, run_id: int | None = None) -> list[dict]:
    where, args = ("WHERE run_id = ?", (run_id,)) if run_id is not None else ("", ())
    return [dict(r) for r in conn.execute(f"SELECT * FROM gaps {where} ORDER BY run_id, id", args)]


def list_rule_noise(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT n.*, r.title, r.origin FROM rule_noise n JOIN runs u ON u.id = n.run_id "
        "LEFT JOIN ruleset_rules r ON r.ruleset_id = u.ruleset_id AND r.rule_id = n.rule_id "
        "WHERE n.run_id = ? AND n.hits > 0 ORDER BY n.hits DESC, n.rule_id", (run_id,)).fetchall()
    return [dict(r, noisy=bool(r["noisy"])) for r in rows]


def run_summary(conn: sqlite3.Connection, run_id: int) -> dict:
    """Status counts and the coverage score of a run (detected / tested, percent; untested excluded)."""
    counts = {s: 0 for s in ("detected", "partial", "missed", "telemetry_gap", "untested", "did_not_run")}
    for status, n in conn.execute("SELECT status, COUNT(*) FROM executions WHERE run_id = ? GROUP BY status", (run_id,)):
        counts[status] = n
    tested = sum(v for k, v in counts.items() if k not in ("untested", "did_not_run"))
    score = round(100.0 * counts["detected"] / tested, 1) if tested else None
    return {"counts": counts, "tested": tested, "score": score}


def set_gap_status(conn: sqlite3.Connection, gap_id: int, status: str, *, closed_in_run: int | None = None,
                   commit: bool = True) -> None:
    if status not in ("open", "closed"):
        raise ValueError("gap status must be 'open' or 'closed'")
    with _tx(conn, commit):
        conn.execute("UPDATE gaps SET status = ?, closed_in_run = ? WHERE id = ?", (status, closed_in_run, gap_id))
