"""A database created before 'did_not_run' existed is migrated in place, keeping its rows."""

import sqlite3

import pytest

from purplebench import db


def _old_database(path):
    old = db.SCHEMA.replace(",'did_not_run'", "")
    assert old != db.SCHEMA
    c = sqlite3.connect(path)
    c.executescript(old)
    c.execute("INSERT INTO campaigns (id, name) VALUES (1, 'c')")
    c.execute("INSERT INTO rulesets (id, version, created_at, rules_json_hash) VALUES (1, 'v1', 't', 'h')")
    c.execute("INSERT INTO runs (id, campaign_id, ruleset_id, mode, started_at) VALUES (1, 1, 1, 'lab', 't')")
    for i, st in enumerate(("detected", "missed", "untested"), start=1):
        c.execute("INSERT INTO executions (id, run_id, technique_id, test_guid, started_at, ended_at, status, ttd_ms,"
                  " events_ref, reason) VALUES (?, 1, 'T1003.001', 'g', 's', 'e', ?, 5, 'ref', 'why')", (i, st))
    c.execute("INSERT INTO hits (execution_id, rule_id, first_ts, count) VALUES (1, 'r', 't', 2)")
    c.execute("PRAGMA user_version = 0")
    c.commit()
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("UPDATE executions SET status = 'did_not_run' WHERE id = 1")
    c.rollback()
    c.close()


def test_old_database_is_migrated_keeping_rows(tmp_path):
    path = tmp_path / "old.db"
    _old_database(path)
    c = db.connect(path)
    try:
        assert c.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
        rows = c.execute("SELECT id, status, ttd_ms, reason FROM executions ORDER BY id").fetchall()
        assert [(r["id"], r["status"], r["ttd_ms"], r["reason"]) for r in rows] == [
            (1, "detected", 5, "why"), (2, "missed", 5, "why"), (3, "untested", 5, "why")]
        assert c.execute("SELECT COUNT(*) FROM hits WHERE execution_id = 1").fetchone()[0] == 1
        c.execute("UPDATE executions SET status = 'did_not_run' WHERE id = 3")
        assert c.execute("PRAGMA foreign_key_check").fetchall() == []
        assert c.execute("SELECT name FROM sqlite_master WHERE name = 'idx_executions_run'").fetchone()
        assert not c.execute("SELECT name FROM sqlite_master WHERE name = 'executions_new'").fetchone()
        # cascade still works through the renamed table
        c.execute("DELETE FROM executions WHERE id = 1")
        assert c.execute("SELECT COUNT(*) FROM hits").fetchone()[0] == 0
    finally:
        c.close()


def test_migration_is_idempotent_and_fresh_databases_are_current(tmp_path):
    path = tmp_path / "old.db"
    _old_database(path)
    db.connect(path).close()
    c = db.connect(path)
    assert c.execute("SELECT COUNT(*) FROM executions").fetchone()[0] == 3
    c.close()
    fresh = db.connect(tmp_path / "fresh.db")
    assert fresh.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    fresh.close()


def test_user_version_is_raised_never_lowered_and_not_rewritten(tmp_path):
    path = tmp_path / "v.db"
    db.connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version = 99")  # a newer schema: must not be downgraded
    raw.commit()
    raw.close()
    c = db.connect(path)
    assert c.execute("PRAGMA user_version").fetchone()[0] == 99
    c.close()
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version = 1")
    raw.commit()
    raw.close()
    c = db.connect(path)
    assert c.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    c.close()


def test_gaps_table_is_migrated_to_allow_accepted(tmp_path):
    path = tmp_path / "old_gaps.db"
    c = sqlite3.connect(path)
    c.executescript(db.SCHEMA.replace(",'accepted'", ""))
    c.execute("INSERT INTO campaigns (id, name) VALUES (1, 'c')")
    c.execute("INSERT INTO rulesets (id, version, created_at, rules_json_hash) VALUES (1, 'v1', 't', 'h')")
    c.execute("INSERT INTO runs (id, campaign_id, ruleset_id, mode, started_at) VALUES (1, 1, 1, 'lab', 't')")
    c.execute("INSERT INTO gaps (id, run_id, technique_id, kind, notes) VALUES (1, 1, 'T1003.001', 'missed', 'n')")
    c.execute("PRAGMA user_version = 2")
    c.commit()
    c.close()
    c = db.connect(path)
    try:
        assert db.update_gap(c, 1, status="accepted", notes="ok")
        row = c.execute("SELECT status, notes FROM gaps WHERE id = 1").fetchone()
        assert (row["status"], row["notes"]) == ("accepted", "ok")
        assert not db.update_gap(c, 5, status="open")
        assert c.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    finally:
        c.close()
