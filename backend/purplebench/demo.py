"""The demo purple-team exercise: load it into an empty database.

The data lives in ``backend/data/demo_fixture.json``, built by ``backend/scripts/build_demo.py`` with the real
Sigma evaluator over the committed recorded telemetry. Every run in it is **recorded mode**: no command was
executed, no lab was used. Cold start only reads the fixture; nothing is evaluated at request time.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading

from . import config, db

log = logging.getLogger(__name__)
_seed_lock = threading.Lock()


def load_fixture() -> dict:
    with open(config.DEMO_FIXTURE, encoding="utf-8") as handle:
        return json.load(handle)


def _already_seeded(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM campaigns LIMIT 1").fetchone() is not None


def seed(conn: sqlite3.Connection) -> bool:
    """Load the demo in one transaction: either everything is stored or nothing is. Returns False
    (and does nothing) if the database already has campaigns, so calling it twice is safe."""
    if _already_seeded(conn):
        return False
    fixture = load_fixture()
    conn.commit()  # no transaction may be open when taking the write lock
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-check under the write lock: another process may have seeded meanwhile.
        if _already_seeded(conn):
            conn.rollback()
            return False
        for c in fixture["campaigns"]:
            db.add_campaign(conn, c["name"], c["description"], c["techniques"], id=c["id"], commit=False)
        for s in fixture["rulesets"]:
            db.add_ruleset(conn, s["version"], s["created_at"], s["rules_json_hash"], s["notes"], s["rules"],
                           id=s["id"], commit=False)
        # All runs first: a gap closed by a later run refers to it.
        for r in fixture["runs"]:
            db.add_run(conn, r["campaign_id"], r["ruleset_id"], r["mode"], r["source"], r["started_at"], r["notes"],
                       id=r["id"], commit=False)
        for r in fixture["runs"]:
            for ex in r["executions"]:
                db.add_execution(conn, r["id"], ex, commit=False)
            db.add_rule_noise(conn, r["id"], r["rule_noise"], commit=False)
            for gap in r["gaps"]:
                db.add_gap(conn, r["id"], gap, commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return True


def ensure_seeded() -> None:
    """Create and seed the database if this instance does not have one yet."""
    with _seed_lock:
        conn = db.connect()
        try:
            if seed(conn):
                log.info("Seeded demo database at %s", config.db_path())
        finally:
            conn.close()
