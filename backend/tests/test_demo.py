"""The demo exercise: the story it tells, that it was built by the real evaluator, and atomic seeding."""

import importlib.util
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import pytest

from purplebench import config, db, demo, library, rulesets, scoring
from purplebench.sigma import recorded_profile
from purplebench.telemetry import read_jsonl_gz

BACKEND = Path(__file__).resolve().parent.parent
TABLES = ("campaigns", "rulesets", "ruleset_rules", "runs", "executions", "hits", "rule_noise", "gaps")
ENC = "Suspicious Execution of Powershell with Base64"
TUNED = "PowerShell Encoded Command Outside The Remote Management Harness"


def _count(c, table):
    return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


@pytest.fixture
def fixture():
    return demo.load_fixture()


@pytest.fixture
def seeded(seeded_db):
    c = db.connect(seeded_db)
    yield c
    c.close()


def _build_module():
    spec = importlib.util.spec_from_file_location("build_demo", BACKEND / "scripts" / "build_demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- the story -------------------------------------------------------------------------------------

def test_two_campaigns_cover_every_library_technique(seeded):
    camps = db.list_campaigns(seeded)
    assert [c["name"] for c in camps] == ["Initial access to credential theft", "Ransomware precursors"]
    union = set(camps[0]["techniques"]) | set(camps[1]["techniques"])
    assert union == {t.attack_id for t in library.list_techniques()}
    assert set(camps[0]["techniques"]) & set(camps[1]["techniques"])  # a technique may be in both


def test_four_recorded_runs_over_six_weeks(seeded):
    runs = db.list_runs(seeded)
    assert [r["ruleset_version"] for r in runs] == ["v1", "v2", "v3", "v4"]
    assert {r["mode"] for r in runs} == {"recorded"}
    assert all("Recorded mode" in r["source"] and "Splunk attack_data" in r["source"] for r in runs)
    start, end = (datetime.strptime(runs[i]["started_at"], "%Y-%m-%dT%H:%M:%SZ") for i in (0, -1))
    assert (end - start).days == 42  # six weeks
    assert runs[0]["started_at"].startswith("2026-09-28")  # the fixed anchor date


def test_rule_set_versions_grow_to_the_full_set(seeded):
    sets = db.list_rulesets(seeded)
    assert [s["rule_count"] for s in sets] == [15, 30, 34, 70]
    rules = [db.get_ruleset(seeded, s["id"])["rules"] for s in sets]
    ids = [{r["rule_id"] for r in rs} for rs in rules]
    assert ids[0] < ids[1] < ids[2] < ids[3]
    assert sum(r["origin"] == "custom" for r in rules[3]) == 12
    # v1 and v2 are SigmaHQ only; the first custom rules arrive in v3 and each names the gap it closes.
    assert {r["origin"] for r in rules[0]} == {"sigmahq"} and {r["origin"] for r in rules[1]} == {"sigmahq"}
    v3_new = [r for r in rules[2] if r["added_in"] == "v3"]
    assert len(v3_new) == 4 and all(r["origin"] == "custom" and r["note"].startswith("Closes") for r in v3_new)


def test_coverage_strictly_increases_from_v1_to_v4(fixture):
    overall = [p["all"] for p in fixture["meta"]["progression"]]
    assert [(o["detected"], o["tested"]) for o in overall] == [(9, 25), (13, 25), (18, 25), (22, 25)]
    scores = [o["score"] for o in overall]
    assert scores == [36.0, 52.0, 72.0, 88.0]
    assert all(a < b for a, b in zip(scores, scores[1:], strict=False))


def test_stored_runs_improve_per_campaign(seeded):
    by_campaign = {}
    for r in db.list_runs(seeded):
        by_campaign.setdefault(r["campaign_id"], []).append(db.run_summary(seeded, r["id"])["score"])
    assert by_campaign[1] == [42.9, 71.4]
    assert by_campaign[2] == [64.3, 85.7]


def test_run_summaries_match_the_fixture(seeded, fixture):
    for r in fixture["runs"]:
        s = db.run_summary(seeded, r["id"])
        assert s["counts"] == r["summary"]["counts"] and s["score"] == r["summary"]["score"]
        assert s["tested"] == r["summary"]["tested"]


def test_untested_technique_is_excluded_from_every_denominator(seeded):
    for run_id in (1, 3):  # the credential theft campaign lists T1558.003
        ex = {e["technique_id"]: e for e in db.list_executions(seeded, run_id)}
        assert ex["T1558.003"]["status"] == "untested" and ex["T1558.003"]["ttd_ms"] is None
        s = db.run_summary(seeded, run_id)
        assert s["counts"]["untested"] == 1 and s["tested"] == 14
        assert not any(g["technique_id"] == "T1558.003" for g in db.list_gaps(seeded, run_id))
        assert "no execution" in ex["T1558.003"]["reason"]


def test_a_named_gap_closes_in_a_later_run(seeded):
    gaps = {(g["run_id"], g["technique_id"]): g for g in db.list_gaps(seeded)}
    closed = gaps[(1, "T1059.001")]
    assert closed["status"] == "closed" and closed["closed_in_run"] == 3
    assert TUNED in closed["notes"]
    later = {e["technique_id"]: e for e in db.list_executions(seeded, 3)}
    assert later["T1059.001"]["status"] == "detected"
    assert gaps[(2, "T1560.001")]["status"] == "closed" and gaps[(2, "T1560.001")]["closed_in_run"] == 4
    # every closed gap is detected in the run that closed it
    for g in gaps.values():
        if g["status"] == "closed":
            status = {e["technique_id"]: e["status"] for e in db.list_executions(seeded, g["closed_in_run"])}
            assert status[g["technique_id"]] == "detected"


def test_some_gaps_stay_open_with_honest_notes(seeded):
    open_gaps = {(g["run_id"], g["technique_id"]): g for g in db.list_gaps(seeded) if g["status"] == "open"}
    assert (4, "T1021.002") in open_gaps and (4, "T1569.002") in open_gaps and (3, "T1550.002") in open_gaps
    assert "Limit of the recorded data" in open_gaps[(3, "T1550.002")]["notes"]
    assert open_gaps[(3, "T1550.002")]["kind"] == "telemetry_gap"  # not "missed": no Security channel recorded
    assert "Not re-run yet" in open_gaps[(3, "T1218.011")]["notes"]  # v4 would close it; not claimed as closed
    for g in open_gaps.values():
        assert g["telemetry_needed"] and g["rule_idea"]


def test_gaps_come_from_missed_telemetry_gap_and_partial_executions(seeded):
    for run in db.list_runs(seeded):
        statuses = {e["technique_id"]: e["status"] for e in db.list_executions(seeded, run["id"])}
        gaps = db.list_gaps(seeded, run["id"])
        assert {g["technique_id"] for g in gaps} == {t for t, s in statuses.items()
                                                      if s in ("missed", "telemetry_gap", "partial")}
        assert all(g["kind"] == statuses[g["technique_id"]] for g in gaps)


def test_a_noisy_rule_is_visible_and_earns_no_credit(seeded):
    noise = {n["title"]: n for n in db.list_rule_noise(seeded, 2)}
    enc = noise[ENC]
    assert enc["hits"] == 5 and enc["noisy"] and enc["origin"] == "sigmahq"
    # run 2: the noisy rule's exact credit is withheld; only a related mshta hit (T1218.005) remains -> partial
    run2 = {e["technique_id"]: e for e in db.list_executions(seeded, 2)}
    ex2 = run2["T1059.001"]
    hits2 = db.list_hits(seeded, ex2["id"])
    assert ex2["status"] == "partial" and "T1218.005" in ex2["reason"] and "earned no credit" in ex2["reason"]
    assert [(h["relation"], h["noisy"]) for h in hits2 if h["title"] == ENC] == [("exact", True)]
    assert [h["relation"] for h in hits2 if not h["noisy"]] == ["related"]
    # T1082 in run 2: only the noisy rule, tagged for another technique, fired -> no credit at all
    ex82 = run2["T1082"]
    assert ex82["status"] == "missed" and "noisy rule(s) for other techniques" in ex82["reason"]
    assert all(h["noisy"] and h["relation"] == "related" for h in db.list_hits(seeded, ex82["id"]))
    # run 4: still enabled and still flagged noisy, but the tuned custom rule carries the detection
    ex4 = next(e for e in db.list_executions(seeded, 4) if e["technique_id"] == "T1059.001")
    hits = {h["title"]: h for h in db.list_hits(seeded, ex4["id"])}
    assert ex4["status"] == "detected"
    assert hits[ENC]["noisy"] is True and hits[TUNED]["noisy"] is False
    assert "earned no credit" in ex4["reason"]


def test_every_status_is_backed_by_its_hits(seeded):
    for run in db.list_runs(seeded):
        for e in db.list_executions(seeded, run["id"]):
            hits = db.list_hits(seeded, e["id"])
            credited = [h for h in hits if h["relation"] == "exact" and not h["noisy"]]
            if e["status"] == "detected":
                assert credited and e["ttd_ms"] is not None and e["ttd_ms"] >= 0
            else:
                assert not credited
            if e["status"] in ("missed", "telemetry_gap", "untested"):
                assert not [h for h in hits if not h["noisy"] and h["relation"] != "none"]
            assert e["events_ref"] and (e["status"] == "untested" or e["started_at"] < e["ended_at"])


def test_matched_event_refs_point_at_real_recorded_events(seeded):
    cache = {}
    checked = 0
    for run in db.list_runs(seeded):
        for e in db.list_executions(seeded, run["id"]):
            path = library.DATA_DIR / "telemetry" / e["events_ref"]
            ids = cache.setdefault(e["events_ref"], {ev["record_id"] for ev in read_jsonl_gz(path)})
            for h in db.list_hits(seeded, e["id"]):
                assert h["record_ids"] and len(h["record_ids"]) == h["count"]
                assert set(h["record_ids"]) <= ids
                checked += 1
    assert checked > 100


def test_ruleset_hash_matches_the_rule_files_in_the_repository(seeded):
    by_id = {r.id: r for r in rulesets.load_all_rules().values()}
    for s in db.list_rulesets(seeded):
        selected = [by_id[r["rule_id"]] for r in db.get_ruleset(seeded, s["id"])["rules"]]
        assert rulesets.rules_hash(selected) == s["rules_json_hash"]
    assert len({s["rules_json_hash"] for s in db.list_rulesets(seeded)}) == 4


def test_hash_ignores_line_endings_but_not_content(tmp_path):
    from purplebench.sigma import load_rules

    originals = list(rulesets.load_all_rules().values())[:3]
    base = rulesets.rules_hash(originals)
    copy = tmp_path / "c"
    copy.mkdir()
    for r in originals:
        (copy / Path(r.path).name).write_bytes(Path(r.path).read_bytes().replace(b"\n", b"\r\n"))
    assert rulesets.rules_hash(load_rules(copy)) == base
    first = copy / Path(originals[0].path).name
    first.write_bytes(first.read_bytes() + b"# edit\n")
    assert rulesets.rules_hash(load_rules(copy)) != base


def test_rule_set_definitions_are_consistent():
    rules = rulesets.load_all_rules()
    stems = sorted(rules)
    seen = []
    for d in rulesets.RULESETS[:-1]:
        for s, _ in d.adds:
            assert s in rules, s
            assert s not in seen, f"{s} added twice"
            seen.append(s)
    assert rulesets.ruleset_stems("v4", stems) == stems
    with pytest.raises(ValueError):
        rulesets.ruleset_stems("v9", stems)
    for stem in rulesets.V4_NOTES:
        assert stem in rules and stem not in seen  # notes only for rules first enabled in v4


# -- built by the real evaluator --------------------------------------------------------------------

def test_fixture_matches_a_rescoring_with_the_real_evaluator(fixture):
    """Score run 3 again here, independently of the build script, and compare statuses and hits."""
    rules = rulesets.load_all_rules()
    run = fixture["runs"][2]
    selected = [rules[s] for s in rulesets.ruleset_stems("v3", sorted(rules))]
    techs = set(fixture["campaigns"][0]["techniques"])
    execs = [e for e in scoring.recorded_executions() if e.technique in techs]
    rs = scoring.score_run(selected, execs, scoring.recorded_baseline(), recorded_profile())
    got = {e.technique: (e.status, sorted(h.rule_id for h in e.hits)) for e in rs.executions}
    want = {e["technique_id"]: (e["status"], sorted(h["rule_id"] for h in e["hits"])) for e in run["executions"]}
    assert got == want


def test_committed_fixture_matches_fresh_build():
    module = _build_module()
    with open(config.DEMO_FIXTURE, encoding="utf-8") as handle:
        committed = json.load(handle)
    text = module.render()
    assert committed == json.loads(text)
    assert module.render() == text  # deterministic
    assert config.DEMO_FIXTURE.read_bytes().decode("utf-8").replace("\r\n", "\n") == text


# -- seeding ----------------------------------------------------------------------------------------

def test_seed_is_idempotent(conn):
    assert demo.seed(conn) is True
    before = {t: _count(conn, t) for t in TABLES}
    assert demo.seed(conn) is False
    assert {t: _count(conn, t) for t in TABLES} == before
    assert before["campaigns"] == 2 and before["rulesets"] == 4 and before["runs"] == 4
    assert before["executions"] == 2 * 15 + 2 * 14 and before["ruleset_rules"] == 15 + 30 + 34 + 70


def test_cold_start_only_loads_the_fixture(conn, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("seeding must not evaluate rules")

    monkeypatch.setattr(scoring, "score_run", boom)
    start = time.perf_counter()
    assert demo.seed(conn)
    assert time.perf_counter() - start < 3


def test_ensure_seeded_creates_database(db_file):
    assert not db_file.exists()
    demo.ensure_seeded()
    demo.ensure_seeded()  # second call is a no-op
    c = db.connect(db_file)
    try:
        assert _count(c, "runs") == 4
    finally:
        c.close()


def test_failed_seed_leaves_database_empty_and_retry_succeeds(db_file, monkeypatch):
    real = db.add_execution
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 7:
            raise RuntimeError("simulated failure partway through seeding")
        return real(*args, **kwargs)

    monkeypatch.setattr(db, "add_execution", flaky)
    with pytest.raises(RuntimeError):
        demo.ensure_seeded()
    c = db.connect(db_file)
    try:
        for table in TABLES:
            assert _count(c, table) == 0, table
    finally:
        c.close()

    monkeypatch.setattr(db, "add_execution", real)
    demo.ensure_seeded()
    c = db.connect(db_file)
    try:
        assert _count(c, "campaigns") == 2 and _count(c, "runs") == 4 and _count(c, "executions") == 58
    finally:
        c.close()


def test_failure_in_a_late_table_also_rolls_everything_back(conn, monkeypatch):
    def broken(*a, **k):
        raise sqlite3.IntegrityError("simulated")

    monkeypatch.setattr(db, "add_gap", broken)
    with pytest.raises(sqlite3.IntegrityError):
        demo.seed(conn)
    assert all(_count(conn, t) == 0 for t in TABLES)
    assert not conn.in_transaction


def test_seed_rechecks_under_write_lock(conn, db_file):
    other = db.connect(db_file)
    try:
        other.execute("INSERT INTO campaigns (name) VALUES ('Already here')")
        other.commit()
        assert demo.seed(conn) is False
    finally:
        other.close()
    assert _count(conn, "campaigns") == 1 and _count(conn, "runs") == 0


# -- schema ------------------------------------------------------------------------------------------

def test_schema_rejects_bad_values(conn):
    cid = db.add_campaign(conn, "c", "", [])
    sid = db.add_ruleset(conn, "v1", "2026-01-01T00:00:00Z", "h", "", [])
    with pytest.raises(sqlite3.IntegrityError):
        db.add_run(conn, cid, sid, "live", "", "2026-01-01T00:00:00Z")  # mode must be recorded or lab
    rid = db.add_run(conn, cid, sid, "lab", "", "2026-01-01T00:00:00Z")
    assert db.get_run(conn, rid)["mode"] == "lab"
    ex = {"technique_id": "T1", "test_guid": None, "started_at": None, "ended_at": None, "status": "maybe",
          "ttd_ms": None, "events_ref": "", "reason": "", "hits": []}
    with pytest.raises(sqlite3.IntegrityError):
        db.add_execution(conn, rid, ex)
    with pytest.raises(ValueError):
        db.add_gap(conn, rid, {"technique_id": "T1", "kind": "nope", "notes": "", "status": "open",
                               "telemetry_needed": "", "rule_idea": ""})
    with pytest.raises(sqlite3.IntegrityError):
        db.add_run(conn, 999, sid, "recorded", "", "2026-01-01T00:00:00Z")  # foreign key


def test_deleting_a_campaign_removes_its_runs_and_children(seeded):
    seeded.execute("DELETE FROM campaigns WHERE id = 1")
    seeded.commit()
    assert [r["id"] for r in db.list_runs(seeded)] == [2, 4]
    assert _count(seeded, "executions") == 14 * 2
    assert not seeded.execute("SELECT 1 FROM hits WHERE execution_id NOT IN (SELECT id FROM executions)").fetchone()
    assert all(g["run_id"] in (2, 4) for g in db.list_gaps(seeded))


def test_gap_status_can_be_changed(seeded):
    gap = db.list_gaps(seeded, 4)[0]
    db.set_gap_status(seeded, gap["id"], "closed", closed_in_run=None)
    assert next(g for g in db.list_gaps(seeded, 4) if g["id"] == gap["id"])["status"] == "closed"
    with pytest.raises(ValueError):
        db.set_gap_status(seeded, gap["id"], "maybe")
