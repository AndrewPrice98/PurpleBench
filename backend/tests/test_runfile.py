"""Lab run-file validation and import, using synthetic run files built from the recorded telemetry."""

import copy
import gzip
import json
from datetime import timedelta
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import pytest

from purplebench import coverage, db, runfile, scoring
from purplebench.runfile import RunFileError
from purplebench.telemetry import normalize_ts, parse_event_xml, parse_ts

GUID = "00000000-0000-4000-8000-000000000001"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def to_xml(ev):
    """Render a normalised event the way Windows renders it (Event.ToXml())."""
    data = "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in ev["fields"].items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="x"/><EventID>{ev["event_id"]}</EventID>'
            f'<TimeCreated SystemTime={quoteattr(ev["ts"])}/><EventRecordID>{ev["record_id"]}</EventRecordID>'
            f'<Channel>{escape(ev["channel"])}</Channel><Computer>{escape(ev["host"])}</Computer></System>'
            f"<EventData>{data}</EventData></Event>")


@pytest.fixture(scope="module")
def recorded():
    return [e for e in scoring.recorded_executions() if e.anchor_ts]


def _entry(ex, **over):
    end = normalize_ts((parse_ts(ex.anchor_ts) + timedelta(seconds=20)).isoformat())
    d = {"technique_id": ex.technique, "test_guid": GUID, "started_at": ex.anchor_ts, "ended_at": end,
         "run_status": "ran", "events_xml": [to_xml(e) for e in ex.events]}
    d.update(over)
    return d


@pytest.fixture
def good(recorded):
    return {"format": "purplebench-run", "version": 2, "mode": "lab", "target": "LAB-WS01",
            "started_at": "2026-11-10T09:00:00Z", "campaign": "Lab smoke test",
            "executions": [_entry(recorded[0])]}


def _raw(obj):
    return json.dumps(obj).encode()


def _counts(conn):
    return [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("runs", "executions", "campaigns")]


def test_xml_round_trip_matches_recorded_event(recorded):
    ev = recorded[0].events[0]
    assert parse_event_xml(to_xml(ev)) == ev


def test_valid_file_normalises(good):
    out = runfile.validate(_raw(good))
    assert out["target"] == "LAB-WS01"
    assert out["campaign"]["name"] == "Lab smoke test"
    assert out["executions"][0]["events"]
    assert out["executions"][0]["started_at"].endswith("Z")
    assert out["executions"][0]["run_status"] == "ran"


def test_bom_accepted(good):
    runfile.validate(b"\xef\xbb\xbf" + _raw(good))


def test_version_1_and_boolean_versions_rejected(good):
    for v in (1, True, 2.0, "2"):
        d = copy.deepcopy(good)
        d["version"] = v
        with pytest.raises(RunFileError, match="version 2"):
            runfile.validate(_raw(d))


def test_unknown_keys_rejected(good):
    d = copy.deepcopy(good)
    d["extra"] = 1
    with pytest.raises(RunFileError, match="unknown top-level"):
        runfile.validate(_raw(d))
    d = copy.deepcopy(good)
    d["executions"][0]["extra"] = 1
    with pytest.raises(RunFileError, match="unknown key"):
        runfile.validate(_raw(d))


def test_import_scores_as_lab_run(seeded_db, good, conn):
    before = _counts(conn)
    rid = runfile.import_run(conn, _raw(good))
    run = db.get_run(conn, rid)
    assert run["mode"] == "lab"
    assert "not yet been run against a real lab" in run["source"]
    assert "LAB-WS01" in run["source"]
    assert _counts(conn)[0] == before[0] + 1
    ex = db.list_executions(conn, rid)
    assert len(ex) == 1
    assert ex[0]["test_guid"] == GUID
    assert ex[0]["status"] in ("detected", "partial", "missed", "telemetry_gap")
    assert ex[0]["events_ref"] == f"lab_events/run{rid}_1.jsonl.gz"
    assert (runfile.events_dir() / f"run{rid}_1.jsonl.gz").exists()


def test_hits_store_channel_and_record_id(seeded_db, good, conn):
    rid = runfile.import_run(conn, _raw(good))
    ex = db.list_executions(conn, rid)[0]
    hits = db.list_hits(conn, ex["id"])
    assert hits, "the recorded technique should fire at least one rule"
    for h in hits:
        refs = h["record_ids"] if "record_ids" in h else json.loads(h["record_ids_json"])
        assert refs and all(isinstance(r, list) and len(r) == 2 and isinstance(r[0], str) for r in refs)


@pytest.mark.parametrize("status", ["failed", "prereqs_missing", "skipped"])
def test_did_not_run_is_never_missed_and_not_in_denominator(seeded_db, good, conn, recorded, status):
    good["executions"][0].update(run_status=status, error="Access is denied\x01 here", events_xml=[])
    good["executions"].append(_entry(recorded[1]))
    rid = runfile.import_run(conn, _raw(good))
    ex = db.list_executions(conn, rid)
    assert ex[0]["status"] == "did_not_run"
    assert "did not run" in ex[0]["reason"] and "Access is denied" in ex[0]["reason"]
    assert "\x01" not in ex[0]["reason"]
    assert ex[0]["ttd_ms"] is None
    assert not [g for g in db.list_gaps(conn, rid) if g["technique_id"] == ex[0]["technique_id"]]
    summary = db.run_summary(conn, rid)
    assert summary["counts"]["did_not_run"] == 1
    assert summary["tested"] == 1  # the second execution only


def test_collection_error_is_not_scored_as_missed(seeded_db, good, conn):
    good["executions"][0].update(collection_error="The RPC server is unavailable", events_xml=[])
    rid = runfile.import_run(conn, _raw(good))
    ex = db.list_executions(conn, rid)[0]
    assert ex["status"] == "did_not_run"
    assert "collection failed" in ex["reason"]


def test_truncated_collection_is_flagged_in_reason(seeded_db, good, conn):
    good["executions"][0]["truncated"] = True
    rid = runfile.import_run(conn, _raw(good))
    ex = db.list_executions(conn, rid)[0]
    assert "later events were not collected" in ex["reason"]


def test_coverage_excludes_did_not_run():
    ex = [scoring.Execution(technique="T1003.001", name="x", tactics=("credential-access",),
                            did_not_run_reason="failed", anchor_ts="2026-01-01T00:00:00.000000Z")]
    r = scoring.score_run([], ex, [], scoring.TelemetryProfile.from_events([]))
    assert r.executions[0].status == scoring.DID_NOT_RUN
    cov = coverage.compute_coverage(r)
    assert cov.tested == 0 and cov.score is None


def test_import_uses_newest_ruleset(seeded_db, good, conn, recorded):
    rid = runfile.import_run(conn, _raw(good))
    newest = max(db.list_rulesets(conn), key=lambda s: s["id"])
    assert db.get_run(conn, rid)["ruleset_id"] == newest["id"]
    assert db.list_executions(conn, rid)[0]["technique_id"] == recorded[0].technique


def test_import_into_existing_campaign_by_name(seeded_db, good, conn):
    first = db.list_campaigns(conn)[0]
    good["campaign"] = first["name"]
    n = len(db.list_campaigns(conn))
    rid = runfile.import_run(conn, _raw(good))
    assert len(db.list_campaigns(conn)) == n
    assert db.get_run(conn, rid)["campaign_id"] == first["id"]


def test_import_explicit_ruleset(seeded_db, good, conn):
    rid = runfile.import_run(conn, _raw(good), ruleset_id=1)
    assert db.get_run(conn, rid)["ruleset_id"] == 1


def test_import_without_ruleset_is_refused(db_file, good, conn):
    with pytest.raises(RunFileError, match="rule set"):
        runfile.import_run(conn, _raw(good))


def test_import_does_not_commit_callers_pending_transaction(seeded_db, good, conn):
    conn.execute("INSERT INTO campaigns (name, description, techniques_json) VALUES ('pending', '', '[]')")
    assert conn.in_transaction
    with pytest.raises(RuntimeError, match="open transaction"):
        runfile.import_run(conn, _raw(good))
    conn.rollback()
    assert not conn.execute("SELECT 1 FROM campaigns WHERE name = 'pending'").fetchone()


def test_failure_rolls_back_rows_and_files(seeded_db, good, conn, monkeypatch):
    real = runfile.db.add_rule_noise

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(runfile.db, "add_rule_noise", boom)
    before = _counts(conn)
    with pytest.raises(RuntimeError):
        runfile.import_run(conn, _raw(good))
    assert _counts(conn) == before
    d = runfile.events_dir()
    assert not d.exists() or not list(d.glob("*.jsonl.gz"))
    monkeypatch.setattr(runfile.db, "add_rule_noise", real)
    runfile.import_run(conn, _raw(good))  # the connection is still usable


def _ev(**over):
    base = {"ts": "2026-01-01T00:00:00Z", "channel": "Security", "event_id": 4688, "host": "h", "record_id": 1,
            "fields": {"CommandLine": "x"}}
    base.update(over)
    return base


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.update(format="other"), "purplebench-run"),
    (lambda d: d.update(version=3), "version 2"),
    (lambda d: d.update(mode="recorded"), "lab"),
    (lambda d: d.update(target="\\\\evil\\share"), "host name only"),
    (lambda d: d.update(target="LAB\n"), "control character"),
    (lambda d: d.update(target="a" * 300), "longer"),
    (lambda d: d.update(started_at="yesterday"), "started_at"),
    (lambda d: d.update(campaign=5), "campaign"),
    (lambda d: d.update(campaign="bad\x1b[31mname"), "control character"),
    (lambda d: d.update(campaign={"name": "ok", "techniques": ["T1003\n"]}), "ATT&CK"),
    (lambda d: d.update(executions=[]), "non-empty"),
    (lambda d: d.update(executions="x"), "non-empty"),
    (lambda d: d["executions"][0].update(technique_id="T1003.001; DROP TABLE runs"), "ATT&CK id"),
    (lambda d: d["executions"][0].update(technique_id="T1003.001\n"), "control character"),
    (lambda d: d["executions"][0].update(test_guid="not-a-guid"), "GUID"),
    (lambda d: d["executions"][0].update(ended_at="2000-01-01T00:00:00Z"), "before"),
    (lambda d: d["executions"][0].update(run_status="exploded"), "run_status"),
    (lambda d: d["executions"][0].update(truncated="yes"), "truncated"),
    (lambda d: d["executions"][0].update(events_xml="x"), "list"),
    (lambda d: d["executions"][0]["events_xml"].append(5), "not a string"),
    (lambda d: d["executions"][0]["events_xml"].append("<not-xml"), "unparseable"),
    (lambda d: d["executions"][0]["events_xml"].append("<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>"), "unparseable"),
    (lambda d: d["executions"][0]["events_xml"].append("<Event xmlns='x'><Foo/></Event>"), "unparseable|System"),
    (lambda d: d["executions"][0]["events_xml"].append(
        to_xml(_ev()).replace("2026-01-01T00:00:00Z", "bad")), "timestamp"),
])
def test_malformed_rejected(good, mutate, msg):
    d = copy.deepcopy(good)
    mutate(d)
    with pytest.raises(RunFileError, match=msg):
        runfile.validate(_raw(d))


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"\xff\xfe\x00", b'{"format": '])
def test_garbage_rejected(raw):
    with pytest.raises(RunFileError):
        runfile.validate(raw)


def test_oversized_file_rejected(good, monkeypatch):
    monkeypatch.setattr(runfile, "MAX_FILE_BYTES", 1000)
    with pytest.raises(RunFileError, match="larger"):
        runfile.validate(_raw(good))


def test_oversized_file_on_disk_rejected(good, tmp_path, monkeypatch):
    p = tmp_path / "run.json"
    p.write_bytes(_raw(good))
    monkeypatch.setattr(runfile, "MAX_FILE_BYTES", 1000)
    with pytest.raises(RunFileError, match="larger"):
        runfile.validate(Path(p))


def test_size_cap_is_32_mb():
    assert runfile.MAX_FILE_BYTES == 32 * 1024 * 1024


def test_too_many_events_rejected(good, monkeypatch):
    monkeypatch.setattr(runfile, "MAX_EVENTS_PER_EXECUTION", 3)
    with pytest.raises(RunFileError, match="more than 3 events"):
        runfile.validate(_raw(good))


def test_too_many_total_events_rejected(good, monkeypatch):
    monkeypatch.setattr(runfile, "MAX_EVENTS_TOTAL", 3)
    with pytest.raises(RunFileError, match="in the run"):
        runfile.validate(_raw(good))


def test_too_many_executions_rejected(good, monkeypatch):
    monkeypatch.setattr(runfile, "MAX_EXECUTIONS", 0)
    with pytest.raises(RunFileError, match="more than 0 executions"):
        runfile.validate(_raw(good))


def _with_event(good, **fields):
    d = copy.deepcopy(good)
    d["executions"][0]["events_xml"] = [to_xml(_ev(fields=fields))]
    return d


def test_one_megabyte_command_line_event_is_skipped_not_the_file(good, recorded):
    d = copy.deepcopy(good)
    d["executions"][0]["events_xml"].append(to_xml(_ev(fields={"CommandLine": "A" * 1_000_000})))
    d["executions"][0]["events_xml"].append(to_xml(_ev(fields={"Details": "B" * (runfile.MAX_FIELD_VALUE + 1)})))
    out = runfile.validate(_raw(d))
    ex = out["executions"][0]
    assert ex["skipped_oversize"] == 2
    assert len(ex["events"]) == len(good["executions"][0]["events_xml"])  # the normal events survive


def test_field_at_the_limit_is_kept(good):
    d = _with_event(good, Details="x" * runfile.MAX_FIELD_VALUE)
    ex = runfile.validate(_raw(d))["executions"][0]
    assert ex["skipped_oversize"] == 0 and len(ex["events"]) == 1


def test_skipped_and_dropped_events_are_flagged_in_the_stored_reason(seeded_db, good, conn):
    good["executions"][0]["events_xml"].append(to_xml(_ev(fields={"Details": "B" * 70_000})))
    good["executions"][0]["dropped_oversize"] = 3
    good["executions"][0]["truncated"] = True
    rid = runfile.import_run(conn, _raw(good))
    reason = db.list_executions(conn, rid)[0]["reason"]
    assert "4 event(s) over the size limit were left out (3 by the runner, 1 on import)" in reason
    assert "collection hit its cap" in reason and "later events were not collected" in reason


def test_dropped_oversize_must_be_a_count(good):
    for bad in (-1, True, "3", 1.5):
        d = copy.deepcopy(good)
        d["executions"][0]["dropped_oversize"] = bad
        with pytest.raises(RunFileError, match="dropped_oversize"):
            runfile.validate(_raw(d))


def test_unicode_digits_are_not_ascii_digits(good):
    d = copy.deepcopy(good)
    d["executions"][0]["technique_id"] = "T١٢٣٤"
    with pytest.raises(RunFileError, match="ATT&CK"):
        runfile.validate(_raw(d))


def test_nul_byte_rejected(good):
    d = copy.deepcopy(good)
    d["executions"][0]["events_xml"] = [to_xml(_ev()).replace(">x<", ">a\u0000b<")]
    with pytest.raises(RunFileError, match="NUL"):
        runfile.validate(_raw(d))


def test_too_many_fields_event_is_skipped(good):
    d = _with_event(good, **{f"f{i}": "x" for i in range(runfile.MAX_FIELDS_PER_EVENT + 1)})
    ex = runfile.validate(_raw(d))["executions"][0]
    assert ex["skipped_oversize"] == 1 and ex["events"] == []


def test_deep_nesting_rejected_without_recursion_error():
    with pytest.raises(RunFileError, match="deeply"):
        runfile.validate(b"[" * 200_000 + b"]" * 200_000)
    with pytest.raises(RunFileError, match="deeply"):
        runfile.validate(b'{"a":' * 100_000 + b"1" + b"}" * 100_000)


def test_brackets_inside_strings_do_not_count_as_depth(good):
    d = _with_event(good, CommandLine='[[[[[[[[[[[[[[{{{{{{{{{{{{{{{{\\"')
    runfile.validate(_raw(d))


def test_hostile_strings_stored_inertly(seeded_db, good, conn):
    evil = "'; DROP TABLE runs; --<script>alert(1)</script>${jndi:ldap://x}%s{0}"
    d = _with_event(good, CommandLine=evil, Image="C:\\x\\..\\..\\evil.exe")
    d["campaign"] = {"name": evil[:200], "techniques": []}
    rid = runfile.import_run(conn, _raw(d))
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] >= 5
    camp = db.get_campaign(conn, db.get_run(conn, rid)["campaign_id"])
    assert camp["name"] == evil[:200]
    path = runfile.events_dir() / f"run{rid}_1.jsonl.gz"
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        assert json.loads(fh.readline())["fields"]["CommandLine"] == evil


def test_unknown_technique_imports_with_id_as_name(seeded_db, good, conn):
    good["executions"][0]["technique_id"] = "T9999"
    rid = runfile.import_run(conn, _raw(good))
    assert db.list_executions(conn, rid)[0]["technique_id"] == "T9999"
