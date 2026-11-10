"""Lab run-file validation and import, using synthetic run files built from the recorded telemetry."""

import copy
import gzip
import json
from datetime import timedelta
from pathlib import Path

import pytest

from purplebench import db, runfile, scoring
from purplebench.runfile import RunFileError
from purplebench.telemetry import normalize_ts, parse_ts

GUID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture(scope="module")
def recorded():
    return [e for e in scoring.recorded_executions() if e.anchor_ts]


def _entry(ex):
    end = normalize_ts((parse_ts(ex.anchor_ts) + timedelta(seconds=20)).isoformat())
    return {"technique_id": ex.technique, "test_guid": GUID, "started_at": ex.anchor_ts, "ended_at": end,
            "events": list(ex.events)}


@pytest.fixture
def good(recorded):
    return {"format": "purplebench-run", "version": 1, "mode": "lab", "target": "LAB-WS01",
            "started_at": "2026-11-10T09:00:00Z", "campaign": "Lab smoke test",
            "executions": [_entry(recorded[0])]}


def _raw(obj):
    return json.dumps(obj).encode()


def _counts(conn):
    return [conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("runs", "executions", "campaigns")]


def test_valid_file_normalises(good):
    out = runfile.validate(_raw(good))
    assert out["target"] == "LAB-WS01"
    assert out["campaign"]["name"] == "Lab smoke test"
    assert out["executions"][0]["events"]
    assert out["executions"][0]["started_at"].endswith("Z")


def test_bom_accepted(good):
    runfile.validate(b"\xef\xbb\xbf" + _raw(good))


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
    assert ex[0]["status"] in scoring.STATUSES
    path = runfile.events_dir() / f"run{rid}_1.jsonl.gz"
    assert path.exists()
    assert ex[0]["events_ref"] == f"lab_events/run{rid}_1.jsonl.gz"


def test_import_matches_recorded_scoring(seeded_db, good, conn, recorded):
    """A recorded execution imported as lab data scores like the recorded run with the same rule set."""
    rid = runfile.import_run(conn, _raw(good))
    got = db.list_executions(conn, rid)[0]
    newest = max(db.list_rulesets(conn), key=lambda s: s["id"])
    assert db.get_run(conn, rid)["ruleset_id"] == newest["id"]
    assert got["technique_id"] == recorded[0].technique
    if got["status"] == "detected":
        assert db.list_hits(conn, got["id"])
        assert got["ttd_ms"] is not None


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


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.update(format="other"), "purplebench-run"),
    (lambda d: d.update(version=2), "version 1"),
    (lambda d: d.update(mode="recorded"), "lab"),
    (lambda d: d.update(target="\\\\evil\\share"), "host name only"),
    (lambda d: d.update(target="a" * 300), "longer"),
    (lambda d: d.update(started_at="yesterday"), "started_at"),
    (lambda d: d.update(campaign=5), "campaign"),
    (lambda d: d.update(executions=[]), "non-empty"),
    (lambda d: d.update(executions="x"), "non-empty"),
    (lambda d: d["executions"][0].update(technique_id="T1003.001; DROP TABLE runs"), "ATT&CK id"),
    (lambda d: d["executions"][0].update(test_guid="not-a-guid"), "GUID"),
    (lambda d: d["executions"][0].update(ended_at="2000-01-01T00:00:00Z"), "before"),
    (lambda d: d["executions"][0].update(events="x"), "list"),
    (lambda d: d["executions"][0]["events"].append(5), "not an object"),
    (lambda d: d["executions"][0]["events"].append({"ts": "2026-01-01T00:00:00Z"}), "needs ts"),
    (lambda d: d["executions"][0]["events"].append({"ts": "bad", "event_id": 1, "fields": {}}), "timestamp"),
    (lambda d: d["executions"][0]["events"].append({"ts": "2026-01-01T00:00:00Z", "event_id": "1", "fields": {}}),
     "event_id"),
    (lambda d: d["executions"][0]["events"].append({"ts": "2026-01-01T00:00:00Z", "event_id": 1, "fields": []}),
     "fields"),
    (lambda d: d["executions"][0]["events"].append(
        {"ts": "2026-01-01T00:00:00Z", "event_id": 1, "fields": {"a": {"nested": 1}}}), "scalar"),
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
    d["executions"][0]["events"] = [{"ts": "2026-01-01T00:00:00Z", "channel": "Security", "event_id": 4688,
                                     "host": "h", "record_id": 1, "fields": fields}]
    return d


def test_one_megabyte_command_line_rejected(good):
    d = _with_event(good, CommandLine="A" * 1_000_000)
    with pytest.raises(RunFileError, match="longer"):
        runfile.validate(_raw(d))


def test_nul_byte_rejected(good):
    d = _with_event(good, CommandLine="a\u0000b")
    with pytest.raises(RunFileError, match="NUL"):
        runfile.validate(_raw(d))


def test_too_many_fields_rejected(good):
    d = _with_event(good, **{f"f{i}": "x" for i in range(runfile.MAX_FIELDS_PER_EVENT + 1)})
    with pytest.raises(RunFileError, match="fields"):
        runfile.validate(_raw(d))


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
