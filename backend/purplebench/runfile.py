"""Validation and import of lab run files written by ``lab/Invoke-PurpleBenchRun.ps1``.

A run file is untrusted input: it may come from a lab VM that the tests just attacked, and its event
fields contain attacker-controlled strings (command lines, file names). It is therefore checked for
size, JSON depth, schema, timestamps, string lengths and counts before anything is stored, and nothing
in it is executed or evaluated except by the Sigma evaluator (which only compares strings).

File format (``format = "purplebench-run"``, ``version = 1``)::

    {"format": "purplebench-run", "version": 1, "mode": "lab", "target": "LAB-WS01",
     "started_at": "2026-11-10T09:00:00Z", "campaign": "name" | {"name": "...", "techniques": [...]},
     "executions": [{"technique_id": "T1003.001", "test_guid": "<guid>|null",
                     "started_at": "...", "ended_at": "...",
                     "events": [{"ts", "channel", "event_id", "host", "record_id", "fields"}]}]}

Import scores the run with the chosen rule set (default: the newest) using the same scorer as recorded
mode. Two differences are deliberate and stored in the run notes: the telemetry profile is built from
the events of the run itself (what this lab actually collected), and there is no benign baseline, so
rule noise is not measured for lab runs.
"""

from __future__ import annotations

import gzip
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import config, db, library, rulesets, scoring
from .coverage import GENERIC_HINT, load_gap_hints
from .sigma import EventIndex, TelemetryProfile, evaluate
from .telemetry import TelemetryError, normalize_ts, parse_event_json, parse_ts

FORMAT = "purplebench-run"
VERSION = 1

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EXECUTIONS = 500
MAX_EVENTS_PER_EXECUTION = 50_000
MAX_EVENTS_TOTAL = 200_000
MAX_FIELDS_PER_EVENT = 200
MAX_FIELD_NAME = 128
MAX_FIELD_VALUE = 65_536  # a 1 MB command line is refused, not truncated: the evidence would be partial
MAX_SHORT = 256  # target, channel, host, campaign name, technique id
MAX_DEPTH = 6  # run file > executions > execution > events > event > fields

_TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class RunFileError(ValueError):
    """The run file is not acceptable. The message says why and is safe to show to the user."""


def _depth_ok(raw: bytes) -> bool:
    """Cheap bracket-depth precheck so the JSON parser never recurses on hostile nesting."""
    depth = 0
    in_str = False
    esc = False
    limit = MAX_DEPTH + 2
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b in (0x7B, 0x5B):
            depth += 1
            if depth > limit:
                return False
        elif b in (0x7D, 0x5D):
            depth -= 1
    return True


def _str(value: Any, what: str, limit: int = MAX_SHORT, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise RunFileError(f"{what} must be a string")
    if "\x00" in value:
        raise RunFileError(f"{what} contains a NUL byte")
    if len(value) > limit:
        raise RunFileError(f"{what} is longer than {limit} characters")
    if not value and not allow_empty:
        raise RunFileError(f"{what} is empty")
    return value


def _ts(value: Any, what: str) -> str:
    try:
        return normalize_ts(_str(value, what, 64))
    except TelemetryError as exc:
        raise RunFileError(f"{what}: {exc}") from exc


def _event(obj: Any, where: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise RunFileError(f"{where}: event is not an object")
    if not {"ts", "event_id", "fields"} <= obj.keys():
        raise RunFileError(f"{where}: event needs ts, event_id and fields")
    fields = obj["fields"]
    if not isinstance(fields, dict):
        raise RunFileError(f"{where}: fields is not an object")
    if len(fields) > MAX_FIELDS_PER_EVENT:
        raise RunFileError(f"{where}: more than {MAX_FIELDS_PER_EVENT} fields")
    for k, v in fields.items():
        _str(k, f"{where}: field name", MAX_FIELD_NAME)
        if v is not None and not isinstance(v, (str, int, float, bool)):
            raise RunFileError(f"{where}: field {k!r} is not a scalar")
        _str("" if v is None else str(v), f"{where}: field {k!r}", MAX_FIELD_VALUE, allow_empty=True)
    for key in ("channel", "host"):
        _str(obj.get(key, ""), f"{where}: {key}", MAX_SHORT, allow_empty=True)
    eid = obj["event_id"]
    if isinstance(eid, bool) or not isinstance(eid, int) or not 0 <= eid <= 65535:
        raise RunFileError(f"{where}: event_id must be an integer 0 to 65535")
    rid = obj.get("record_id", 0)
    if isinstance(rid, bool) or not isinstance(rid, int) or not 0 <= rid < 2**63:
        raise RunFileError(f"{where}: record_id must be a non-negative integer")
    _str(obj["ts"], f"{where}: ts", 64)
    try:
        return parse_event_json(obj)  # shared normalisation (timestamps, field coercion)
    except TelemetryError as exc:
        raise RunFileError(f"{where}: {exc}") from exc


def validate(raw: bytes | str | Path) -> dict[str, Any]:
    """Check a run file and return its normalised form (events normalised, timestamps in UTC)."""
    if isinstance(raw, Path):
        if raw.stat().st_size > MAX_FILE_BYTES:
            raise RunFileError(f"run file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
        raw = raw.read_bytes()
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_FILE_BYTES:
        raise RunFileError(f"run file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    if raw.startswith(b"\xef\xbb\xbf"):  # PowerShell 5.1 writes a BOM with -Encoding UTF8
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunFileError("run file is not valid UTF-8") from exc
    if not _depth_ok(raw):
        raise RunFileError("run file is nested too deeply")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise RunFileError("run file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise RunFileError("run file must be a JSON object")
    if data.get("format") != FORMAT or data.get("version") != VERSION:
        raise RunFileError(f"not a {FORMAT} version {VERSION} file")
    if data.get("mode") != "lab":
        raise RunFileError('run file mode must be "lab"')
    target = _str(data.get("target"), "target")
    if not _HOST.match(target):
        raise RunFileError("target must be a host name only (letters, digits, dot, dash, underscore)")
    started = _ts(data.get("started_at"), "started_at")

    camp = data.get("campaign")
    if isinstance(camp, dict):
        camp_name = _str(camp.get("name"), "campaign name")
        camp_techs = camp.get("techniques", [])
        if not isinstance(camp_techs, list) or len(camp_techs) > MAX_EXECUTIONS:
            raise RunFileError("campaign techniques must be a short list")
        for t in camp_techs:
            if not isinstance(t, str) or not _TECH.match(t):
                raise RunFileError("campaign techniques must be ATT&CK ids")
    else:
        camp_name, camp_techs = _str(camp, "campaign"), []

    rows = data.get("executions")
    if not isinstance(rows, list) or not rows:
        raise RunFileError("executions must be a non-empty list")
    if len(rows) > MAX_EXECUTIONS:
        raise RunFileError(f"more than {MAX_EXECUTIONS} executions")
    total = 0
    executions: list[dict[str, Any]] = []
    for i, row in enumerate(rows):
        where = f"execution {i + 1}"
        if not isinstance(row, dict):
            raise RunFileError(f"{where} is not an object")
        tech = _str(row.get("technique_id"), f"{where}: technique_id")
        if not _TECH.match(tech):
            raise RunFileError(f"{where}: technique_id is not an ATT&CK id")
        guid = row.get("test_guid")
        if guid is not None and not (isinstance(guid, str) and _GUID.match(guid)):
            raise RunFileError(f"{where}: test_guid is not a GUID")
        t0, t1 = _ts(row.get("started_at"), f"{where}: started_at"), _ts(row.get("ended_at"), f"{where}: ended_at")
        if parse_ts(t1) < parse_ts(t0):
            raise RunFileError(f"{where}: ended_at is before started_at")
        evs = row.get("events")
        if not isinstance(evs, list):
            raise RunFileError(f"{where}: events must be a list")
        if len(evs) > MAX_EVENTS_PER_EXECUTION:
            raise RunFileError(f"{where}: more than {MAX_EVENTS_PER_EXECUTION} events")
        total += len(evs)
        if total > MAX_EVENTS_TOTAL:
            raise RunFileError(f"more than {MAX_EVENTS_TOTAL} events in the run")
        events = [_event(e, f"{where}, event {j + 1}") for j, e in enumerate(evs)]
        executions.append({"technique_id": tech, "test_guid": guid.lower() if guid else None,
                           "started_at": t0, "ended_at": t1, "events": events})
    return {"target": target, "started_at": started, "campaign": {"name": camp_name, "techniques": camp_techs},
            "executions": executions}


def _record_ids(rule, index: EventIndex, profile: TelemetryProfile, anchor: str, skew: float,
                window: float) -> list[int]:
    res = evaluate(rule, index, profile)
    return [ref.record_id for ref in res.matches if -skew <= scoring._seconds(ref.ts, anchor) <= window]


def events_dir() -> Path:
    """Where stored lab events live (next to the database); the API pages them from here."""
    return config.db_path().parent / "lab_events"


def import_run(conn: sqlite3.Connection, raw: bytes | str | Path, *, ruleset_id: int | None = None,
               noise_threshold: int = scoring.DEFAULT_NOISE_THRESHOLD) -> int:
    """Validate ``raw`` and store it as a lab run scored with the rule set. Returns the run id.

    Nothing is stored if validation or scoring fails.
    """
    run = validate(raw)
    if ruleset_id is not None:
        rs_row = db.get_ruleset(conn, ruleset_id)
    else:
        sets = db.list_rulesets(conn)
        rs_row = max(sets, key=lambda s: s["id"]) if sets else None
    if rs_row is None:
        raise RunFileError("no rule set to score with: seed or create a rule set first")
    wanted = {r["rule_id"] for r in conn.execute(
        "SELECT rule_id FROM ruleset_rules WHERE ruleset_id = ?", (rs_row["id"],)).fetchall()}
    rules = [r for r in rulesets.load_all_rules().values() if r.id in wanted]
    lib = {t.attack_id: t for t in library.list_techniques()}

    execs, all_events = [], []
    for ex in run["executions"]:
        t = lib.get(ex["technique_id"])
        dur = (parse_ts(ex["ended_at"]) - parse_ts(ex["started_at"])).total_seconds()
        execs.append(scoring.Execution(
            technique=ex["technique_id"], name=t.name if t else ex["technique_id"], tactics=t.tactics if t else (),
            events=ex["events"], anchor_ts=ex["started_at"],
            window_seconds=scoring.DEFAULT_WINDOW_SECONDS + max(0.0, dur),
            atomic_test=t.atomic.name if t and t.atomic else None))
        all_events.extend(ex["events"])
    profile = TelemetryProfile.from_events(all_events)
    score = scoring.score_run(rules, execs, [], profile, noise_threshold)
    hints = load_gap_hints()

    campaign = next((c for c in db.list_campaigns(conn) if c["name"] == run["campaign"]["name"]), None)
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    written: list[Path] = []
    try:
        if campaign is None:
            techs = run["campaign"]["techniques"] or sorted({e["technique_id"] for e in run["executions"]})
            cid = db.add_campaign(conn, run["campaign"]["name"], "Imported from a lab run file.", techs, commit=False)
        else:
            cid = campaign["id"]
        source = (f"Lab run on {run['target']} from a run file written by the PurpleBench lab runner. "
                  "Lab mode has not yet been run against a real lab by the project author; "
                  "this result is only as good as the lab that produced the file.")
        notes = ("No benign baseline is collected in lab mode, so rule noise was not measured for this run. "
                 f"Telemetry profile: the events of this run. Scored with rule set {rs_row['version']}.")
        run_id = db.add_run(conn, cid, rs_row["id"], "lab", source, run["started_at"], notes, commit=False)
        by_rule = {r.id: r for r in rules}
        out_dir = events_dir()
        for n, (ex, es) in enumerate(zip(run["executions"], score.executions, strict=True), start=1):
            index = EventIndex(ex["events"])
            window = execs[n - 1].window_seconds
            hits = []
            for h in es.hits:
                ids = _record_ids(by_rule[h.rule_id], index, profile, ex["started_at"], score.skew_seconds, window)
                hits.append({"rule_id": h.rule_id, "first_ts": h.first_ts, "count": h.events, "relation": h.relation,
                             "noisy": h.noisy, "noise_hits": h.noise_hits, "record_ids": ids})
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"run{run_id}_{n}.jsonl.gz"
            written.append(path)
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                for ev in ex["events"]:
                    fh.write(json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
            db.add_execution(conn, run_id, {
                "technique_id": ex["technique_id"], "test_guid": ex["test_guid"], "started_at": ex["started_at"],
                "ended_at": ex["ended_at"], "status": es.status,
                "ttd_ms": None if es.ttd_seconds is None else round(es.ttd_seconds * 1000),
                "events_ref": f"lab_events/run{run_id}_{n}.jsonl.gz", "reason": es.reason, "hits": hits},
                commit=False)
            if es.status in ("missed", "telemetry_gap", "partial"):
                hint = hints.get(es.technique) or GENERIC_HINT
                db.add_gap(conn, run_id, {
                    "technique_id": es.technique, "kind": es.status, "notes": es.reason.rstrip(".") + ".",
                    "status": "open", "telemetry_needed": hint["telemetry_needed"], "rule_idea": hint["rule_idea"],
                    "closed_in_run": None}, commit=False)
        db.add_rule_noise(conn, run_id, [{"rule_id": r.rule_id, "status": r.status, "hits": r.hits, "noisy": r.noisy}
                                         for r in score.rule_noise], commit=False)
        conn.commit()
    except BaseException:
        conn.rollback()
        for p in written:
            p.unlink(missing_ok=True)
        raise
    return run_id


__all__ = ["RunFileError", "validate", "import_run", "events_dir"]
