"""Validation and import of lab run files written by ``lab/Invoke-PurpleBenchRun.ps1``.

A run file is untrusted input: it may come from a lab VM that the tests just attacked, and its event
fields contain attacker-controlled strings (command lines, file names). It is therefore checked for
size, JSON depth, schema, timestamps, string lengths and counts before anything is stored, and nothing
in it is executed or evaluated except by the Sigma evaluator (which only compares strings).

File format (``format = "purplebench-run"``, ``version = 2``)::

    {"format": "purplebench-run", "version": 2, "mode": "lab", "target": "LAB-WS01",
     "started_at": "2026-11-10T09:00:00Z", "campaign": "name" | {"name": "...", "techniques": [...]},
     "executions": [{"technique_id": "T1003.001", "test_guid": "<guid>|null",
                     "started_at": "...", "ended_at": "...",
                     "run_status": "ran|failed|prereqs_missing|skipped", "error": "...",
                     "collection_error": "...", "truncated": false, "dropped_oversize": 0,
                     "events_xml": ["<Event ...>...</Event>", ...]}]}

Events are shipped exactly as Windows renders them (``Event.ToXml()``) and normalised here by
``telemetry.parse_event_xml`` (defusedxml, DTDs refused), the one event normaliser of the project.

Import scores the run with the chosen rule set (default: the newest) using the same scorer as recorded
mode. Executions whose test did not run (failed, prerequisites missing, skipped) or whose event collection
failed are stored with status ``did_not_run`` and a reason, and are excluded from coverage like untested
ones: they are never scored "missed". Two differences from recorded mode are stored in the run notes: the
telemetry profile is built from the events of the run itself (what this lab actually collected), and there
is no benign baseline, so rule noise is not measured for lab runs.
"""

from __future__ import annotations

import gzip
import json
import re
import sqlite3
import unicodedata
from pathlib import Path
from typing import Any

from . import config, db, library, rulesets, scoring
from .coverage import GENERIC_HINT, load_gap_hints
from .sigma import EventIndex, TelemetryProfile, evaluate
from .telemetry import TelemetryError, normalize_ts, parse_event_xml, parse_ts

FORMAT = "purplebench-run"
VERSION = 2

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_EXECUTIONS = 500
MAX_EVENTS_PER_EXECUTION = 50_000
MAX_EVENTS_TOTAL = 200_000
MAX_EVENT_XML_CHARS = 512_000  # one event's XML as shipped by the runner
MAX_FIELDS_PER_EVENT = 200
MAX_FIELD_NAME = 128
MAX_FIELD_VALUE = 65_536  # a 1 MB command line is refused, not truncated: the evidence would be partial
MAX_SHORT = 256  # target, channel, host, campaign name, technique id
MAX_ERROR = 2000
MAX_DEPTH = 6  # run file > executions > execution > events_xml > string (+ margin)

RUN_STATUSES = ("ran", "failed", "prereqs_missing", "skipped")
_TOP_KEYS = {"format", "version", "mode", "target", "started_at", "campaign", "executions"}
_EXEC_KEYS = {"technique_id", "test_guid", "started_at", "ended_at", "run_status", "error", "collection_error",
              "truncated", "dropped_oversize", "events_xml"}

_TECH = re.compile(r"T[0-9]{4}(\.[0-9]{3})?", re.ASCII)
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", re.ASCII)
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.ASCII)


class RunFileError(ValueError):
    """The run file is not acceptable. The message says why and is safe to show to the user."""


class _Oversize(RunFileError):
    """One event is over a size limit: the event is skipped and counted, the file is still accepted."""


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
    """A short header string: no NUL or other control characters (it is echoed in the UI and reports)."""
    if not isinstance(value, str):
        raise RunFileError(f"{what} must be a string")
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise RunFileError(f"{what} contains a control character")
    if len(value) > limit:
        raise RunFileError(f"{what} is longer than {limit} characters")
    if not value and not allow_empty:
        raise RunFileError(f"{what} is empty")
    return value


def _message(value: Any, what: str) -> str:
    """Free text from the runner (error messages): control characters become spaces, length is capped."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise RunFileError(f"{what} must be a string")
    if len(value) > 10 * MAX_ERROR:
        raise RunFileError(f"{what} is longer than {10 * MAX_ERROR} characters")
    clean = "".join(" " if unicodedata.category(c) == "Cc" else c for c in value)
    return clean[:MAX_ERROR]


def _ts(value: Any, what: str) -> str:
    try:
        return normalize_ts(_str(value, what, 64))
    except TelemetryError as exc:
        raise RunFileError(f"{what}: {exc}") from exc


def _event(xml: Any, where: str) -> dict[str, Any]:
    """Normalise one event shipped as Windows Event XML (the only normaliser is telemetry.parse_event_xml)."""
    if not isinstance(xml, str):
        raise RunFileError(f"{where}: event is not a string of event XML")
    if len(xml) > MAX_EVENT_XML_CHARS:
        raise _Oversize(f"{where}: event XML is longer than {MAX_EVENT_XML_CHARS} characters")
    if "\x00" in xml:
        raise RunFileError(f"{where}: event contains a NUL byte")
    try:
        ev = parse_event_xml(xml)
    except TelemetryError as exc:
        raise RunFileError(f"{where}: {exc}") from exc
    if len(ev["fields"]) > MAX_FIELDS_PER_EVENT:
        raise _Oversize(f"{where}: more than {MAX_FIELDS_PER_EVENT} fields")
    for k, v in ev["fields"].items():
        if len(k) > MAX_FIELD_NAME:
            raise _Oversize(f"{where}: field name is longer than {MAX_FIELD_NAME} characters")
        if len(v) > MAX_FIELD_VALUE:
            raise _Oversize(f"{where}: field {k!r} is longer than {MAX_FIELD_VALUE} characters")
    for key in ("channel", "host"):
        if len(ev[key]) > MAX_SHORT:
            raise _Oversize(f"{where}: {key} is longer than {MAX_SHORT} characters")
    if not 0 <= ev["event_id"] <= 65535 or not 0 <= ev["record_id"] < 2**63:
        raise RunFileError(f"{where}: event id or record id out of range")
    return ev


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
    if raw.startswith(b"\xef\xbb\xbf"):  # tolerate a BOM
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
    ver = data.get("version")
    if data.get("format") != FORMAT or type(ver) is not int or ver != VERSION:
        raise RunFileError(f"not a {FORMAT} version {VERSION} file")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise RunFileError(f"unknown top-level key(s): {', '.join(sorted(map(str, unknown)))[:100]}")
    if data.get("mode") != "lab":
        raise RunFileError('run file mode must be "lab"')
    target = _str(data.get("target"), "target")
    if not _HOST.fullmatch(target):
        raise RunFileError("target must be a host name only (letters, digits, dot, dash, underscore)")
    started = _ts(data.get("started_at"), "started_at")

    camp = data.get("campaign")
    if isinstance(camp, dict):
        camp_name = _str(camp.get("name"), "campaign name")
        camp_techs = camp.get("techniques", [])
        if not isinstance(camp_techs, list) or len(camp_techs) > MAX_EXECUTIONS:
            raise RunFileError("campaign techniques must be a short list")
        for t in camp_techs:
            if not isinstance(t, str) or not _TECH.fullmatch(t):
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
        extra = set(row) - _EXEC_KEYS
        if extra:
            raise RunFileError(f"{where}: unknown key(s): {', '.join(sorted(map(str, extra)))[:100]}")
        tech = _str(row.get("technique_id"), f"{where}: technique_id")
        if not _TECH.fullmatch(tech):
            raise RunFileError(f"{where}: technique_id is not an ATT&CK id")
        guid = row.get("test_guid")
        if guid is not None and not (isinstance(guid, str) and _GUID.fullmatch(guid)):
            raise RunFileError(f"{where}: test_guid is not a GUID")
        t0, t1 = _ts(row.get("started_at"), f"{where}: started_at"), _ts(row.get("ended_at"), f"{where}: ended_at")
        if parse_ts(t1) < parse_ts(t0):
            raise RunFileError(f"{where}: ended_at is before started_at")
        status = row.get("run_status")
        if status not in RUN_STATUSES:
            raise RunFileError(f"{where}: run_status must be one of {', '.join(RUN_STATUSES)}")
        truncated = row.get("truncated", False)
        if not isinstance(truncated, bool):
            raise RunFileError(f"{where}: truncated must be true or false")
        evs = row.get("events_xml")
        if not isinstance(evs, list):
            raise RunFileError(f"{where}: events_xml must be a list")
        if len(evs) > MAX_EVENTS_PER_EXECUTION:
            raise RunFileError(f"{where}: more than {MAX_EVENTS_PER_EXECUTION} events")
        total += len(evs)
        if total > MAX_EVENTS_TOTAL:
            raise RunFileError(f"more than {MAX_EVENTS_TOTAL} events in the run")
        dropped = row.get("dropped_oversize", 0)
        if type(dropped) is not int or not 0 <= dropped <= 10_000_000:
            raise RunFileError(f"{where}: dropped_oversize must be a non-negative integer")
        events, skipped = [], 0
        for j, e in enumerate(evs):
            try:
                events.append(_event(e, f"{where}, event {j + 1}"))
            except _Oversize:
                skipped += 1  # an over-limit event is left out and counted; the rest of the file is kept
        executions.append({
            "technique_id": tech, "test_guid": guid.lower() if guid else None, "started_at": t0, "ended_at": t1,
            "run_status": status, "error": _message(row.get("error"), f"{where}: error"),
            "collection_error": _message(row.get("collection_error"), f"{where}: collection_error"),
            "truncated": truncated, "dropped_oversize": dropped, "skipped_oversize": skipped,
            "events": events})
    return {"target": target, "started_at": started, "campaign": {"name": camp_name, "techniques": camp_techs},
            "executions": executions}


def _record_refs(rule, index: EventIndex, profile: TelemetryProfile, anchor: str, skew: float,
                 window: float) -> list[list[Any]]:
    """The matching events inside the window as [channel, record_id] pairs (record ids repeat across logs)."""
    res = evaluate(rule, index, profile)
    return [[ref.channel, ref.record_id] for ref in res.matches
            if -skew <= scoring._seconds(ref.ts, anchor) <= window]


def events_dir() -> Path:
    """Where stored lab events live (next to the database); the API pages them from here."""
    return config.db_path().parent / "lab_events"


def _did_not_run_reason(ex: dict[str, Any]) -> str | None:
    if ex["run_status"] != "ran":
        label = ex["run_status"].replace("_", " ")
        return f"the test did not run ({label})" + (f": {ex['error']}" if ex["error"] else "")
    if ex["collection_error"]:
        return f"event collection failed, so the test could not be scored: {ex['collection_error']}"
    if not ex["events"] and ex["skipped_oversize"] + ex["dropped_oversize"] > 0:
        return "all collected events exceeded size limits"
    return None


def import_run(conn: sqlite3.Connection, raw: bytes | str | Path, *, ruleset_id: int | None = None,
               noise_threshold: int = scoring.DEFAULT_NOISE_THRESHOLD) -> int:
    """Validate ``raw`` and store it as a lab run scored with the rule set. Returns the run id.

    Nothing is stored if validation or scoring fails. The connection must have no open transaction (the
    import does not commit anything the caller has pending).
    """
    run = validate(raw)
    if conn.in_transaction:
        raise RuntimeError("import_run needs a connection without an open transaction")
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

    execs, profile_events = [], []
    for ex in run["executions"]:
        t = lib.get(ex["technique_id"])
        dur = (parse_ts(ex["ended_at"]) - parse_ts(ex["started_at"])).total_seconds()
        dnr = _did_not_run_reason(ex)
        execs.append(scoring.Execution(
            technique=ex["technique_id"], name=t.name if t else ex["technique_id"], tactics=t.tactics if t else (),
            events=ex["events"], anchor_ts=ex["started_at"],
            window_seconds=scoring.DEFAULT_WINDOW_SECONDS + max(0.0, dur), did_not_run_reason=dnr,
            atomic_test=t.atomic.name if t and t.atomic else None))
        if dnr is None:
            profile_events.extend(ex["events"])
    profile = TelemetryProfile.from_events(profile_events)
    score = scoring.score_run(rules, execs, [], profile, noise_threshold)
    hints = load_gap_hints()

    campaign = next((c for c in db.list_campaigns(conn) if c["name"] == run["campaign"]["name"]), None)
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
                 "WinRM harness activity (for example wsmprovhost.exe) can appear in the collected windows. "
                 f"Telemetry profile: the events of this run. Scored with rule set {rs_row['version']}.")
        run_id = db.add_run(conn, cid, rs_row["id"], "lab", source, run["started_at"], notes, commit=False)
        by_rule = {r.id: r for r in rules}
        out_dir = events_dir()
        for n, (ex, es) in enumerate(zip(run["executions"], score.executions, strict=True), start=1):
            index = EventIndex(ex["events"])
            window = execs[n - 1].window_seconds
            hits = []
            for h in es.hits:
                refs = _record_refs(by_rule[h.rule_id], index, profile, ex["started_at"], score.skew_seconds, window)
                hits.append({"rule_id": h.rule_id, "first_ts": h.first_ts, "count": h.events, "relation": h.relation,
                             "noisy": h.noisy, "noise_hits": h.noise_hits, "record_ids": refs})
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"run{run_id}_{n}.jsonl.gz"
            written.append(path)
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                for ev in ex["events"]:
                    fh.write(json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
            reason = es.reason
            if es.status != scoring.DID_NOT_RUN:
                if ex["truncated"]:
                    reason += " Event collection hit its cap for this test, so later events were not collected."
                left_out = ex["dropped_oversize"] + ex["skipped_oversize"]
                if left_out:
                    reason += (f" {left_out} event(s) over the size limit were left out "
                               f"({ex['dropped_oversize']} by the runner, {ex['skipped_oversize']} on import), "
                               "so the events may be incomplete.")
            db.add_execution(conn, run_id, {
                "technique_id": ex["technique_id"], "test_guid": ex["test_guid"], "started_at": ex["started_at"],
                "ended_at": ex["ended_at"], "status": es.status,
                "ttd_ms": None if es.ttd_seconds is None else round(es.ttd_seconds * 1000),
                "events_ref": f"lab_events/run{run_id}_{n}.jsonl.gz", "reason": reason, "hits": hits},
                commit=False)
            if es.status in ("missed", "telemetry_gap", "partial"):
                hint = hints.get(es.technique) or GENERIC_HINT
                db.add_gap(conn, run_id, {
                    "technique_id": es.technique, "kind": es.status, "notes": reason.rstrip(".") + ".",
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
