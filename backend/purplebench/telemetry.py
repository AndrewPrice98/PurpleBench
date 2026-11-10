"""Recorded telemetry loading and normalisation (Sysmon and Security events).

Normalised event shape (field names inside ``fields`` are the original EventData names)::

    {"ts": "2020-11-30T13:42:16.668830Z", "channel": "Microsoft-Windows-Sysmon/Operational",
     "event_id": 10, "host": "win-dc-11.attackrange.local", "record_id": 34, "fields": {...}}

Windows Event XML is parsed with defusedxml (entities, DTDs and external references are refused).
Nothing here executes or evaluates event content.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as SafeET

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

MAX_EVENT_BYTES = 2_000_000  # one event larger than this is rejected, not parsed

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"


class TelemetryError(ValueError):
    """Raised for input that is not a well-formed event."""


def normalize_ts(value: str) -> str:
    """Return an ISO-8601 UTC timestamp with microsecond precision and a ``Z`` suffix."""
    v = value.strip()
    if not v:
        raise TelemetryError("empty timestamp")
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    # Windows writes 7 fractional digits; datetime accepts at most 6.
    if "." in v:
        head, rest = v.split(".", 1)
        i = 0
        while i < len(rest) and rest[i].isdigit():
            i += 1
        v = f"{head}.{rest[:i][:6].ljust(6, '0')}{rest[i:]}"
    try:
        dt = datetime.fromisoformat(v.replace(" ", "T", 1))
    except ValueError as exc:
        raise TelemetryError(f"bad timestamp {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: str) -> datetime:
    """Parse a normalised timestamp."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_event_xml(xml: str) -> dict[str, Any]:
    """Normalise one Windows Event XML ``<Event>`` document."""
    if len(xml) > MAX_EVENT_BYTES:
        raise TelemetryError("event too large")
    try:
        root = SafeET.fromstring(xml)
    except Exception as exc:  # defusedxml raises its own subclasses as well as ParseError
        raise TelemetryError(f"unparseable event: {type(exc).__name__}") from exc
    system = root.find(f"{_NS}System")
    if system is None:
        raise TelemetryError("event has no System element")

    def text(tag: str) -> str:
        el = system.find(f"{_NS}{tag}")
        return (el.text or "").strip() if el is not None else ""

    created = system.find(f"{_NS}TimeCreated")
    if created is None or not created.get("SystemTime"):
        raise TelemetryError("event has no TimeCreated")
    fields: dict[str, str] = {}
    data_parent = root.find(f"{_NS}EventData")
    if data_parent is None:
        data_parent = root.find(f"{_NS}UserData")
    if data_parent is not None:
        unnamed = 0
        for el in data_parent.iter():
            if el.tag == f"{_NS}Data":
                name = el.get("Name")
                if not name:
                    unnamed += 1
                    name = f"Data{unnamed}"
                fields[name] = el.text or ""
            elif el is not data_parent and len(el) == 0 and el.text is not None:
                fields[el.tag.removeprefix(_NS)] = el.text
    return {
        "ts": normalize_ts(created.get("SystemTime", "")),
        "channel": text("Channel"),
        "event_id": _int(text("EventID")),
        "host": text("Computer"),
        "record_id": _int(text("EventRecordID")),
        "fields": fields,
    }


def parse_event_json(obj: dict[str, Any]) -> dict[str, Any]:
    """Normalise one JSON event.

    Accepts an already-normalised event, or the flat shape used by common export tools
    (``EventID``, ``Channel``, ``Hostname``/``Computer``, ``@timestamp``/``TimeCreated`` and EventData
    keys at top level or under ``EventData``/``event_data``).
    """
    if not isinstance(obj, dict):
        raise TelemetryError("event is not an object")
    if {"ts", "event_id", "fields"} <= obj.keys():
        fields = obj["fields"]
        if not isinstance(fields, dict):
            raise TelemetryError("fields is not an object")
        return {
            "ts": normalize_ts(str(obj["ts"])),
            "channel": str(obj.get("channel", "")),
            "event_id": _int(obj["event_id"]),
            "host": str(obj.get("host", "")),
            "record_id": _int(obj.get("record_id", 0)),
            "fields": {str(k): "" if v is None else str(v) for k, v in fields.items()},
        }
    ts = obj.get("@timestamp") or obj.get("TimeCreated") or obj.get("EventTime") or obj.get("UtcTime")
    if not ts:
        raise TelemetryError("event has no timestamp")
    meta = {"EventID", "Channel", "Hostname", "Computer", "@timestamp", "TimeCreated", "EventTime",
            "EventRecordID", "RecordNumber", "EventData", "event_data"}
    nested = obj.get("EventData") or obj.get("event_data")
    src = nested if isinstance(nested, dict) else {k: v for k, v in obj.items() if k not in meta}
    return {
        "ts": normalize_ts(str(ts)),
        "channel": str(obj.get("Channel", "")),
        "event_id": _int(obj.get("EventID")),
        "host": str(obj.get("Hostname") or obj.get("Computer") or ""),
        "record_id": _int(obj.get("EventRecordID") or obj.get("RecordNumber")),
        "fields": {str(k): "" if v is None else str(v) for k, v in src.items()},
    }


def iter_xml_events(lines: Iterable[str]) -> Iterator[str]:
    """Group text lines into ``<Event ...>...</Event>`` documents.

    Splunk's exports hold one event per line, but a command line containing a newline spreads one
    event over several lines, so events are delimited by tags, not by line.
    """
    buf: list[str] = []
    size = 0
    for line in lines:
        stripped = line.strip()
        if not buf and not stripped.startswith("<Event"):
            continue
        buf.append(line)
        size += len(line)
        if size > MAX_EVENT_BYTES:
            buf, size = [], 0
            continue
        if stripped.endswith("</Event>"):
            yield "".join(buf).strip()
            buf, size = [], 0


def read_xml_log(path: Path | str) -> Iterator[dict[str, Any]]:
    """Yield normalised events from a Windows Event XML file; malformed events are skipped."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        for doc in iter_xml_events(fh):
            try:
                yield parse_event_xml(doc)
            except TelemetryError:
                continue


def event_sort_key(ev: dict[str, Any]) -> tuple[str, str, int]:
    return ev["ts"], ev["host"], ev["record_id"]


def write_jsonl_gz(path: Path | str, events: Iterable[dict[str, Any]]) -> None:
    """Write events as deterministic gzip JSON lines (fixed mtime, sorted keys)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
        for ev in events:
            gz.write(json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")


def read_jsonl_gz(path: Path | str) -> Iterator[dict[str, Any]]:
    """Yield normalised events from a committed ``.jsonl.gz`` file."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
