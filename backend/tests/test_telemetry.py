import gzip
import json

import pytest

from purplebench import telemetry as T

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SYSMON_1 = (
    f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
    "<TimeCreated SystemTime='2020-11-30T13:44:25.0150000Z'/><EventRecordID>77</EventRecordID>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>win-dc-11.attackrange.local</Computer>"
    "</System><EventData><Data Name='RuleName'>-</Data><Data Name='Image'>C:\\Windows\\System32\\wbem\\WMIC.exe</Data>"
    "<Data Name='CommandLine'>wmic  process call create notepad.exe</Data><Data Name='Empty'></Data></EventData></Event>"
)

SECURITY_4688 = (
    f"<Event xmlns='{NS}'><System><EventID>4688</EventID><TimeCreated SystemTime='2021-01-01T00:00:00Z'/>"
    "<EventRecordID>5</EventRecordID><Channel>Security</Channel><Computer>WS01</Computer></System>"
    "<EventData><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data><Data Name='CommandLine'>cmd /c dir</Data>"
    "</EventData></Event>"
)


def test_parse_sysmon_event_keeps_original_field_names():
    ev = T.parse_event_xml(SYSMON_1)
    assert ev["ts"] == "2020-11-30T13:44:25.015000Z"
    assert ev["channel"] == T.SYSMON
    assert ev["event_id"] == 1
    assert ev["host"] == "win-dc-11.attackrange.local"
    assert ev["record_id"] == 77
    assert ev["fields"]["Image"].endswith("WMIC.exe")
    assert ev["fields"]["CommandLine"] == "wmic  process call create notepad.exe"
    assert ev["fields"]["Empty"] == ""


def test_parse_security_event():
    ev = T.parse_event_xml(SECURITY_4688)
    assert (ev["channel"], ev["event_id"], ev["host"]) == (T.SECURITY, 4688, "WS01")
    assert ev["fields"]["NewProcessName"].endswith("cmd.exe")
    assert ev["ts"] == "2021-01-01T00:00:00.000000Z"


@pytest.mark.parametrize(
    "xml",
    [
        # entity expansion (billion laughs style) must be refused, not expanded
        "<!DOCTYPE e [<!ENTITY a 'aaaa'><!ENTITY b '&a;&a;&a;&a;'>]>"
        f"<Event xmlns='{NS}'><System><EventID>1</EventID><TimeCreated SystemTime='2020-01-01T00:00:00Z'/></System>"
        "<EventData><Data Name='x'>&b;</Data></EventData></Event>",
        # external entity
        "<!DOCTYPE e [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>"
        f"<Event xmlns='{NS}'><System><EventID>1</EventID><TimeCreated SystemTime='2020-01-01T00:00:00Z'/></System>"
        "<EventData><Data Name='x'>&x;</Data></EventData></Event>",
        "<Event",  # truncated
        f"<Event xmlns='{NS}'></Event>",  # no System
        f"<Event xmlns='{NS}'><System><EventID>1</EventID></System></Event>",  # no TimeCreated
    ],
)
def test_hostile_or_malformed_xml_is_rejected(xml):
    with pytest.raises(T.TelemetryError):
        T.parse_event_xml(xml)


def test_oversized_event_is_rejected():
    with pytest.raises(T.TelemetryError):
        T.parse_event_xml("<Event>" + "a" * (T.MAX_EVENT_BYTES + 1) + "</Event>")


def test_events_split_on_tags_not_lines():
    multi = SYSMON_1.replace("wmic  process", "wmic\n  process")  # a command line with a newline
    cut = multi.index("wmic\n") + 5
    lines = ["junk before\n", multi[:cut], multi[cut:] + "\n", SECURITY_4688 + "\n"]
    docs = list(T.iter_xml_events(lines))
    assert len(docs) == 2
    first = T.parse_event_xml(docs[0])
    assert "\n" in first["fields"]["CommandLine"]
    assert T.parse_event_xml(docs[1])["event_id"] == 4688


def test_read_xml_log_skips_bad_events(tmp_path):
    p = tmp_path / "x.log"
    p.write_text(SYSMON_1 + "\n<Event xmlns='x'>broken</Event>\n" + SECURITY_4688 + "\n", encoding="utf-8")
    evs = list(T.read_xml_log(p))
    assert [e["event_id"] for e in evs] == [1, 4688]


def test_bare_dtd_is_refused():
    # defusedxml's defaults accept a DOCTYPE without entities; forbid_dtd=True refuses any DTD.
    with pytest.raises(T.TelemetryError, match="DTDForbidden"):
        T.parse_event_xml("<!DOCTYPE Event>" + SYSMON_1)


def test_read_xml_log_counts_skipped_events_by_reason(tmp_path):
    p = tmp_path / "x.log"
    big = "<Event>" + "a\n" * (T.MAX_EVENT_BYTES // 2 + 10) + "</Event>\n"
    p.write_text("stray text\n" + SYSMON_1 + "\n<Event xmlns='x'>broken</Event>\n" + big
                 + "<!DOCTYPE Event>" + SECURITY_4688 + "\n" + SECURITY_4688 + "\n" + "<Event xmlns='x'><System>\n",
                 encoding="utf-8")
    stats = T.ReadStats()
    evs = list(T.read_xml_log(p, stats))
    assert [e["event_id"] for e in evs] == [1, 4688]
    assert stats.parsed == 2
    # A line starting with a DOCTYPE is not an <Event> start, so it never reaches the parser.
    assert stats.skipped == {
        "text outside an event": 2,
        "event has no System element": 1,
        "event too large": 1,
        "unterminated event at end of input": 1,
    }
    assert stats.as_dict()["skipped"] == 5


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2020-11-30T13:42:16.668830600Z", "2020-11-30T13:42:16.668830Z"),
        ("2020-11-30 13:42:16.659", "2020-11-30T13:42:16.659000Z"),
        ("2021-01-01T02:00:00+02:00", "2021-01-01T00:00:00.000000Z"),
        ("2021-01-01T00:00:00Z", "2021-01-01T00:00:00.000000Z"),
    ],
)
def test_normalize_ts(raw, expected):
    assert T.normalize_ts(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", "yesterday", "2020-13-45T00:00:00Z"])
def test_normalize_ts_rejects_garbage(bad):
    with pytest.raises(T.TelemetryError):
        T.normalize_ts(bad)


def test_parse_event_json_flat_and_normalised():
    flat = {"EventID": 1, "Channel": T.SYSMON, "Hostname": "h", "@timestamp": "2021-02-02T00:00:00Z",
            "EventRecordID": "9", "Image": "C:\\x.exe", "CommandLine": "x"}
    ev = T.parse_event_json(flat)
    assert ev == {"ts": "2021-02-02T00:00:00.000000Z", "channel": T.SYSMON, "event_id": 1, "host": "h",
                  "record_id": 9, "fields": {"Image": "C:\\x.exe", "CommandLine": "x"}}
    assert T.parse_event_json(ev) == ev  # idempotent on already normalised events
    nested = {"EventID": 4688, "Channel": "Security", "Computer": "c", "TimeCreated": "2021-02-02T00:00:00Z",
              "EventData": {"NewProcessName": "a", "Odd": None}}
    assert T.parse_event_json(nested)["fields"] == {"NewProcessName": "a", "Odd": ""}


def test_parse_event_json_rejects_bad_shapes():
    for bad in ([], "x", {"EventID": 1}, {"ts": "2020-01-01T00:00:00Z", "event_id": 1, "fields": []}):
        with pytest.raises(T.TelemetryError):
            T.parse_event_json(bad)


def test_jsonl_gz_round_trip_is_deterministic(tmp_path):
    evs = [T.parse_event_xml(SYSMON_1), T.parse_event_xml(SECURITY_4688)]
    a, b = tmp_path / "a.jsonl.gz", tmp_path / "b.jsonl.gz"
    T.write_jsonl_gz(a, evs)
    T.write_jsonl_gz(b, evs)
    assert a.read_bytes() == b.read_bytes()
    assert list(T.read_jsonl_gz(a)) == evs
    with gzip.open(a, "rt", encoding="utf-8") as fh:
        assert all(json.loads(line) for line in fh)
