import importlib.util
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from purplebench import library
from purplebench.telemetry import read_jsonl_gz

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_datasets.py"
_spec = importlib.util.spec_from_file_location("build_datasets", SCRIPT)
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)

T0 = datetime(2021, 1, 1, 12, 0, 0, tzinfo=UTC)


def ev(sec, host="h1", eid=1, image="C:\\Windows\\System32\\cmd.exe", cmd="", parent="", rid=None, channel="Microsoft-Windows-Sysmon/Operational"):
    t = T0 + timedelta(seconds=sec)
    return {
        "ts": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "channel": channel, "event_id": eid, "host": host,
        "record_id": rid if rid is not None else int(sec * 10),
        "fields": {"Image": image, "CommandLine": cmd, "ParentImage": parent},
    }


def stream(extra=()):
    base = [ev(s, eid=10) for s in range(0, 1000, 5)]  # noise on h1
    base += [ev(s, host="h2", eid=10) for s in range(0, 1000, 5)]  # noise on another host
    return sorted(base + list(extra), key=B.event_sort_key)


def test_window_is_30s_before_first_to_120s_after_last_anchor_on_one_host():
    events = stream([ev(400, cmd="vssadmin delete shadows"), ev(410, cmd="vssadmin delete shadows /all")])
    kept, w = B.derive_window(events, r"vssadmin\s+delete")
    assert w["method"] == "process-creation-anchor"
    assert w["host"] == "h1"
    times = [B.parse_ts(e["ts"]) for e in kept]
    assert min(times) >= T0 + timedelta(seconds=370)
    assert max(times) <= T0 + timedelta(seconds=530)
    assert min(times) <= T0 + timedelta(seconds=375)  # context before the anchor is kept
    assert max(times) >= T0 + timedelta(seconds=525)  # and after
    assert {e["host"] for e in kept} == {"h1"}
    assert w["anchor_events"] == 2 and w["clusters_found"] == 1
    # all event ids / channels in the window are kept, not just the matching ones
    assert {e["event_id"] for e in kept} == {1, 10}


def test_windows_start_and_end_dates_are_recorded():
    kept, w = B.derive_window(stream([ev(400, cmd="x-anchor")]), "x-anchor")
    assert w["start"] == "2021-01-01T12:06:10.000000Z" and w["end"] == "2021-01-01T12:08:40.000000Z"
    assert w["anchor_first"] == w["anchor_last"] == "2021-01-01T12:06:40.000000Z"


def test_first_cluster_is_chosen_and_others_counted():
    events = stream([ev(100, cmd="anchorcmd"), ev(700, cmd="anchorcmd")])
    kept, w = B.derive_window(events, "anchorcmd")
    assert w["clusters_found"] == 2 and w["anchor_first"].startswith("2021-01-01T12:01:40")
    assert any("2 anchor clusters" in f for f in w["flags"])
    kept2, w2 = B.derive_window(events, "anchorcmd", cluster=1)
    assert w2["anchor_first"].startswith("2021-01-01T12:11:40")


def test_anchor_matches_process_creation_events_only():
    events = stream([ev(100, eid=11, cmd="anchorcmd"), ev(200, eid=4688, cmd="anchorcmd")])
    events[0]["fields"]["NewProcessName"] = "x"
    _, w = B.derive_window(events, "anchorcmd")
    assert w["method"] == "process-creation-anchor" and w["anchor_events"] == 1
    assert w["anchor_first"].startswith("2021-01-01T12:03:20")  # the 4688, not the file-create


def test_no_anchor_falls_back_to_flagged_file_head():
    events = stream()
    kept, w = B.derive_window(events, "nothing-matches", head_events=50)
    assert w["method"] == "whole-file-head" and len(kept) == 50 and w["anchor_events"] == 0
    assert any("no-anchor-event-found" in f for f in w["flags"])
    kept2, w2 = B.derive_window(events, None, head_events=10)
    assert w2["method"] == "whole-file-head"


def test_event_cap_shrinks_the_window_and_flags_it():
    dense = [ev(s / 10, eid=10, rid=100000 + s) for s in range(3000, 6000)]  # 10 events per second
    events = stream([ev(400, cmd="anchorcmd")] + dense)
    kept, w = B.derive_window(events, "anchorcmd", max_events=800)
    assert len(kept) <= 800 and w["truncated"] is True
    assert any("shrunk" in f for f in w["flags"])
    assert any("anchorcmd" in e["fields"]["CommandLine"] for e in kept)  # the anchor itself survives


def test_baseline_stops_before_the_first_harness_event_and_is_deduplicated():
    lead = [ev(s, image="C:\\Windows\\System32\\svchost.exe", cmd="svchost -k x", eid=1, rid=s) for s in range(0, 100, 10)]
    lead += [ev(s + 1, eid=10) for s in range(0, 100, 10)]
    harness = ev(200, parent="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd='"C:\\Windows\\system32\\cmd.exe" /c "whoami"')
    attack = ev(210, cmd="whoami")
    events = sorted(lead + [harness, attack], key=B.event_sort_key)
    got = B.baseline_lead_in(events)
    assert harness not in got and attack not in got
    assert all(B.parse_ts(e["ts"]) <= T0 + timedelta(seconds=170) for e in got)
    base, info = B.build_baseline({"d1": events, "d2": events})
    assert len(base) == info["unique_signatures"] == 2  # one process shape, one access shape; d2 adds nothing
    assert info["from_recordings"] == {"d1": 2}


def test_baseline_needs_a_harness_marker_to_trust_the_head():
    assert B.baseline_lead_in(stream()) == []


def test_baseline_is_thinned_deterministically():
    evs = [ev(s, image=f"C:\\p{s}.exe", cmd=f"p{s}", eid=1, rid=s) for s in range(0, 500)]
    evs.append(ev(900, parent="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd='"C:\\Windows\\system32\\cmd.exe" /c "x"'))
    a, _ = B.build_baseline({"d": evs}, max_events=100)
    b, _ = B.build_baseline({"d": evs}, max_events=100)
    assert len(a) == 100 and a == b


# ---- specification sanity and the committed data ----

def test_specs_are_consistent():
    ids = [s["attack_id"] for s in B.SPECS]
    assert len(ids) == len(set(ids))
    for s in B.SPECS:
        if s["anchor"]:
            re.compile(s["anchor"])
        assert (s["atomic"] is None) == (s["link"] == "recorded")
        assert s["link"] in {"named", "command-matched", "recorded"}
        assert s["basis"] in {"atomic command", "dataset description"}
    assert {s["attack_id"] for s in B.SPECS} == {t.attack_id for t in library.list_techniques()}


def test_committed_windows_really_contain_their_anchor_events():
    import json
    m = json.loads((library.DATA_DIR / "telemetry" / "manifest.json").read_text("utf-8"))
    specs = {s["attack_id"]: s for s in B.SPECS}
    for f in m["files"]:
        if f["kind"] != "test":
            continue
        w = f["window"]
        events = list(read_jsonl_gz(library.DATA_DIR / "telemetry" / f["path"]))
        assert {e["host"] for e in events} == {w["host"]}
        if w["method"] == "whole-file-head":
            assert f["link"] == "recorded" and any("no-anchor" in x for x in w["flags"])
            continue
        rx = re.compile(specs[f["technique"]]["anchor"], re.I)
        hits = [e for e in events if (t := B.process_text(e)) is not None and rx.search(t)]
        assert len(hits) >= w["anchor_events"] >= 1, f["path"]
        assert w["anchor_first"] in {e["ts"] for e in hits}
        first = B.parse_ts(w["anchor_first"])
        assert B.parse_ts(events[0]["ts"]) >= first - timedelta(seconds=B.PRE_S + 1)
        assert B.parse_ts(events[0]["ts"]) <= first  # some lead-in context is kept


def test_baseline_has_no_attack_commands():
    rxs = [re.compile(s["anchor"], re.I) for s in B.SPECS if s["anchor"]]
    base = list(read_jsonl_gz(library.DATA_DIR / "telemetry" / "baseline.jsonl.gz"))
    assert len(base) >= 1000
    for e in base:
        t = B.process_text(e)
        assert t is None or not any(rx.search(t) for rx in rxs)
        assert not B._HARNESS_RX.search(str(e["fields"]))


def test_refuses_sources_inside_the_repository(tmp_path):
    repo_inside = Path(__file__).resolve().parent
    with pytest.raises(SystemExit):
        B.main(["--sources", str(repo_inside), "--out", str(tmp_path)])
