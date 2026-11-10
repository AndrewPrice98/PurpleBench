"""Build the committed technique library and trimmed recorded telemetry.

    python -I scripts/build_datasets.py --sources <dir> [--out backend/data] [--check]

``--sources`` is a scratch directory OUTSIDE the repository holding the untrusted downloads
(``scripts/fetch_sources.py`` fills it):

    logs/<dataset_id>.log        Splunk attack_data Windows Event XML (Sysmon)
    atomics/<attack_id>.yaml     Atomic Red Team test definitions
    yml/<dataset_id>.yml         Splunk dataset manifests
    licenses/*.txt               upstream licence texts

Everything read from there is data. XML goes through defusedxml (``purplebench.telemetry``), YAML
through ``yaml.safe_load``, and nothing is executed or imported.

What it writes under ``--out``:

    library.json                          technique library (ATT&CK v20 ids, Atomic test metadata)
    telemetry/<technique>/<test>.jsonl.gz trimmed, normalised events of one test window
    telemetry/baseline.jsonl.gz           benign lead-in events (see ``build_baseline``)
    telemetry/manifest.json               hashes, counts, windows, provenance
    telemetry/LICENSE-Apache-2.0.txt, NOTICE.md, data/ATOMIC_RED_TEAM_LICENSE.txt

``--check`` rebuilds into a temporary directory and fails if the result differs from the committed
files (compared on the uncompressed content hash, which does not depend on the zlib build).

Window derivation (the Splunk logs carry no explicit execution windows): find the process-creation
events (Sysmon EID 1, Security 4688) whose image and command line match the Atomic test's command (or
the dataset description for runs that are not a named Atomic test), group them into clusters on one
host (gap <= CLUSTER_GAP_S), take the chosen cluster, and keep every event of that host from
PRE_S seconds before the first anchor to POST_S seconds after the last one, from all channels.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import shutil
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

import yaml  # noqa: E402

from purplebench.telemetry import (  # noqa: E402
    event_sort_key,
    parse_ts,
    ReadStats,
    read_xml_log,
    write_jsonl_gz,
)

PRE_S = 30
POST_S = 120
CLUSTER_GAP_S = 120
MAX_EVENTS = 15000
HEAD_EVENTS = 1500  # events kept when no anchor is found (whole-file-head)
BASELINE_MAX = 3000
BASELINE_MARGIN_S = 30  # lead-in stops this long before the first harness event

SPLUNK_REPO = "https://github.com/splunk/attack_data"
SPLUNK_COMMIT = "c8af10d015d392fca97f9eb65181e9f06bc18e40"
ATOMIC_REPO = "https://github.com/redcanaryco/atomic-red-team"
ATOMIC_COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
MEDIA = f"https://media.githubusercontent.com/media/splunk/attack_data/{SPLUNK_COMMIT}/"

ATTACK_VERSION = "20"
ATTACK_DATA_RELEASE = "20.1"

RECORDED = "recorded technique execution"
ATOMIC_KIND = "atomic test"


def S(attack_id, dataset_id, name, tactics, atomic, anchor, *, link, basis, folder="atomic_red_team",
      cluster=0, note=None, guid=None):
    return {
        "attack_id": attack_id, "dataset_id": dataset_id, "name": name, "tactics": tactics,
        "atomic": atomic, "anchor": anchor, "link": link, "basis": basis, "folder": folder,
        "cluster": cluster, "note": note, "guid": guid,
    }


# link: "named"           the Splunk dataset description names this Atomic test, and the events show it
#       "command-matched" the description does not name it, but the recorded command line equals the
#                         test's command (default arguments substituted)
#       "recorded"        not tied to a named Atomic test: kept with atomic = None
# basis: what the anchor regex expresses ("atomic command" or "dataset description").
SPECS: list[dict[str, Any]] = [
    S("T1059.001", "T1059.001", "PowerShell", ["execution"], "Run Bloodhound from Memory using Download Cradle",
      r"Remote download of SharpHound\.ps1 into memory", link="command-matched", basis="atomic command",
      note="Task 1 listed 'Powershell Invoke-DownloadCradle' (a manual test with no command); the recording "
           "contains the download-cradle test above instead, matched by its command text."),
    S("T1047", "T1047", "Windows Management Instrumentation", ["execution"], "WMI Execute Local Process",
      r"wmic\s+process call create notepad\.exe", link="named", basis="atomic command"),
    S("T1569.002", "T1569.002", "Service Execution", ["execution"], "Use PsExec to execute a command on a remote host",
      r"PsExec\.exe\s+\\\\localhost\s+-u\s+DOMAIN\\Administrator", link="command-matched", basis="atomic command"),
    S("T1053.005", "T1053.005", "Scheduled Task", ["execution", "persistence", "privilege-escalation"],
      "Scheduled task Local", r"SCHTASKS\s+/Create\s+/SC\s+ONCE\s+/TN\s+spawn", link="named", basis="atomic command"),
    S("T1547.001", "T1547.001", "Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"],
      "Reg Key Run", r'REG\s+ADD\s+"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"\s+/V\s+"Atomic Red Team"',
      link="named", basis="atomic command"),
    S("T1543.003", "T1543.003", "Windows Service", ["persistence", "privilege-escalation"], "Service Installation CMD",
      r"sc\.exe\s+create\s+AtomicTestService_CMD", link="named", basis="atomic command"),
    S("T1136.001", "T1136.001", "Local Account", ["persistence"], "Create a new user in PowerShell",
      r"New-LocalUser\s+-Name\s+\W*T1136\.001_PowerShell", link="named", basis="atomic command"),
    S("T1548.002", "T1548.002", "Bypass User Account Control", ["privilege-escalation"],
      "Bypass UAC using Event Viewer (cmd)", r"reg\.exe\s+add\s+hkcu\\software\\classes\\mscfile\\shell\\open\\command",
      link="command-matched", basis="atomic command"),
    S("T1685", "T1562.001", "Disable or Modify Tools", ["defense-impairment"],
      "Tamper with Windows Defender Command Prompt", r"\bsc\s+(stop|config)\s+windefend", link="named",
      basis="atomic command"),
    S("T1685.005", "T1070.001", "Clear Windows Event Logs", ["defense-impairment"], "Clear Logs",
      r"wevtutil\s+cl\s+System", link="named", basis="atomic command"),
    S("T1218.011", "T1218.011", "Rundll32", ["stealth"], "Rundll32 execute VBscript command",
      r"rundll32\s+vbscript:.*Run\(\"calc\.exe\"\)", link="named", basis="atomic command"),
    S("T1218.005", "T1218.005", "Mshta", ["stealth"], "Mshta executes VBScript to execute malicious command",
      r"mshta\.exe\"?\s+\"vbscript:", link="named", basis="atomic command",
      note="The dataset was generated with AtomicTestHarnesses; the recorded mshta command line is the "
           "harness variant of the VBScript test, not the Atomic Red Team command string verbatim."),
    S("T1218.010", "T1218.010", "Regsvr32", ["stealth"], "Regsvr32 local COM scriptlet execution",
      r"regsvr32\.exe\s+/s\s+/u\s+/i:C:\\AtomicRedTeam\\atomics\\T1218\.010\\src\\RegSvr32\.sct", link="named",
      basis="atomic command"),
    S("T1027", "T1027", "Obfuscated Files or Information", ["stealth"], "Execute base64-encoded PowerShell",
      r"-EncodedCommand\s+VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkA", link="named", basis="atomic command"),
    S("T1003.001", "T1003.001", "LSASS Memory", ["credential-access"], "Dump LSASS.exe Memory using ProcDump",
      r"procdump\.exe\s+-accepteula\s+-ma\s+lsass\.exe", link="named", basis="atomic command"),
    S("T1003.002", "T1003.002", "Security Account Manager", ["credential-access"],
      "Registry dump of SAM, creds, and secrets", r"reg\s+save\s+HKLM\\sam", link="named", basis="atomic command"),
    S("T1558.003", "T1558.003", "Kerberoasting", ["credential-access"], None, None, link="recorded",
      basis="dataset description",
      note="Dataset description: manual kerberoasting with mimikatz. The shipped Sysmon file (truncated upstream "
           "at 10,000 events) contains no kerberoasting activity, so no anchor exists and the file head is used."),
    S("T1082", "T1082", "System Information Discovery", ["discovery"], "System Information Discovery",
      r"systeminfo", link="command-matched", basis="atomic command",
      guid="66703791-c902-4560-8770-42b8a91f7667"),
    S("T1033", "T1033", "System Owner/User Discovery", ["discovery"], "System Owner/User Discovery",
      r"cmd\.exe\s+/C\s+whoami", link="named", basis="atomic command"),
    S("T1018", "T1018", "Remote System Discovery", ["discovery"], "Remote System Discovery - net",
      r"\bnet\s+view\b", link="named", basis="atomic command"),
    S("T1069.001", "T1069.001", "Local Groups", ["discovery"],
      "Basic Permission Groups Discovery Windows (Local)", r"\bnet1?\s+localgroup\b", link="command-matched",
      basis="atomic command"),
    S("T1021.002", "T1021.002", "SMB/Windows Admin Shares", ["lateral-movement"], "Copy and Execute File with PsExec",
      r"PsExec\.exe\s+\\\\localhost\s+-accepteula\s+-c\s", link="named", basis="atomic command",
      note="Task 1 listed 'Map admin share'; the shipped Sysmon file holds only 10 events and its description "
           "names that test, but it contains no 'net use' command. It does contain 'Copy and Execute File with "
           "PsExec' (also named in the description), so that test is used."),
    S("T1550.002", "T1550.002", "Pass the Hash", ["lateral-movement"], None, r"mimikatz\.exe", link="recorded",
      basis="dataset description",
      note="Dataset description: manual pass the hash with mimikatz and psexec. The anchor is the mimikatz.exe "
           "launch; the command line carries no sekurlsa::pth argument (mimikatz was run interactively)."),
    S("T1560.001", "T1560.001", "Archive via Utility", ["collection"], None, r"7z\.exe\s+a\s+-v500m",
      link="recorded", basis="dataset description", folder="archive_utility",
      note="Dataset description: Cobalt Strike spawning 7z.exe to archive files; not an Atomic Red Team run."),
    S("T1105", "T1105", "Ingress Tool Transfer", ["command-and-control"], "certutil download (urlcache)",
      r"certutil\s+-urlcache\s+-split\s+-f\s+\S+LICENSE\.txt\s+Atomic-license\.txt", link="command-matched",
      basis="atomic command"),
    S("T1490", "T1490", "Inhibit System Recovery", ["impact"], "Windows - Delete Volume Shadow Copies",
      r"vssadmin\.exe\s+delete\s+shadows\s+/all\s+/quiet", link="named", basis="atomic command"),
]

# Harness markers: the first event that shows the Atomic harness (or an attack tool) running ends the
# benign lead-in used for the baseline.
_HARNESS_RX = re.compile(r"atomicredteam|invoke-atomic|\\atomics\\|mimikatz|AtomicTest", re.I)


# --------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def content_sha256(events: list[dict[str, Any]]) -> str:
    h = hashlib.sha256()
    for ev in events:
        h.update(json.dumps(ev, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
    return h.hexdigest()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def process_text(ev: dict[str, Any]) -> str | None:
    """Image and command line of a process-creation event (Sysmon 1, Security 4688), else None."""
    f = ev["fields"]
    if ev["event_id"] == 1:
        return f"{f.get('Image', '')} {f.get('CommandLine', '')}"
    if ev["event_id"] == 4688:
        return f"{f.get('NewProcessName', '')} {f.get('CommandLine', '')}"
    return None


def counts(events: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for ev in events:
        out[ev["channel"]][str(ev["event_id"])] += 1
    return {ch: dict(sorted(c.items(), key=lambda kv: int(kv[0]))) for ch, c in sorted(out.items())}


def dominant_host(events: list[dict[str, Any]]) -> str:
    return collections.Counter(e["host"] for e in events).most_common(1)[0][0]


def iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------------------------------
# window derivation
# --------------------------------------------------------------------------------------------------

def find_anchor_clusters(events: list[dict[str, Any]], anchor_rx: re.Pattern[str]) -> list[list[dict[str, Any]]]:
    """Group matching process-creation events into per-host clusters, ordered by first timestamp."""
    by_host: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for ev in events:
        txt = process_text(ev)
        if txt is not None and anchor_rx.search(txt):
            by_host[ev["host"]].append(ev)
    clusters: list[list[dict[str, Any]]] = []
    for hits in by_host.values():
        cur: list[dict[str, Any]] = []
        for ev in hits:
            if cur and (parse_ts(ev["ts"]) - parse_ts(cur[-1]["ts"])).total_seconds() > CLUSTER_GAP_S:
                clusters.append(cur)
                cur = []
            cur.append(ev)
        if cur:
            clusters.append(cur)
    clusters.sort(key=lambda c: c[0]["ts"])
    return clusters


def derive_window(events: list[dict[str, Any]], anchor: str | None, cluster: int = 0,
                  pre_s: int = PRE_S, post_s: int = POST_S, max_events: int = MAX_EVENTS,
                  head_events: int = HEAD_EVENTS) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (kept events, window description). ``events`` must be sorted."""
    flags: list[str] = []
    clusters = find_anchor_clusters(events, re.compile(anchor, re.I)) if anchor else []
    if not clusters or cluster >= len(clusters):
        host = dominant_host(events)
        host_events = [e for e in events if e["host"] == host]
        kept = host_events[:head_events]
        flags.append("no-anchor-event-found: window is the head of the recording, not an execution window")
        return kept, {
            "method": "whole-file-head", "host": host, "start": kept[0]["ts"], "end": kept[-1]["ts"],
            "anchor_events": 0, "anchor_first": None, "anchor_last": None, "truncated": len(host_events) > len(kept),
            "clusters_found": 0, "flags": flags,
        }
    chosen = clusters[cluster]
    host = chosen[0]["host"]
    first, last = parse_ts(chosen[0]["ts"]), parse_ts(chosen[-1]["ts"])
    host_events = [e for e in events if e["host"] == host]
    start, end = first - timedelta(seconds=pre_s), last + timedelta(seconds=post_s)

    def select(s, e):
        return [ev for ev in host_events if s <= parse_ts(ev["ts"]) <= e]

    kept = select(start, end)
    truncated = False
    if len(kept) > max_events:
        # Shrink the trailing context first, then the leading context, then cut the tail.
        for new_post, new_pre in ((30, pre_s), (30, 10), (10, 5)):
            end = last + timedelta(seconds=new_post)
            start = first - timedelta(seconds=new_pre)
            kept = select(start, end)
            if len(kept) <= max_events:
                break
        if len(kept) > max_events:
            kept = kept[:max_events]
        truncated = True
        flags.append(f"window shrunk to stay within {max_events} events")
    if len(chosen) == 1:
        flags.append("single anchor event")
    if len(clusters) > 1:
        flags.append(f"{len(clusters)} anchor clusters in the recording; cluster {cluster} used")
    return kept, {
        "method": "process-creation-anchor", "host": host, "start": iso(start), "end": iso(end),
        "anchor_events": len(chosen), "anchor_first": chosen[0]["ts"], "anchor_last": chosen[-1]["ts"],
        "truncated": truncated, "clusters_found": len(clusters), "flags": flags,
    }


# --------------------------------------------------------------------------------------------------
# baseline
# --------------------------------------------------------------------------------------------------

_SIG_KEYS = ("Image", "SourceImage", "TargetImage", "GrantedAccess", "CommandLine", "ParentImage", "TargetObject",
             "EventType", "QueryName", "DestinationIp", "DestinationPort", "ImageLoaded", "Signed", "User")


def _signature(ev: dict[str, Any]) -> tuple:
    f = ev["fields"]
    return (ev["event_id"],) + tuple(f.get(k, "") for k in _SIG_KEYS)


def _is_harness(ev: dict[str, Any]) -> bool:
    f = ev["fields"]
    if _HARNESS_RX.search(json.dumps(f)):
        return True
    return (ev["event_id"] == 1 and f.get("Image", "").lower().endswith("\\cmd.exe")
            and f.get("ParentImage", "").lower().endswith("\\powershell.exe") and '/c "' in f.get("CommandLine", ""))


def baseline_lead_in(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Events of the dominant host before the first Atomic-harness event, minus a safety margin."""
    host = dominant_host(events)
    host_events = [e for e in events if e["host"] == host]
    idx = next((i for i, e in enumerate(host_events) if _is_harness(e)), len(host_events))
    if idx == len(host_events):
        return []  # no harness event found: no confidence that the head is attack-free
    cutoff = parse_ts(host_events[idx]["ts"]) - timedelta(seconds=BASELINE_MARGIN_S)
    return [e for e in host_events[:idx] if parse_ts(e["ts"]) <= cutoff]


def build_baseline(per_file_events: dict[str, list[dict[str, Any]]], max_events: int = BASELINE_MAX
                   ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    seen: set = set()
    picked: list[dict[str, Any]] = []
    used: dict[str, int] = {}
    for did in sorted(per_file_events):
        n = 0
        for ev in baseline_lead_in(per_file_events[did]):
            sig = _signature(ev)
            if sig in seen:
                continue
            seen.add(sig)
            picked.append(ev)
            n += 1
        if n:
            used[did] = n
    picked.sort(key=event_sort_key)
    total_unique = len(picked)
    if len(picked) > max_events:  # deterministic thinning, keeps the spread over hosts and time
        step = len(picked) / max_events
        picked = [picked[int(i * step)] for i in range(max_events)]
    return picked, {"unique_signatures": total_unique, "from_recordings": used}


# --------------------------------------------------------------------------------------------------
# Atomic metadata and library
# --------------------------------------------------------------------------------------------------

def load_atomic_tests(sources: Path, attack_id: str) -> dict[str, Any]:
    with open(sources / "atomics" / f"{attack_id}.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def atomic_record(doc: dict[str, Any], attack_id: str, test_name: str, guid: str | None = None) -> dict[str, Any]:
    matches = [t for t in doc["atomic_tests"] if t["name"] == test_name and "windows" in t["supported_platforms"]]
    if guid:
        matches = [t for t in matches if t["auto_generated_guid"] == guid]
    if len(matches) != 1:
        raise SystemExit(f"{attack_id}: expected one Windows test named {test_name!r}, found {len(matches)}")
    t = matches[0]
    ex = t["executor"]
    args = {k: str(v.get("default", "")) for k, v in (t.get("input_arguments") or {}).items()}
    return {
        "guid": t["auto_generated_guid"], "name": t["name"], "description": (t.get("description") or "").strip(),
        "executor": ex["name"], "command": (ex.get("command") or "").rstrip("\n"),
        "cleanup_command": (ex.get("cleanup_command") or "").rstrip("\n"),
        "elevation_required": bool(ex.get("elevation_required", False)),
        "input_arguments": args, "supported_platforms": list(t["supported_platforms"]),
        "source_url": f"{ATOMIC_REPO}/blob/{ATOMIC_COMMIT}/atomics/{attack_id}/{attack_id}.yaml",
    }


def dataset_manifest(sources: Path, dataset_id: str) -> dict[str, Any]:
    with open(sources / "yml" / f"{dataset_id}.yml", encoding="utf-8") as fh:
        y = yaml.safe_load(fh)
    return {
        "author": str(y.get("author", "")), "date": str(y.get("date", "")), "id": str(y.get("id", "")),
        "environment": str(y.get("environment", "")), "description": " ".join(str(y.get("description", "")).split()),
    }


# --------------------------------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------------------------------

def build(sources: Path, out: Path) -> dict[str, Any]:
    tele = out / "telemetry"
    if tele.exists():
        shutil.rmtree(tele)
    tele.mkdir(parents=True)
    techniques: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    per_file: dict[str, list[dict[str, Any]]] = {}

    for spec in SPECS:
        aid, did = spec["attack_id"], spec["dataset_id"]
        log = sources / "logs" / f"{did}.log"
        stats = ReadStats()
        events = sorted(read_xml_log(log, stats), key=event_sort_key)
        per_file[did] = events
        doc = load_atomic_tests(sources, aid)
        atomic = atomic_record(doc, aid, spec["atomic"], spec["guid"]) if spec["atomic"] else None
        dm = dataset_manifest(sources, did)
        kept, window = derive_window(events, spec["anchor"], spec["cluster"])
        if spec["link"] == "recorded" and window["method"] != "whole-file-head":
            pass  # an anchor exists but the execution is not a named Atomic test
        rel = f"{aid}/{slug(spec['atomic']) if spec['atomic'] else 'recorded-execution'}.jsonl.gz"
        path = tele / rel
        write_jsonl_gz(path, kept)
        src_rel = f"datasets/attack_techniques/{did}/{spec['folder']}/windows-sysmon.log"
        entry = {
            "path": rel, "kind": "test", "technique": aid, "dataset_id": did,
            "atomic_guid": atomic["guid"] if atomic else None, "atomic_name": atomic["name"] if atomic else None,
            "link": spec["link"], "events": len(kept), "by_channel": counts(kept),
            "sha256": sha256_file(path), "bytes": path.stat().st_size, "content_sha256": content_sha256(kept),
            "window": {**window, "basis": spec["basis"], "anchor_regex": spec["anchor"], "note": spec["note"],
                       "pre_seconds": PRE_S, "post_seconds": POST_S,
                       "recording_start": events[0]["ts"], "recording_end": events[-1]["ts"],
                       "recording_events": len(events)},
            "source": {
                "repo": SPLUNK_REPO, "commit": SPLUNK_COMMIT, "path": src_rel, "url": MEDIA + src_rel,
                "sha256": sha256_file(log), "bytes": log.stat().st_size, "dataset_author": dm["author"],
                "dataset_date": dm["date"], "dataset_id": dm["id"], "dataset_description": dm["description"],
                "parse": stats.as_dict(),
            },
            "license": "Apache-2.0",
        }
        files.append(entry)
        techniques.append({
            "attack_id": aid, "dataset_id": did, "name": spec["name"], "tactics": spec["tactics"],
            "execution_kind": ATOMIC_KIND if atomic else RECORDED,
            "atomic": atomic,
            "dataset": {
                "name": f"Splunk attack_data {did}/{spec['folder']}", "url": f"{SPLUNK_REPO}/tree/{SPLUNK_COMMIT}/"
                f"datasets/attack_techniques/{did}/{spec['folder']}", "author": dm["author"], "date": dm["date"],
                "description": dm["description"], "environment": dm["environment"], "license": "Apache-2.0",
            },
            "link": spec["link"],
            "telemetry": rel,
            "note": spec["note"],
        })
        print(f"{aid:10s} {entry['events']:5d} events  {entry['window']['method']:23s} {entry['bytes']:8d} B  "
              f"source: {stats.parsed} parsed, {stats.skipped_total} skipped"
              + (f" {dict(stats.skipped)}" if stats.skipped else ""), flush=True)

    base_events, base_info = build_baseline(per_file)
    # The baseline must not overlap any attack window or contain any anchor command.
    all_anchor_rx = [re.compile(s["anchor"], re.I) for s in SPECS if s["anchor"]]
    for ev in base_events:
        txt = process_text(ev)
        if txt is not None and any(rx.search(txt) for rx in all_anchor_rx):
            raise SystemExit(f"baseline event matches an attack anchor: {txt[:120]}")
    bpath = tele / "baseline.jsonl.gz"
    write_jsonl_gz(bpath, base_events)
    files.append({
        "path": "baseline.jsonl.gz", "kind": "baseline", "technique": None, "dataset_id": None,
        "events": len(base_events), "by_channel": counts(base_events), "sha256": sha256_file(bpath),
        "bytes": bpath.stat().st_size, "content_sha256": content_sha256(base_events),
        "window": None,
        "provenance": (
            "Benign-by-construction lead-in of the Splunk attack_data recordings above: for each recording, the "
            "events of its busiest host from the start up to 30 s before the first Atomic Red Team harness or "
            "attack-tool event (so before any test ran), de-duplicated by event shape across recordings and "
            "thinned deterministically to the cap. This is idle Windows Server 2016 domain-controller lab "
            "activity (boot, services, Splunk forwarder, .NET compilation by the harness's PowerShell). Splunk "
            "attack_data publishes no benign-only dataset, so this is not a production workstation baseline."),
        "baseline": {**base_info, "max_events": BASELINE_MAX, "margin_seconds": BASELINE_MARGIN_S},
        "source": {"repo": SPLUNK_REPO, "commit": SPLUNK_COMMIT, "recordings": sorted(base_info["from_recordings"])},
        "license": "Apache-2.0",
    })
    print(f"baseline   {len(base_events):5d} events  {base_info['unique_signatures']} unique shapes", flush=True)

    manifest = {
        "manifest_version": 1,
        "generator": "backend/scripts/build_datasets.py",
        "attack": {"version": ATTACK_VERSION, "data_release": ATTACK_DATA_RELEASE},
        "sources": {
            "telemetry": {"name": "Splunk attack_data", "repo": SPLUNK_REPO, "commit": SPLUNK_COMMIT,
                          "license": "Apache-2.0", "format": "Windows Event XML (Sysmon/Operational)"},
            "atomics": {"name": "Atomic Red Team", "repo": ATOMIC_REPO, "commit": ATOMIC_COMMIT, "license": "MIT"},
        },
        "parameters": {"pre_seconds": PRE_S, "post_seconds": POST_S, "cluster_gap_seconds": CLUSTER_GAP_S,
                       "max_events_per_test": MAX_EVENTS, "head_events": HEAD_EVENTS,
                       "baseline_max_events": BASELINE_MAX},
        "trimmed": True,
        "total_bytes": sum(f["bytes"] for f in files),
        "files": files,
    }
    (tele / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    library = {
        "library_version": 1,
        "attack": {"version": ATTACK_VERSION, "data_release": ATTACK_DATA_RELEASE, "domain": "enterprise-attack"},
        "atomic_red_team": {"repo": ATOMIC_REPO, "commit": ATOMIC_COMMIT, "license": "MIT"},
        "techniques": techniques,
    }
    (out / "library.json").write_text(json.dumps(library, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    lic = sources / "licenses"
    shutil.copyfile(lic / "splunk-attack_data-LICENSE.txt", tele / "LICENSE-Apache-2.0.txt")
    shutil.copyfile(lic / "atomic-red-team-LICENSE.txt", out / "ATOMIC_RED_TEAM_LICENSE.txt")
    (tele / "NOTICE.md").write_text(NOTICE, encoding="utf-8")
    return manifest


NOTICE = f"""# Recorded telemetry notice

The `*.jsonl.gz` files in this directory are **trimmed, normalised subsets** of Windows Sysmon event
logs from Splunk's `attack_data` repository ({SPLUNK_REPO}, commit `{SPLUNK_COMMIT}`), licensed under
the Apache License 2.0 (text in `LICENSE-Apache-2.0.txt`).

Changes made by PurpleBench: events were parsed from Windows Event XML, normalised to JSON (original
EventData field names kept), reduced to the events of one test window on one host (or, for
`baseline.jsonl.gz`, to benign lead-in events), and re-compressed. Event values are unchanged apart
from timestamp precision (7→6 fractional digits) and conversion from XML to JSON. Events the parser
could not read are counted per file in `manifest.json` (`source.parse`).
Each file's exact upstream path, URL, dataset author and window derivation are listed in `manifest.json`.

Dataset authors are named in the upstream `.yml` manifests and copied into `manifest.json`.
The data are recordings of simulated attacks on lab machines (hostnames such as `win-dc-*.attackrange.local`).
"""


def check(sources: Path, out: Path) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        fresh_out = Path(tmp)
        fresh = build(sources, fresh_out)
        committed = json.loads((out / "telemetry" / "manifest.json").read_text("utf-8"))
        bad = []
        want = {f["path"]: f for f in committed["files"]}
        got = {f["path"]: f for f in fresh["files"]}
        for p in sorted(set(want) | set(got)):
            if p not in want or p not in got:
                bad.append(f"{p}: present in only one of committed/rebuilt")
            elif want[p]["content_sha256"] != got[p]["content_sha256"] or want[p]["events"] != got[p]["events"]:
                bad.append(f"{p}: content differs from rebuild")
            elif want[p]["window"] != got[p]["window"]:
                bad.append(f"{p}: window metadata differs from rebuild")
        if json.loads((out / "library.json").read_text("utf-8")) != json.loads((fresh_out / "library.json").read_text("utf-8")):
            bad.append("library.json differs from rebuild")
    for b in bad:
        print("MISMATCH", b)
    print("OK: committed files match a rebuild" if not bad else f"{len(bad)} mismatch(es)")
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sources", required=True, type=Path, help="scratch directory with the downloaded sources")
    ap.add_argument("--out", type=Path, default=BACKEND / "data", help="output data directory")
    ap.add_argument("--check", action="store_true", help="rebuild and compare with the committed files")
    ap.add_argument("--download", action="store_true", help="run scripts/fetch_sources.py first")
    args = ap.parse_args(argv)
    if args.download:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import fetch_sources
        fetch_sources.main(["fetch_sources", str(args.sources)])
    repo = BACKEND.parent
    if repo in args.sources.resolve().parents or args.sources.resolve() == repo:
        raise SystemExit("--sources must be outside the repository")
    if args.check:
        return check(args.sources, args.out)
    build(args.sources, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
