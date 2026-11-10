"""Logsource -> (channel, event id) mapping and field mapping (Review Focus 2)."""
import pytest
from sigma_helpers import evaluate_on, event, proc

from purplebench import sigma
from purplebench.sigma import mapping as M

PC = {"product": "windows", "category": "process_creation"}


def rule(detection, logsource=PC):
    r = sigma.parse_rule({"title": "t", "id": "x", "logsource": logsource, "detection": detection})
    assert r.status == "ok", r.reason
    return r


# Every Windows category of the Sigma 2.1.0 taxonomy appendix that is an event log channel.
TAXONOMY = {
    "process_creation": (M.SYSMON, (1,)), "file_change": (M.SYSMON, (2,)), "network_connection": (M.SYSMON, (3,)),
    "sysmon_status": (M.SYSMON, (4, 16)), "process_termination": (M.SYSMON, (5,)), "driver_load": (M.SYSMON, (6,)),
    "image_load": (M.SYSMON, (7,)), "create_remote_thread": (M.SYSMON, (8,)), "raw_access_thread": (M.SYSMON, (9,)),
    "process_access": (M.SYSMON, (10,)), "file_event": (M.SYSMON, (11,)), "registry_event": (M.SYSMON, (12, 13, 14)),
    "registry_add": (M.SYSMON, (12,)), "registry_delete": (M.SYSMON, (12,)), "registry_set": (M.SYSMON, (13,)),
    "registry_rename": (M.SYSMON, (14,)), "create_stream_hash": (M.SYSMON, (15,)), "pipe_created": (M.SYSMON, (17, 18)),
    "wmi_event": (M.SYSMON, (19, 20, 21)), "dns_query": (M.SYSMON, (22,)), "file_delete": (M.SYSMON, (23,)),
    "clipboard_capture": (M.SYSMON, (24,)), "process_tampering": (M.SYSMON, (25,)),
    "file_delete_detected": (M.SYSMON, (26,)), "file_block_executable": (M.SYSMON, (27,)),
    "file_block_shredding": (M.SYSMON, (28,)), "file_executable_detected": (M.SYSMON, (29,)),
    "sysmon_error": (M.SYSMON, (255,)),
    "ps_classic_start": (M.POWERSHELL_CLASSIC, (400,)), "ps_classic_provider_start": (M.POWERSHELL_CLASSIC, (600,)),
    "ps_classic_script": (M.POWERSHELL_CLASSIC, (800,)), "ps_module": (M.POWERSHELL, (4103,)),
    "ps_script": (M.POWERSHELL, (4104,)),
}


@pytest.mark.parametrize("category,expected", sorted(TAXONOMY.items()))
def test_category_mapping(category, expected):
    sources = M.resolve_logsource({"product": "windows", "category": category})
    assert (sources[0].channel, sources[0].event_ids) == expected


def test_process_creation_also_reads_security_4688_and_ps_script_reads_powershell_core():
    pc = M.resolve_logsource(PC)
    assert [(s.channel, s.event_ids) for s in pc] == [(M.SYSMON, (1,)), (M.SECURITY, (4688,))]
    ps = M.resolve_logsource({"product": "windows", "category": "ps_script"})
    assert [(s.channel, s.event_ids) for s in ps] == [(M.POWERSHELL, (4104,)), (M.POWERSHELL_CORE, (4104,))]


@pytest.mark.parametrize("service,channel", [
    ("security", "Security"), ("system", "System"), ("sysmon", M.SYSMON), ("powershell", M.POWERSHELL),
    ("powershell-classic", "Windows PowerShell"), ("taskscheduler", "Microsoft-Windows-TaskScheduler/Operational"),
    ("windefend", "Microsoft-Windows-Windows Defender/Operational"), ("application", "Application"),
])
def test_service_mapping(service, channel):
    sources = M.resolve_logsource({"product": "windows", "service": service})
    assert sources[0].channel == channel and sources[0].event_ids is None


@pytest.mark.parametrize("logsource,reason", [
    ({"product": "linux", "category": "process_creation"}, "product 'linux'"),
    ({"category": "process_creation"}, "product None"),
    ({"product": "windows", "category": "file_rename"}, "ETW provider"),
    ({"product": "windows", "service": "nosuch"}, "service 'nosuch'"),
    ({"product": "windows"}, "neither category nor service"),
    ({"product": "windows", "category": "process_creation", "service": "sysmon"}, "both category"),
])
def test_unmapped_logsources(logsource, reason):
    with pytest.raises(M.LogsourceError, match=reason):
        M.resolve_logsource(logsource)


SEC_4688 = dict(NewProcessName="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd.exe /c whoami",
                ParentProcessName="C:\\Windows\\explorer.exe", SubjectUserName="alice", SubjectDomainName="CORP",
                NewProcessId="0x1a4", ProcessId="0x32", MandatoryLabel="S-1-16-12288", SubjectLogonId="0x3e7")


@pytest.mark.parametrize("field,value", [
    ("Image", "C:\\Windows\\System32\\cmd.exe"), ("CommandLine", "cmd.exe /c whoami"),
    ("ParentImage", "C:\\Windows\\explorer.exe"), ("User", "CORP\\alice"), ("ProcessId", "420"),
    ("ParentProcessId", "50"), ("IntegrityLevel", "High"), ("LogonId", "0x3e7"),
])
def test_security_4688_field_mapping(field, value):
    ev = event(4688, channel=M.SECURITY, **SEC_4688)
    src = M.resolve_logsource(PC)[1]
    assert M.read_field(src, ev, field) == value
    # and a rule written against the Sysmon field name matches the 4688 event
    res = evaluate_on(rule({"sel": {field: value}, "condition": "sel"}), [ev])
    assert res.status == sigma.MATCH, res.detail


def test_security_4688_cannot_supply_sysmon_only_fields():
    src = M.resolve_logsource(PC)[1]
    present = frozenset(SEC_4688)
    for f in ("OriginalFileName", "Hashes", "ParentCommandLine", "CurrentDirectory", "Product", "ParentUser"):
        assert not M.field_available(src, f, present)
    for f in ("Image", "ParentImage", "CommandLine", "User", "EventID"):
        assert M.field_available(src, f, present)
    # the raw 4688 names are not readable under their own name through the process_creation mapping
    assert M.read_field(src, event(4688, channel=M.SECURITY, **SEC_4688), "NewProcessName") is None


def test_sysmon_fields_pass_through_and_hashes_are_split():
    src = M.resolve_logsource(PC)[0]
    ev = proc(Hashes="SHA1=AA,MD5=BB,SHA256=CC,IMPHASH=DD")
    assert M.read_field(src, ev, "Image") == ev["fields"]["Image"]
    assert (M.read_field(src, ev, "md5"), M.read_field(src, ev, "sha1"), M.read_field(src, ev, "sha256"),
            M.read_field(src, ev, "Imphash")) == ("BB", "AA", "CC", "DD")
    assert M.read_field(src, ev, "NoSuchField") is None


def test_envelope_fields():
    src = M.resolve_logsource({"product": "windows", "service": "sysmon"})[0]
    ev = proc(rid=7)
    assert M.read_field(src, ev, "EventID") == "1"
    assert M.read_field(src, ev, "Channel") == M.SYSMON
    assert M.read_field(src, ev, "Computer") == "host1"
    r = rule({"sel": {"EventID": 1, "Image|endswith": "notepad.exe"}, "condition": "sel"},
             {"product": "windows", "service": "sysmon"})
    assert evaluate_on(r, [ev, event(3, rid=8, Image="x")]).matched_events == (7,)


def test_category_restricts_event_ids():
    r = rule({"sel": {"Image|endswith": "notepad.exe"}, "condition": "sel"})
    other = event(5, rid=2, Image="C:\\Windows\\System32\\notepad.exe")  # process termination, same field
    res = evaluate_on(r, [proc(rid=1), other])
    assert res.matched_events == (1,)
