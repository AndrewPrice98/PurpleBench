"""Rule set versions v1 to v4.

A rule set version is a list of rule files in the repository (``rules/sigmahq`` and ``rules/custom``);
the YAML itself is never copied into the database. The versions model a team that tunes its detections
over six weeks: each step adds rules that close specific gaps the previous runs showed, and ``v4``
is the full bundled set. The narrative for every addition is recorded in ``DECISIONS.md`` and, per
rule, in the ``note`` below (stored with the rule set).

``rules_hash`` is a content hash of the selected rule files (line endings normalised), so a stored
rule set can be checked against the files that exist today.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import config
from .sigma import Rule, load_rules

ORIGINS = ("sigmahq", "custom")


@dataclass(frozen=True)
class RuleSetDef:
    version: str
    offset_days: int  # days after the demo anchor date when the rule set was created
    notes: str
    adds: tuple[tuple[str, str], ...]  # (rule file stem, why it was added); empty note = no remark


H = "proc_creation_win_"

V1 = RuleSetDef("v1", -1, (
    "Starter set: 15 well-known SigmaHQ rules a team enables first (LSASS dumping with ProcDump, shadow copy "
    "deletion, event log clearing, Run key and scheduled task persistence, new local users, certutil downloads, "
    "regsvr32 and mshta abuse, PsExec) plus two Windows Security/System log rules and the Security-channel "
    "pass-the-hash rule. The recorded telemetry has no Security or System channel, so those three can show "
    "nothing here."), (
    (H + "sysinternals_procdump_lsass", "LSASS dumping with ProcDump."),
    (H + "susp_shadow_copies_deletion", "Shadow copy deletion (vssadmin, wmic)."),
    (H + "powershell_shadowcopy_deletion", "Shadow copy deletion with PowerShell."),
    (H + "susp_eventlog_clear", "Event log clearing."),
    (H + "reg_add_run_key", "Run key persistence."),
    (H + "schtasks_creation", "Scheduled task creation."),
    (H + "net_user_add", "New local user with net.exe."),
    (H + "certutil_download", "Certutil used to download files."),
    (H + "regsvr32_flags_anomaly", "Regsvr32 scriptlet abuse."),
    (H + "mshta_susp_child_processes", "Mshta spawning interpreters."),
    (H + "sysinternals_psexec_execution", "PsExec use. Only tagged with the parent technique T1021, so it "
                                          "earns partial credit for T1021.002 at best."),
    ("proc_access_win_lsass_memdump", "LSASS memory access. Fires on benign activity in the baseline (2 hits), "
                                      "so it is noisy and earns no credit."),
    ("win_system_eventlog_cleared", "System log cleared (event 104). Telemetry gap in recorded mode."),
    ("win_security_user_creation", "User created (event 4720). Telemetry gap in recorded mode."),
    ("win_security_pass_the_hash_2", "Pass-the-hash logon (event 4624). Telemetry gap in recorded mode, so "
                                     "T1550.002 reads as a telemetry gap, not a miss."),
))

V2 = RuleSetDef("v2", 13, (
    "More SigmaHQ coverage after run 1: services, WMI, Defender tampering and network discovery, plus the popular "
    "encoded-PowerShell rule. That rule fires on the benign baseline (5 hits) so it is flagged noisy and its "
    "credit is withheld. The Event Viewer UAC bypass rules from SigmaHQ are added too; they do not match the "
    "recorded telemetry (Sysmon writes the key as ...\\command\\(Default))."), (
    (H + "powershell_encode", "Encoded PowerShell. Noisy: 5 hits on the benign baseline, so its exact credit "
                              "for T1059.001 is withheld (only a related mshta hit remains, partial) until v3 "
                              "adds a tuned replacement."),
    (H + "wmic_process_creation", "WMI process creation (T1047)."),
    (H + "sc_create_service", "Service creation with sc.exe (T1543.003)."),
    (H + "susp_service_creation", "Second service creation rule."),
    (H + "powershell_disable_defender_av_security_monitoring", "Defender tampering with PowerShell (T1685)."),
    (H + "net_view_share_and_sessions_enum", "Remote system discovery with net view (T1018)."),
    (H + "wmic_recon_group", "Group recon with wmic. It fires once on the baseline (noisy) and did not match "
                             "the recorded local group enumeration, so T1069.001 stays a gap until v3."),
    (H + "eventvwr_susp_child_process", "Event Viewer UAC bypass. Does not match the recording."),
    ("registry_set_uac_bypass_eventvwr", "Event Viewer UAC bypass key. Does not match the recording: the key "
                                         "path ends in \\command\\(Default) in Sysmon."),
    (H + "rundll32_process_dump_via_comsvcs", "LSASS dump through comsvcs.dll."),
    ("win_security_susp_scheduled_task_creation", "Scheduled task (event 4698). Telemetry gap in recorded mode."),
    ("win_system_service_install_susp", "Service install (event 7045). Telemetry gap in recorded mode."),
    ("posh_ps_susp_download", "Script block logging rule (event 4104). Telemetry gap in recorded mode."),
    (H + "powershell_base64_iex", "Uses the unsupported |base64offset modifier, so it is listed as unsupported "
                                  "and never evaluated as no-match."),
    (H + "mshta_javascript", "Mshta running script content."),
))

V3 = RuleSetDef("v3", 27, (
    "First custom rules, each written for a gap runs 1 and 2 showed: a tuned replacement for the noisy "
    "encoded-PowerShell rule, local group enumeration with net.exe, 7-Zip archives with split volumes or maximum "
    "compression, and quser/qwinsta session discovery. The noisy SigmaHQ rule stays enabled and visible but "
    "no longer carries any credit."), (
    ("proc_creation_win_powershell_encoded_command_tuned", "Closes T1059.001 (missed in run 1, partial in "
                                                           "run 2 with the noisy rule's credit withheld) and T1027: encoded commands outside the "
                                                           "remote-management harness shapes that make the "
                                                           "SigmaHQ rule noisy."),
    (H + "net_localgroup_enumeration", "Closes T1069.001: the SigmaHQ wmic rule never matched the recorded "
                                       "'net localgroup' and was noisy on the baseline."),
    (H + "7zip_split_or_max_compression", "Closes T1560.001: the SigmaHQ 7-Zip rule only covers password-protected "
                                          "archives."),
    (H + "quser_qwinsta_session_discovery", "Closes T1033: logged-on user discovery with quser/qwinsta."),
))

# v4 is every remaining bundled rule; these are the ones that close a specific gap, the rest get a default remark.
V4_NOTES = {
    "registry_set_uac_bypass_shell_open_command": "Closes T1548.002: matches the shell\\open\\command hijack "
        "including Sysmon's \\(Default) suffix, which the SigmaHQ Event Viewer rules miss.",
    "proc_creation_win_uac_bypass_fodhelper": "Second UAC bypass rule for T1548.002.",
    "registry_set_uac_disable": "Third UAC rule for T1548.002.",
    H + "rundll32_mshtml_script_protocol": "Closes T1218.011: the comparable SigmaHQ rule has no ATT&CK tag, "
        "so it could not be credited to a technique.",
    H + "rundll32_uncommon_dll_extension": "Second T1218.011 rule.",
    H + "reg_dumping_sensitive_hives": "Closes T1003.002 (SAM and SYSTEM hive dumping).",
    H + "esentutl_sensitive_file_copy": "Second T1003.002 rule.",
    H + "systeminfo_execution": "Closes T1082 (partial in run 2: only a noisy rule fired).",
    H + "whoami_output": "Second T1033 rule.",
    H + "cmd_ping_sweep": "Second T1018 rule: ping sweeps from a cmd loop.",
    "proc_access_win_lsass_from_user_writable_path": "Credit source for T1003.001 in place of the noisy "
        "proc_access_win_lsass_memdump rule.",
}
V4_DEFAULT = "Remaining bundled rule enabled in v4 (second rule for a technique that was already covered, or outside recorded telemetry)."
V4 = RuleSetDef("v4", 41, (
    "The full bundled set (58 SigmaHQ and 12 custom rules): the held-back UAC, rundll32, credential and "
    "discovery rules, and every other bundled rule. Rules that cannot match recorded telemetry (Security, System "
    "and PowerShell script block channels) or use unsupported Sigma features stay in the set and are labelled as "
    "such, not hidden."), ())

RULESETS: tuple[RuleSetDef, ...] = (V1, V2, V3, V4)


def load_all_rules(rules_dir: Path | str | None = None) -> dict[str, Rule]:
    """Every bundled rule keyed by file stem. Stems are unique across the two folders."""
    root = Path(rules_dir) if rules_dir else config.RULES_DIR
    out: dict[str, Rule] = {}
    for origin in ORIGINS:
        for r in load_rules(root / origin):
            stem = Path(r.path).stem
            if stem in out:
                raise ValueError(f"duplicate rule file name {stem}")
            out[stem] = r
    return out


def ruleset_stems(version: str, all_stems: list[str]) -> list[str]:
    """Rule file stems enabled in ``version`` (cumulative; v4 is everything), in file-name order."""
    wanted: set[str] = set()
    for d in RULESETS:
        wanted.update(s for s, _ in d.adds)
        if d.version == version:
            break
    else:
        raise ValueError(f"unknown rule set version {version}")
    if version == V4.version:
        wanted = set(all_stems)
    missing = sorted(wanted - set(all_stems))
    if missing:
        raise ValueError(f"rule set {version} names unknown rules: {', '.join(missing)}")
    return sorted(wanted)


def added_in(stem: str) -> tuple[str, str]:
    """(version that first enabled the rule, remark)."""
    for d in RULESETS[:-1]:
        for s, note in d.adds:
            if s == stem:
                return d.version, note
    return V4.version, V4_NOTES.get(stem, V4_DEFAULT)


def rules_hash(rules: list[Rule]) -> str:
    """SHA-256 over the id, file name and normalised content hash of the selected rules."""
    items = []
    for r in sorted(rules, key=lambda x: x.id):
        data = Path(r.path).read_bytes().replace(b"\r\n", b"\n")
        items.append({"id": r.id, "file": Path(r.path).name, "sha256": hashlib.sha256(data).hexdigest()})
    blob = json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()
