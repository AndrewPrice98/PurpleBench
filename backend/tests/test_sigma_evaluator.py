"""Sigma evaluator: statuses, telemetry gaps, determinism."""
import random

from sigma_helpers import evaluate_on, event, proc

from purplebench import sigma
from purplebench.sigma import mapping as M

PC = {"product": "windows", "category": "process_creation"}


def rule(detection, logsource=PC):
    r = sigma.parse_rule({"title": "t", "id": "x", "logsource": logsource, "detection": detection})
    assert r.status == "ok", r.reason
    return r


SEC_4688 = dict(NewProcessName="C:\\Windows\\System32\\cmd.exe", CommandLine="cmd.exe /c whoami",
                ParentProcessName="C:\\Windows\\explorer.exe", SubjectUserName="alice", SubjectDomainName="CORP")


def test_missing_field_is_telemetry_gap():
    # Sysmon in the recordings predates ParentUser: a rule that needs it cannot match there.
    needs = rule({"sel": {"ParentUser|contains": "AUTHORI", "Image|endswith": "\\whoami.exe"}, "condition": "sel"})
    res = evaluate_on(needs, [proc(Image="C:\\Windows\\System32\\whoami.exe")])
    assert res.status == sigma.GAP
    assert "ParentUser" in res.detail and "Sysmon event 1" in res.detail
    assert "channel 'Security' is not in the telemetry" in res.detail
    assert res.matched_events == ()

    # The same field only in a filter does not stop the rule from matching: not a gap.
    filtered = rule({"sel": {"Image|endswith": "\\whoami.exe"}, "filter": {"ParentUser|contains": "AUTHORI"},
                     "condition": "sel and not filter"})
    res = evaluate_on(filtered, [proc(Image="C:\\Windows\\System32\\whoami.exe")])
    assert res.status == sigma.MATCH

    # Security 4688 only (lab mode): Image is mapped from NewProcessName, so a Sysmon-named rule works ...
    ev4688 = event(4688, channel=M.SECURITY, **SEC_4688)
    by_image = rule({"sel": {"Image|endswith": "\\cmd.exe"}, "condition": "sel"})
    assert evaluate_on(by_image, [ev4688]).status == sigma.MATCH
    # ... but OriginalFileName does not exist in 4688: telemetry gap, not "missed".
    by_ofn = rule({"sel": {"OriginalFileName": "Cmd.Exe"}, "condition": "sel"})
    res = evaluate_on(by_ofn, [ev4688])
    assert res.status == sigma.GAP
    assert "Security event 4688" in res.detail and "OriginalFileName" in res.detail
    assert "channel 'Microsoft-Windows-Sysmon/Operational' is not in the telemetry" in res.detail


def test_or_of_present_and_missing_field_is_evaluable():
    r = rule({"a": {"ParentUser": "x"}, "b": {"Image|endswith": "\\cmd.exe"}, "condition": "a or b"})
    assert evaluate_on(r, [proc(Image="C:\\cmd.exe")]).status == sigma.MATCH
    assert evaluate_on(r, [proc()]).status == sigma.NO_MATCH


def test_null_and_exists_false_on_missing_field_are_not_gaps():
    r = rule({"sel": {"Image|endswith": "notepad.exe", "ParentUser": None}, "condition": "sel"})
    assert evaluate_on(r, [proc()]).status == sigma.MATCH
    r = rule({"sel": {"ParentUser|exists": False}, "condition": "sel"})
    assert evaluate_on(r, [proc()]).status == sigma.MATCH


def test_absent_channel_and_event_id_are_gaps():
    sec = rule({"sel": {"EventID": 4720}, "condition": "sel"}, {"product": "windows", "service": "security"})
    res = evaluate_on(sec, [proc()])
    assert res.status == sigma.GAP and "channel 'Security' is not in the telemetry" in res.detail
    ps = rule({"sel": {"ScriptBlockText|contains": "x"}, "condition": "sel"},
              {"product": "windows", "category": "ps_script"})
    assert evaluate_on(ps, [proc()]).status == sigma.GAP
    remote_thread = rule({"sel": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "sel"},
                         {"product": "windows", "category": "create_remote_thread"})
    res = evaluate_on(remote_thread, [proc()])
    assert res.status == sigma.GAP and "no Sysmon event 8 in the telemetry" in res.detail


def test_corpus_profile_turns_a_window_without_the_event_into_no_match():
    remote_thread = rule({"sel": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "sel"},
                         {"product": "windows", "category": "create_remote_thread"})
    corpus = sigma.TelemetryProfile.from_events([proc(), event(8, TargetImage="C:\\x.exe", SourceImage="y")])
    assert sigma.evaluate(remote_thread, [proc()], profile=corpus).status == sigma.NO_MATCH


def test_match_lists_record_ids_in_time_order_and_first_ts():
    r = rule({"sel": {"Image|endswith": "\\cmd.exe"}, "condition": "sel"})
    evs = [proc(rid=30, ts="2021-01-01T00:00:03.000000Z", Image="C:\\cmd.exe"),
           proc(rid=10, ts="2021-01-01T00:00:01.000000Z", Image="C:\\cmd.exe"),
           proc(rid=20, ts="2021-01-01T00:00:02.000000Z")]
    res = evaluate_on(r, evs)
    assert res.status == sigma.MATCH
    assert res.matched_events == (10, 30)
    assert res.first_ts == "2021-01-01T00:00:01.000000Z"
    assert res.matches[0] == sigma.EventRef("2021-01-01T00:00:01.000000Z", "host1", 10, M.SYSMON, 1)
    assert res.rule_id == "x" and "2 matching event(s)" in res.detail


def test_evaluation_is_deterministic_and_order_independent():
    r = rule({"sel": {"CommandLine|contains": "a"}, "condition": "sel"})
    evs = [proc(rid=i, ts=f"2021-01-01T00:00:{i:02d}.000000Z", CommandLine="a" if i % 3 else "b") for i in range(40)]
    first = evaluate_on(r, evs)
    shuffled = evs[:]
    random.Random(7).shuffle(shuffled)
    assert evaluate_on(r, shuffled) == first
    assert evaluate_on(r, sigma.EventIndex(evs)) == first
    assert evs == sorted(evs, key=lambda e: e["record_id"])  # inputs are not mutated


def test_no_match_is_reported_when_evaluable():
    r = rule({"sel": {"Image|endswith": "\\cmd.exe"}, "condition": "sel"})
    res = evaluate_on(r, [proc()])
    assert res.status == sigma.NO_MATCH and res.matched_events == () and res.first_ts is None
    assert "not evaluated" in res.detail  # the Security 4688 source is absent and says so
    assert res.gaps == ("channel 'Security' is not in the telemetry (needed for Security event 4688)",)
