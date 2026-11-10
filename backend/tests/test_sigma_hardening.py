"""Fix round 1 of the Sigma evaluator review: envelope-aware gap analysis, malformed rules,
regex time limits, linear wildcard matching, required profile."""
import importlib.util
import logging
import random
import re
import time
from dataclasses import replace
from pathlib import Path

import pytest
from sigma_helpers import evaluate_on, event, proc

from purplebench import sigma
from purplebench.sigma import mapping as M
from purplebench.sigma import parser as P

RULES = Path(__file__).resolve().parent.parent / "rules"
PC = {"product": "windows", "category": "process_creation"}
SECURITY = {"product": "windows", "service": "security"}


def rule(detection, logsource=PC):
    r = sigma.parse_rule({"title": "t", "id": "x", "logsource": logsource, "detection": detection})
    assert r.status == "ok", r.reason
    return r


# -------------------------------------------------------------------------------------------- 1. EventID-aware gaps

def tgt(eid, **f):
    base = dict(TargetUserName="u", ServiceName="svc", TicketEncryptionType="0x17", TicketOptions="0x40810000",
                Status="0x0", IpAddress="::ffff:10.0.0.5")
    base.update(f)
    return event(eid, channel=M.SECURITY, **base)


def test_kerberoasting_rule_on_4768_only_telemetry_is_a_gap():
    real = sigma.load_rule(RULES / "sigmahq" / "win_security_kerberoasting_activity.yml")
    assert real.status == "ok"
    synthetic = rule({"sel": {"EventID": 4769, "TicketEncryptionType": "0x17"}, "condition": "sel"}, SECURITY)
    for r in (real, synthetic):
        res = evaluate_on(r, [tgt(4768)])
        assert res.status == sigma.GAP, res.detail
        assert "no Security event 4769 in the telemetry" in res.detail
        # with the event id present the rule is evaluated, not a gap
        assert evaluate_on(r, [tgt(4768), tgt(4769, rid=2)]).status in (sigma.MATCH, sigma.NO_MATCH)
    assert evaluate_on(synthetic, [tgt(4768), tgt(4769, rid=2)]).matched_events == (2,)


def test_eventid_rule_on_a_channel_wide_source_lists_no_noise_gaps():
    r = rule({"sel": {"EventID": 1, "Image|endswith": "\\whoami.exe"}, "condition": "sel"},
             {"product": "windows", "service": "sysmon"})
    res = sigma.evaluate(r, [proc(Image="C:\\Windows\\System32\\whoami.exe")], sigma.recorded_profile())
    assert res.status == sigma.MATCH
    assert res.gaps == () and "not evaluated" not in res.detail


def test_channel_wide_rule_without_eventid_does_not_report_other_event_ids():
    r = rule({"sel": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "sel"},
             {"product": "windows", "service": "sysmon"})
    res = sigma.evaluate(r, [proc()], sigma.recorded_profile())
    assert res.status == sigma.NO_MATCH and res.gaps == ()


def test_channel_rule_pruned_by_channel_test():
    r = rule({"sel": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 8}, "condition": "sel"},
             {"product": "windows", "service": "sysmon"})
    res = evaluate_on(r, [proc()])
    assert res.status == sigma.GAP and "no Sysmon event 8 in the telemetry" in res.detail


# -------------------------------------------------------------------------------------------- 2. malformed rules

def doc(logsource=None, condition="sel", sel=None):
    return {"title": "t", "id": "x", "logsource": logsource or PC,
            "detection": {"sel": sel or {"Image": "a"}, "condition": condition}}


@pytest.mark.parametrize("d,reason", [
    (doc(logsource={"product": "windows", "category": ["x"]}), "logsource category must be a string"),
    (doc(logsource={"product": "windows", "service": {"a": 1}}), "logsource service must be a string"),
    (doc(logsource={"product": ["windows"], "category": "process_creation"}), "logsource product must be a string"),
    (doc(condition="(" * 3000 + "sel" + ")" * 3000), "nests deeper than 64 levels"),
    (doc(condition="not " * 3000 + "sel"), "nests deeper than 64 levels"),
    (doc(sel={"CommandLine|re": "a{99999999999}"}), "does not compile"),
    (doc(sel={("tuple", "key"): "x"}), "is not a string"),
])
def test_malformed_rule_is_unsupported_not_an_exception(d, reason):
    r = sigma.parse_rule(d)
    assert r.status == "unsupported" and reason in r.reason


def test_deeply_nested_yaml_is_unsupported(tmp_path):
    text = ("title: x\nlogsource: {product: windows, category: process_creation}\n"
            "detection:\n  sel: {Image: " + "[" * 5000 + "]" * 5000 + "}\n  condition: sel\n")
    assert sigma.parse_rule_text(text).reason == "rule could not be parsed: RecursionError"
    f = tmp_path / "nested.yml"
    f.write_text(text, encoding="utf-8")
    assert sigma.load_rule(f).status == "unsupported"


def test_one_bad_file_never_aborts_a_rule_folder(tmp_path):
    good = (RULES / "sigmahq" / "proc_creation_win_schtasks_creation.yml").read_bytes()
    (tmp_path / "a_good.yml").write_bytes(good)
    (tmp_path / "b_bad.yml").write_text("title: x\nlogsource: {product: windows, category: [x]}\n"
                                        "detection: {sel: {Image: a}, condition: sel}\n", encoding="utf-8")
    (tmp_path / "c_nested.yml").write_text("title: x\ndetection: " + "[" * 5000 + "]" * 5000 + "\n", encoding="utf-8")
    rules = sigma.load_rules(tmp_path)
    assert [r.status for r in rules] == ["ok", "unsupported", "unsupported"]


def test_evaluate_all_reports_a_rule_that_fails_and_continues():
    good = rule({"sel": {"Image|endswith": "notepad.exe"}, "condition": "sel"})
    broken = replace(good, id="broken", detection=replace(good.detection, condition=("id", "missing")))
    evs = [proc()]
    results = sigma.evaluate_all([broken, good], evs, sigma.TelemetryProfile.from_events(evs))
    assert results[0].status == sigma.UNSUPPORTED and results[0].detail == "rule could not be evaluated: KeyError"
    assert results[1].status == sigma.MATCH


# -------------------------------------------------------------------------------------------- 3. regex time limit

@pytest.mark.parametrize("pattern,value", [
    (r"(\w+\s?){1,25}!", "abcdefghij" * 3 + " x" * 5000),
    (r"\w*\w*\w*\w*!", "a" * 30_000),
    (r".*.*.*=", "a" * 30_000),
])
def test_pathological_regexes_complete_quickly(pattern, value):
    r = rule({"sel": {"CommandLine|re": pattern}, "condition": "sel"})
    t = time.perf_counter()
    res = evaluate_on(r, [proc(CommandLine=value)])
    assert time.perf_counter() - t < 2
    assert res.status == sigma.NO_MATCH


def test_regex_timeout_counts_as_no_match_and_is_reported(monkeypatch, caplog):
    # (a|aa)+b is exponential; bypass the static guard to exercise the time limit itself.
    monkeypatch.setattr(P, "check_regex", lambda pattern: None)
    r = rule({"sel": {"CommandLine|re": "(a|aa)+b"}, "other": {"Image|endswith": "\\cmd.exe"},
              "condition": "sel or other"})
    evs = [proc(rid=1, CommandLine="a" * 60), proc(rid=2, Image="C:\\cmd.exe", CommandLine="x")]
    t = time.perf_counter()
    with caplog.at_level(logging.WARNING):
        res = evaluate_on(r, evs)
    assert time.perf_counter() - t < 2
    assert res.status == sigma.MATCH and res.matched_events == (2,)
    assert res.regex_timeouts == 1 and "1 |re match(es) timed out" in res.detail
    assert any("timed out" in rec.getMessage() for rec in caplog.records)


def test_regex_flags_still_apply_with_the_regex_module():
    ev = [proc(CommandLine="cmd.exe\n/c whoami")]
    assert evaluate_on(rule({"sel": {"CommandLine|re|i|s": "^CMD.EXE./C"}, "condition": "sel"}), ev).status == sigma.MATCH
    assert evaluate_on(rule({"sel": {"CommandLine|re|i": "^CMD.EXE./C"}, "condition": "sel"}), ev).status == sigma.NO_MATCH
    assert evaluate_on(rule({"sel": {"CommandLine|re|s": "^CMD.EXE./C"}, "condition": "sel"}), ev).status == sigma.NO_MATCH


# -------------------------------------------------------------------------------------------- 4. linear wildcards

def test_many_wildcards_on_a_long_value_are_linear():
    pred = P.string_predicate("*a*b*c*d", "contains")
    value = "abc" * 10_000
    t = time.perf_counter()
    assert pred(value) is False
    assert pred(value + "d") is True
    assert time.perf_counter() - t < 0.5


def _reference(value: str, mode: str, cased: bool, windash: bool):
    """The previous regex construction, used as the reference for the glob matcher."""
    cls = "[" + re.escape(P.WINDASH_CHARS) + "]"
    parts = []
    for kind, text in P.wildcard_tokens(value):
        if kind == "any":
            parts.append(".*")
        elif kind == "one":
            parts.append(".")
        else:
            parts.append("".join(cls if windash and ch in P.WINDASH_CHARS else re.escape(ch) for ch in text))
    body = "".join(parts)
    if mode in ("contains", "endswith"):
        body = ".*" + body
    if mode in ("contains", "startswith"):
        body += ".*"
    rx = re.compile(body, re.DOTALL | (0 if cased else re.IGNORECASE))
    return lambda v: rx.fullmatch(v) is not None


def test_glob_matcher_agrees_with_the_regex_reference():
    rnd = random.Random(1234)
    alphabet = "aAb-/\u2013*?\\"
    checked = 0
    for _ in range(4000):
        pattern = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 7)))
        mode = rnd.choice(["equals", "contains", "startswith", "endswith"])
        cased, windash = rnd.random() < 0.3, rnd.random() < 0.4
        ours = P.string_predicate(pattern, mode, cased=cased, windash=windash)
        ref = _reference(pattern, mode, cased, windash)
        for _ in range(6):
            value = "".join(rnd.choice("aAb-/\u2013\u2014*?\\\n") for _ in range(rnd.randint(0, 9)))
            assert ours(value) == ref(value), (pattern, mode, cased, windash, value)
            checked += 1
    assert checked == 24_000


# -------------------------------------------------------------------------------------------- 5. required profile

def test_profile_is_required():
    r = rule({"sel": {"Image": "x"}, "condition": "sel"})
    with pytest.raises(TypeError):
        sigma.evaluate(r, [proc()])  # noqa: the missing argument is the point
    with pytest.raises(TypeError):
        sigma.evaluate_all([r], [proc()])
    with pytest.raises(TypeError, match="TelemetryProfile"):
        sigma.evaluate(r, [proc()], None)


def test_stale_top_level_evaluator_stub_is_gone():
    assert importlib.util.find_spec("purplebench.evaluator") is None
