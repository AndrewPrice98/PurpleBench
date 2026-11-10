"""Scoring, coverage, gaps and Navigator export (Review Focus 3 and 4)."""
import copy
import json
from datetime import UTC, datetime, timedelta

import pytest
from sigma_helpers import proc

from purplebench import coverage, library, navigator, scoring, sigma
from purplebench.scoring import DETECTED, MISSED, PARTIAL, TELEMETRY_GAP, UNTESTED, Execution

T0 = datetime(2021, 1, 1, 12, 0, 0, tzinfo=UTC)
ANCHOR = T0.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts(offset: float) -> str:
    return (T0 + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def rule(rid: str, image: str, tags=("attack.t1059.001",), title=None):
    r = sigma.parse_rule({
        "title": title or rid, "id": rid, "tags": list(tags),
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"sel": {"Image|endswith": image}, "condition": "sel"},
    })
    assert r.status == "ok", r.reason
    return r


def ex(technique="T1059.001", events=(), **kw):
    return Execution(technique=technique, name="t", tactics=("execution",), events=list(events), anchor_ts=ANCHOR, **kw)


def run(rules, executions, baseline=(), threshold=0, **kw):
    evs = [e for x in executions for e in x.events] + list(baseline) + [proc(999)]
    return scoring.score_run(rules, executions, baseline, sigma.TelemetryProfile.from_events(evs), threshold, **kw)


def evil(offset, rid=1, name="evil.exe"):
    return proc(rid, ts(offset), Image=f"C:\\Users\\u\\{name}")


R_EVIL = rule("r-evil", "\\evil.exe")


@pytest.mark.parametrize("offset,status,ttd", [
    (7.0, DETECTED, 7.0),      # normal case: 7 s after the execution start
    (-3.0, DETECTED, 0.0),     # within the +-5 s skew tolerance: counts, TTD clamped to 0
    (-5.0, DETECTED, 0.0),     # boundary
    (-20.0, MISSED, None),     # lead-in activity long before the start: not this execution
    (300.0, MISSED, None),     # long after the window: must not distort TTD or earn credit
])
def test_ttd_with_skew(offset, status, ttd):
    s = run([R_EVIL], [ex(events=[evil(offset)])]).executions[0]
    assert s.status == status
    assert s.ttd_seconds == ttd
    if status == MISSED:
        assert s.out_of_window == 1 and "outside the execution window" in s.reason


def test_ttd_uses_first_in_window_match_not_the_outliers():
    s = run([R_EVIL], [ex(events=[evil(-60, 1), evil(-2, 2), evil(9, 3), evil(500, 4)])]).executions[0]
    assert s.status == DETECTED and s.ttd_seconds == 0.0 and s.out_of_window == 2
    s = run([R_EVIL], [ex(events=[evil(-60, 1), evil(9, 3), evil(500, 4)])]).executions[0]
    assert s.ttd_seconds == 9.0


def test_skew_and_window_are_configurable():
    e = ex(events=[evil(-8)])
    assert run([R_EVIL], [e]).executions[0].status == MISSED
    assert run([R_EVIL], [e], skew_seconds=10).executions[0].status == DETECTED
    late = ex(events=[evil(200)])
    assert run([R_EVIL], [late]).executions[0].status == MISSED
    assert run([R_EVIL], [late], window_seconds=300).executions[0].status == DETECTED  # run-level value applies
    assert run([R_EVIL], [ex(events=[evil(200)], window_seconds=300)]).executions[0].status == DETECTED
    # A per-execution window wins over the run-level one.
    assert run([R_EVIL], [ex(events=[evil(200)], window_seconds=60)], window_seconds=300).executions[0].status == MISSED


def test_noisy_rule_excluded_from_coverage():
    baseline = [proc(50, ts(-500), Image="C:\\benign\\evil.exe")]  # the rule fires on benign activity
    e = ex(events=[evil(4)])
    r = run([R_EVIL], [e], baseline)
    s = r.executions[0]
    assert s.status == PARTIAL and s.reason.startswith("noisy rule") and "1 baseline hits" in s.reason
    assert s.hits[0].noisy and s.hits[0].noise_hits == 1
    assert [n.rule_id for n in r.noisy_rules] == ["r-evil"]
    cov = coverage.compute_coverage(r)
    assert cov.counts[DETECTED] == 0 and cov.score == 0.0
    assert cov.noisy_rules[0]["hits"] == 1
    # The threshold is configurable: allowing one benign hit restores detected credit.
    r2 = run([R_EVIL], [e], baseline, threshold=1)
    assert r2.executions[0].status == DETECTED and not r2.noisy_rules
    # A clean rule next to the noisy one still earns the credit.
    clean = rule("r-clean", "\\u\\evil.exe", title="clean")
    s3 = run([R_EVIL, clean], [e], baseline).executions[0]
    assert s3.status == DETECTED and s3.reason.startswith("detected by clean")


def test_parent_technique_rule_is_partial():
    parent = rule("r-parent", "\\evil.exe", tags=("attack.t1569",))
    s = run([parent], [ex("T1569.002", [evil(2)])]).executions[0]
    assert s.status == PARTIAL and s.reason.startswith("parent-technique rule") and s.hits[0].relation == "parent"


def test_exact_subtechnique_id_is_detected_and_alias_is_mapped():
    exact = rule("r-exact", "\\evil.exe", tags=("attack.t1562.001",))  # SigmaHQ tag predating v19
    assert exact.techniques == ("T1685",)
    s = run([exact], [ex("T1685", [evil(2)])]).executions[0]
    assert s.status == DETECTED


def test_related_technique_is_partial():
    other = rule("r-other", "\\evil.exe", tags=("attack.t1105",))
    s = run([other], [ex("T1059.001", [evil(2)])]).executions[0]
    assert s.status == PARTIAL and s.reason.startswith("detected via related technique T1105")
    assert s.ttd_seconds == 2.0


def test_missed_and_telemetry_gap_and_untested():
    # Rule is tagged and evaluable, nothing fired: missed.
    s = run([R_EVIL], [ex(events=[proc(1, ts(1))])]).executions[0]
    assert s.status == MISSED and "none fired" in s.reason
    # No rule tagged for the technique at all: missed.
    s = run([R_EVIL], [ex("T1047", [proc(1, ts(1))])]).executions[0]
    assert s.status == MISSED and "no rule" in s.reason
    # The only tagged rule needs a Security channel the telemetry lacks: telemetry gap, not missed.
    sec = sigma.parse_rule({"title": "sec", "id": "r-sec", "tags": ["attack.t1059.001"],
                            "logsource": {"product": "windows", "service": "security"},
                            "detection": {"sel": {"EventID": 4688, "NewProcessName|endswith": "\\evil.exe"},
                                          "condition": "sel"}})
    s = run([sec], [ex(events=[proc(1, ts(1))])]).executions[0]
    assert s.status == TELEMETRY_GAP and s.gap_details and "Security" in s.reason
    # A gap rule next to an evaluable rule that did not fire is a miss.
    assert run([sec, R_EVIL], [ex(events=[proc(1, ts(1))])]).executions[0].status == MISSED
    # Untested: excluded from the denominators.
    u = Execution(technique="T1558.003", name="k", tactics=("credential-access",), anchor_ts=None,
                  untested_reason=scoring.UNTESTED_NO_EXECUTION)
    r = run([R_EVIL], [ex(events=[evil(1)]), ex("T1047", [proc(1, ts(1))]), u])
    assert r.executions[2].status == UNTESTED and r.executions[2].reason == "recorded dataset contains no execution"
    cov = coverage.compute_coverage(r)
    assert cov.counts == {"detected": 1, "partial": 0, "missed": 1, "telemetry_gap": 0, "untested": 1, "did_not_run": 0}
    assert cov.tested == 2 and cov.score == 50.0


def test_coverage_by_tactic_with_multi_tactic_technique():
    multi = Execution(technique="T1053.005", name="sched", tactics=("execution", "persistence"),
                      events=[evil(1)], anchor_ts=ANCHOR)
    miss = Execution(technique="T1547.001", name="run", tactics=("persistence",), events=[proc(1, ts(1))],
                     anchor_ts=ANCHOR)
    rl = rule("r-multi", "\\evil.exe", tags=("attack.t1053.005",))
    cov = coverage.compute_coverage(run([rl], [multi, miss]))
    by = {t.tactic: t for t in cov.tactics}
    assert by["execution"].score == 100.0 and by["execution"].tested == 1
    assert by["persistence"].score == 50.0 and by["persistence"].tested == 2
    assert cov.tested == 2 and cov.score == 50.0  # the multi-tactic technique counts once overall
    assert [t.tactic for t in cov.tactics] == ["execution", "persistence"]


def test_best_status_across_executions_of_one_technique():
    r = run([R_EVIL], [ex(events=[proc(1, ts(1))]), ex(events=[evil(3)])])
    cov = coverage.compute_coverage(r)
    assert len(cov.techniques) == 1 and cov.techniques[0].status == DETECTED and cov.techniques[0].executions == 2


def test_gaps_use_curated_hints():
    r = run([R_EVIL], [ex("T1047", [proc(1, ts(1))]), ex("T1999", [proc(1, ts(1))]), ex(events=[evil(1)])])
    gaps = coverage.compute_gaps(r)
    assert [g.technique for g in gaps] == ["T1047", "T1999"]
    assert gaps[0].hinted and "wmic" in gaps[0].rule_idea.lower() and gaps[0].kind == MISSED
    assert not gaps[1].hinted and gaps[1].telemetry_needed


def test_every_library_technique_has_a_hint():
    hints = coverage.load_gap_hints()
    ids = {t.attack_id for t in library.list_techniques()}
    assert ids <= set(hints)
    assert set(hints) <= ids
    assert all(h["telemetry_needed"] and h["rule_idea"] for h in hints.values())


def test_navigator_layer_is_valid_and_colours_by_status():
    other = rule("r-other", "\\other.exe", tags=("attack.t1105",))
    execs = [ex("T1059.001", [evil(1)]), ex("T1047", [proc(1, ts(1))]), ex("T1105", [evil(1, 2, "other.exe")]),
             Execution(technique="T1558.003", name="k", tactics=("credential-access",),
                       untested_reason=scoring.UNTESTED_NO_EXECUTION)]
    layer = navigator.build_layer(coverage.compute_coverage(run([R_EVIL, other], execs)), name="x")
    assert navigator.validate_layer(layer) == []
    assert layer["versions"] == {"attack": "20", "navigator": "5.3.2", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    by = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by["T1059.001"]["color"] == navigator.COLORS[DETECTED] and by["T1059.001"]["score"] == 100
    assert by["T1105"]["color"] == navigator.COLORS[DETECTED]
    assert by["T1047"]["color"] == navigator.COLORS[MISSED] and by["T1047"]["score"] == 0
    assert "score" not in by["T1558.003"] and by["T1558.003"]["comment"].startswith("Untested")
    assert all(t["comment"] and t["enabled"] is True and t["metadata"] for t in layer["techniques"])
    json.dumps(layer)


def test_validate_layer_rejects_bad_layers():
    good = navigator.build_layer(coverage.compute_coverage(run([R_EVIL], [ex(events=[evil(1)])])))
    assert navigator.validate_layer(good) == []

    def bad(mutate):
        layer = copy.deepcopy(good)
        mutate(layer)
        return navigator.validate_layer(layer)
    assert bad(lambda g: g.pop("name"))
    assert bad(lambda g: g.update(domain="windows"))
    assert bad(lambda g: g["versions"].update(layer="4.4"))
    assert bad(lambda g: g["versions"].pop("navigator"))
    assert bad(lambda g: g["techniques"][0].update(techniqueID="1059"))
    assert bad(lambda g: g["techniques"][0].update(color="blue"))
    assert bad(lambda g: g["techniques"][0].update(score="100"))
    assert bad(lambda g: g["techniques"][0].update(metadata=[{"name": "a"}]))
    assert bad(lambda g: g["techniques"].append(dict(g["techniques"][0])))
    assert navigator.validate_layer([]) == ["layer is not an object"]


def test_scoring_is_deterministic():
    execs = [ex(events=[evil(1), evil(8, 2)]), ex("T1047", [proc(1, ts(1))])]
    rs = [R_EVIL, rule("r-b", "\\evil.exe", tags=("attack.t1105",))]
    a = run(rs, execs, [evil(-500, 50)])
    b = run(list(reversed(rs)), execs, [evil(-500, 50)])
    assert a == b
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)
    la = navigator.build_layer(coverage.compute_coverage(a))
    assert json.dumps(la) == json.dumps(navigator.build_layer(coverage.compute_coverage(b)))


def test_invalid_settings_rejected():
    with pytest.raises(ValueError):
        run([R_EVIL], [ex()], threshold=-1)


# --- the committed rule set over the committed recordings ----------------------------------------

@pytest.fixture(scope="module")
def recorded_run():
    from pathlib import Path
    root = Path(library.DATA_DIR).parent / "rules"
    rules = sigma.load_rules(root / "sigmahq") + sigma.load_rules(root / "custom")
    return scoring.score_run(rules, scoring.recorded_executions(), scoring.recorded_baseline(),
                             sigma.recorded_profile())


def test_recorded_run_shape(recorded_run):
    assert len(recorded_run.executions) == 26
    by = {e.technique: e for e in recorded_run.executions}
    assert by["T1558.003"].status == UNTESTED
    assert by["T1558.003"].reason == "recorded dataset contains no execution"
    cov = coverage.compute_coverage(recorded_run)
    assert cov.tested == 25 and sum(cov.counts.values()) == 26
    assert cov.score == round(100 * cov.counts[DETECTED] / 25, 1)
    # TTD is measured from the command start: never negative, never beyond the window.
    for e in recorded_run.executions:
        assert e.ttd_seconds is None or 0.0 <= e.ttd_seconds <= 120.0
    assert navigator.validate_layer(navigator.build_layer(cov)) == []


def test_recorded_run_is_deterministic(recorded_run):
    from pathlib import Path
    root = Path(library.DATA_DIR).parent / "rules"
    rules = sigma.load_rules(root / "custom") + sigma.load_rules(root / "sigmahq")
    again = scoring.score_run(rules, scoring.recorded_executions(), scoring.recorded_baseline(),
                              sigma.recorded_profile())
    assert again == recorded_run


def test_untagged_rule_earns_no_credit():
    untagged = rule("r-untagged", "\\evil.exe", tags=())
    assert untagged.techniques == ()
    s = run([untagged], [ex(events=[evil(2)])]).executions[0]
    assert s.status == MISSED
    assert s.hits and s.hits[0].relation == "none" and s.hits[0].rule_id == "r-untagged"  # still listed
    # Next to a tagged rule it neither adds credit nor appears in the reason.
    s2 = run([untagged, R_EVIL], [ex(events=[evil(2)])]).executions[0]
    assert s2.status == DETECTED and "r-untagged" not in s2.reason
    # A noisy untagged rule does not produce a "noisy rule" partial either.
    base = [proc(50, ts(-500), Image="C:\\benign\\evil.exe")]
    assert run([untagged], [ex(events=[evil(2)])], base).executions[0].status == MISSED


def test_suppressed_noisy_exact_rule_is_noted():
    base = [proc(50, ts(-500), Image="C:\\benign\\evil.exe")]
    clean = rule("r-clean", "\\u\\evil.exe", title="clean")
    s = run([R_EVIL, clean], [ex(events=[evil(2)])], base).executions[0]
    assert s.status == DETECTED and "earned no credit" in s.reason and "r-evil" in s.reason


def test_navigator_metadata_names_rule_author():
    from purplebench import rulesets
    rule = next(r for r in rulesets.load_all_rules().values() if r.author)
    cov = coverage.Coverage(
        techniques=(coverage.TechniqueCoverage("T1003.001", "x", ("credential-access",), "detected", "r", 1, 0.0, (rule.id,)),),
        tactics=(), counts={}, tested=1, score=100.0, partial_score=100.0)
    layer = navigator.build_layer(cov)
    value = next(m["value"] for m in layer["techniques"][0]["metadata"] if "rules" in m["name"])
    assert value == f"{rule.title} ({rule.author})"
    assert navigator.validate_layer(layer) == []
