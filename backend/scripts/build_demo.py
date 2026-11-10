"""Build backend/data/demo_fixture.json, the recorded-mode demo exercise.

Four runs over six weeks, two campaigns, rule set versions v1 to v4. Every number in the fixture is produced
by the real Sigma evaluator and scoring code over the committed recorded telemetry (Splunk attack_data
subsets); nothing is typed in by hand except the campaign definitions, the run schedule and the rule set
membership in ``purplebench/rulesets.py``. Nothing was executed anywhere: this is recorded mode.

Deterministic: running it twice gives identical output, and a test checks that the committed fixture equals
a fresh build. Dates are relative to the fixed anchor date below.

    python scripts/build_demo.py            # write the fixture
    python scripts/build_demo.py --check    # exit 1 if the committed file is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from purplebench import config, library, rulesets, scoring  # noqa: E402
from purplebench.coverage import GENERIC_HINT, compute_coverage, load_gap_hints  # noqa: E402
from purplebench.sigma import EventIndex, evaluate, recorded_profile  # noqa: E402
from purplebench.telemetry import normalize_ts, parse_ts  # noqa: E402

OUT = config.DEMO_FIXTURE
ANCHOR = date(2026, 9, 28)  # a Monday; run 1. Everything else is an offset from it.

SOURCE = ("Recorded mode: Sysmon recordings from Splunk attack_data (Apache-2.0), trimmed to each test window; "
          "https://github.com/splunk/attack_data. Nothing was executed and no lab was used.")

# Campaigns partition the 26 library techniques; a technique may appear in both (T1059.001, T1003.001, T1053.005).
CAMPAIGNS = [
    {"id": 1, "name": "Initial access to credential theft",
     "description": "What an intruder does after the first foothold: run scripts and signed binaries, persist, "
                    "escalate, dump credentials, learn the host and move with stolen hashes. Kerberoasting "
                    "(T1558.003) is listed but cannot be scored: the recorded dataset holds no execution of it.",
     "techniques": ["T1059.001", "T1027", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1547.001", "T1053.005",
                    "T1548.002", "T1003.001", "T1003.002", "T1558.003", "T1033", "T1069.001", "T1550.002"]},
    {"id": 2, "name": "Ransomware precursors",
     "description": "The steps that usually come right before encryption: remote execution and services, new "
                    "accounts, tampering with Defender and logs, staging data, discovery and deleting recovery "
                    "points.",
     "techniques": ["T1059.001", "T1047", "T1569.002", "T1543.003", "T1136.001", "T1685", "T1685.005", "T1490",
                    "T1021.002", "T1560.001", "T1003.001", "T1053.005", "T1082", "T1018"]},
]

# (run id, campaign id, rule set version, days after the anchor, what the run is for)
RUNS = [
    (1, 1, "v1", 0, "Baseline: the starter rule set against the credential theft campaign."),
    (2, 2, "v2", 14, "More SigmaHQ coverage against the ransomware precursors campaign."),
    (3, 1, "v3", 28, "Re-run of the credential theft campaign with the first custom rules, to see which gaps "
                     "from run 1 closed."),
    (4, 2, "v4", 42, "Re-run of the ransomware precursors campaign with the full bundled set."),
]


# Why some gaps honestly stay open (written by hand from the recorded data; see DECISIONS.md Task 3).
OPEN_REMARKS = {
    "T1550.002": "Limit of the recorded data: the run launched mimikatz interactively with no sekurlsa::pth on "
                 "the command line, and the recording has no Security channel, so logon-based pass-the-hash "
                 "rules cannot be evaluated in recorded mode.",
    "T1569.002": "Only rules tagged with other techniques (service creation) or the parent T1569 fire; no bundled "
                 "rule is tagged T1569.002, so partial is the honest result.",
    "T1021.002": "The PsExec rule is tagged with the parent technique T1021 only and no bundled rule is tagged "
                 "T1021.002; the recording also holds just 10 events.",
}


def ts(day_offset: int, hour: int = 9) -> str:
    d = datetime(ANCHOR.year, ANCHOR.month, ANCHOR.day, hour, tzinfo=timezone.utc) + timedelta(days=day_offset)
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _end(anchor_ts: str, seconds: float) -> str:
    return normalize_ts((parse_ts(anchor_ts) + timedelta(seconds=seconds)).isoformat())


def _stem_of(rule) -> str:
    return Path(rule.path).stem


def _record_ids(rule, index: EventIndex, profile, anchor: str, skew: float, window: float) -> list[int]:
    res = evaluate(rule, index, profile)
    return [ref.record_id for ref in res.matches if -skew <= scoring.seconds_between(ref.ts, anchor) <= window]


def _gap_text(es: scoring.ExecutionScore) -> str:
    label = {"missed": "Missed", "telemetry_gap": "Telemetry gap", "partial": "Partial"}[es.status]
    return f"{label}: {es.reason}"


def _credit(es: scoring.ExecutionScore, titles: dict[str, str]) -> str:
    names = [titles[h.rule_id] for h in es.hits if h.relation == "exact" and not h.noisy]
    return ", ".join(names) if names else "no rule with exact credit"


def build() -> dict:
    all_rules = rulesets.load_all_rules()
    stems = sorted(all_rules)
    profile = recorded_profile()
    baseline = scoring.recorded_baseline()
    executions = scoring.recorded_executions()
    by_tech = {e.technique: e for e in executions}
    lib = {t.attack_id: t for t in library.list_techniques()}
    hints = load_gap_hints()
    titles = {r.id: r.title for r in all_rules.values()}

    # Rule sets.
    set_defs = {d.version: d for d in rulesets.RULESETS}
    set_ids = {d.version: i for i, d in enumerate(rulesets.RULESETS, start=1)}
    set_rules = {v: [all_rules[s] for s in rulesets.ruleset_stems(v, stems)] for v in set_defs}
    rulesets_out = []
    for d in rulesets.RULESETS:
        entries = []
        for s in rulesets.ruleset_stems(d.version, stems):
            r = all_rules[s]
            first, note = rulesets.added_in(s)
            entries.append({"rule_id": r.id, "file": Path(r.path).name, "origin": r.origin, "title": r.title,
                            "added_in": first, "note": note})
        rulesets_out.append({"id": set_ids[d.version], "version": d.version, "created_at": ts(d.offset_days, 8),
                             "rules_json_hash": rulesets.rules_hash(set_rules[d.version]), "notes": d.notes,
                             "rules": entries})

    # The same rule set scored over every execution, to describe what a later version would do for a gap.
    full = {v: {e.technique: e for e in scoring.score_run(set_rules[v], executions, baseline, profile).executions}
            for v in set_defs}

    indexes = {e.technique: EventIndex(e.events) for e in executions}
    runs_out = []
    scores: dict[int, scoring.RunScore] = {}
    for run_id, campaign_id, version, offset, purpose in RUNS:
        camp = CAMPAIGNS[campaign_id - 1]
        run_execs = [by_tech[t.attack_id] for t in library.list_techniques() if t.attack_id in camp["techniques"]]
        rs = scoring.score_run(set_rules[version], run_execs, baseline, profile)
        scores[run_id] = rs
        cov = compute_coverage(rs)
        ex_out = []
        for es, ex in zip(rs.executions, run_execs, strict=True):
            tech = lib[es.technique]
            window = ex.window_seconds if ex.window_seconds is not None else rs.window_seconds
            hits_out = []
            for h in es.hits:
                ids = _record_ids(_rule_by_id(set_rules[version], h.rule_id), indexes[es.technique], profile,
                                  ex.anchor_ts, rs.skew_seconds, window)
                if len(ids) != h.events:
                    raise RuntimeError(f"event count mismatch for {es.technique} / {h.rule_id}: "
                                       f"{len(ids)} record ids but the score counted {h.events}")
                hits_out.append({"rule_id": h.rule_id, "first_ts": h.first_ts, "count": h.events,
                                 "relation": h.relation, "noisy": h.noisy, "noise_hits": h.noise_hits,
                                 "record_ids": ids})
            ex_out.append({
                "technique_id": es.technique, "name": es.name, "tactics": list(es.tactics),
                "test_guid": tech.atomic.guid if tech.atomic else None,
                "started_at": es.anchor_ts, "ended_at": _end(es.anchor_ts, window) if es.anchor_ts else None,
                "status": es.status,
                "ttd_ms": None if es.ttd_seconds is None else round(es.ttd_seconds * 1000),
                "events_ref": tech.telemetry, "reason": es.reason, "hits": hits_out,
            })
        runs_out.append({
            "id": run_id, "campaign_id": campaign_id, "ruleset_id": set_ids[version], "mode": "recorded",
            "source": SOURCE, "started_at": ts(offset), "notes": purpose,
            "summary": {"counts": cov.counts, "tested": cov.tested, "score": cov.score,
                        "partial_score": cov.partial_score},
            "executions": ex_out,
            "rule_noise": [{"rule_id": n.rule_id, "status": n.status, "hits": n.hits, "noisy": n.noisy}
                           for n in rs.rule_noise],
            "gaps": [],
        })

    # Gaps: one per missed / telemetry-gap / partial execution; closed when a later run of the same campaign
    # detects the technique.
    for i, (run_id, campaign_id, version, _, _) in enumerate(RUNS):
        later = [r for r in RUNS[i + 1:] if r[1] == campaign_id]
        for es in scores[run_id].executions:
            if es.status not in ("missed", "telemetry_gap", "partial"):
                continue
            hint = hints.get(es.technique) or GENERIC_HINT
            notes, status, closed_in = _gap_text(es).rstrip(".") + ".", "open", None
            if later:
                nxt = next((e for e in scores[later[0][0]].executions if e.technique == es.technique))
                if nxt.status == "detected":
                    status, closed_in = "closed", later[0][0]
                    notes += (f" Closed in run {later[0][0]} (rule set {later[0][2]}): "
                              f"{_credit(nxt, titles)}.")
                else:
                    notes += (f" Still open in run {later[0][0]} (rule set {later[0][2]}): "
                              f"{nxt.status.replace('_', ' ')}.")
            else:
                newer = next((v for v in set_defs if int(v[1:]) > int(version[1:])
                              and full[v][es.technique].status == "detected"), None)
                if newer:
                    notes += (f" Not re-run yet: rule set {newer} detects this on the same recorded telemetry "
                              f"({_credit(full[newer][es.technique], titles)}); re-run the campaign to confirm.")
                else:
                    notes += " No bundled rule set detects this."
            if status == "open" and es.technique in OPEN_REMARKS:
                notes += " " + OPEN_REMARKS[es.technique]
            next(r for r in runs_out if r["id"] == run_id)["gaps"].append({
                "technique_id": es.technique, "kind": es.status, "notes": notes, "status": status,
                "telemetry_needed": hint["telemetry_needed"], "rule_idea": hint["rule_idea"],
                "closed_in_run": closed_in})

    return {
        "meta": {
            "anchor_date": ANCHOR.isoformat(), "mode": "recorded",
            "dataset": {"name": "Splunk attack_data", "license": "Apache-2.0",
                        "url": "https://github.com/splunk/attack_data"},
            "generator": "backend/scripts/build_demo.py",
            "note": "Computed by the real evaluator at build time. Run timestamps are demo dates; execution "
                    "timestamps are those of the original recordings.",
            "progression": _progression(full, executions),
        },
        "campaigns": CAMPAIGNS,
        "rulesets": rulesets_out,
        "runs": runs_out,
    }


def _rule_by_id(rules, rule_id):
    return next(r for r in rules if r.id == rule_id)


def _progression(full: dict, executions: list) -> list[dict]:
    """Coverage of each rule set over each campaign and over all techniques (detected / tested, percent)."""
    out = []
    for v, per_tech in full.items():
        row = {"version": v}
        sets = {"all": [e.technique for e in executions]} | {c["name"]: c["techniques"] for c in CAMPAIGNS}
        for name, techs in sets.items():
            sel = [per_tech[t] for t in techs]
            tested = sum(1 for e in sel if e.status not in ("untested", "did_not_run"))
            det = sum(1 for e in sel if e.status == "detected")
            row[name] = {"detected": det, "tested": tested, "score": round(100.0 * det / tested, 1)}
        out.append(row)
    return out


def render() -> str:
    return json.dumps(build(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed fixture is stale")
    args = parser.parse_args()
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8").replace("\r\n", "\n") if OUT.exists() else ""
        if current != text:
            print("demo_fixture.json is out of date; run scripts/build_demo.py", file=sys.stderr)
            return 1
        return 0
    with open(OUT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
