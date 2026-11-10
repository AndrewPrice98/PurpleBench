"""Purple-team exercise reports (Markdown and self-contained HTML) for one run.

Both formats are rendered from one small document model, so they carry the same content. They are
deterministic: ``now`` is passed in (never read from the clock) and every list is sorted. Every value that
comes from the database (campaign name, notes, rule titles, reasons, hints) is untrusted: the HTML output
escapes it with ``html.escape`` and has no scripts and no external resources; the Markdown output
HTML-escapes it and then backslash-escapes Markdown punctuation.
"""

from __future__ import annotations

import html
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import db, library
from .coverage import GENERIC_HINT, load_gap_hints
from .scoring import DETECTED, DID_NOT_RUN, MISSED, NOT_TESTED, PARTIAL, STATUSES, TELEMETRY_GAP, UNTESTED

STATUS_LABELS = {DETECTED: "Detected", PARTIAL: "Partial", MISSED: "Missed", TELEMETRY_GAP: "Telemetry gap",
                 UNTESTED: "Untested", DID_NOT_RUN: "Did not run"}
_BEST = (DETECTED, PARTIAL, MISSED, TELEMETRY_GAP, DID_NOT_RUN, UNTESTED)

MISSED_MEANING = ('"Missed" means that no rule in this rule set fired on this telemetry. It says nothing about '
                  "any product's coverage.")
RECORDED_NOTE = ("Recorded mode: nothing was executed and no lab was used. Each technique was scored by running the "
                 "rule set over a trimmed Sysmon recording from the dataset named below.")
RECORDED_LIMITS = ("Limitations: the recordings contain Sysmon events only (no Security log, no PowerShell script "
                   "block logging, no EDR telemetry), so techniques that need other sources show as missed or as "
                   "telemetry gaps. The rule set was written against these same recordings, so its coverage here is "
                   "a best case on known telemetry, not a prediction for unseen attacks.")
TTD_NOTE = ('"Event-time to first match" is measured on event timestamps from the anchor events of the test window. '
            "In recorded mode the anchors are the attack's own events, so it is close to zero and is not a "
            "detection latency.")
LAB_NOTE = "Lab mode: not yet run against a real lab. This report is not yet validated against a real lab."
LAB_LIMITS = ("This result comes from a run file written by the PurpleBench lab runner and is only as good as the lab "
              "that produced it. No benign baseline is collected in lab mode, so rule noise is not measured.")

ATTRIBUTION = (
    ("SigmaHQ rules", "Detection Rule License (DRL) 1.1", "https://github.com/SigmaHQ/sigma",
     "Rule author, id and license fields are kept unchanged. PurpleBench's own custom rules are also DRL 1.1."),
    ("Atomic Red Team test metadata", "MIT, Copyright (c) 2018 Red Canary, Inc.",
     "https://github.com/redcanaryco/atomic-red-team", "Test names, GUIDs and descriptions."),
    ("Splunk attack_data recorded telemetry", "Apache License 2.0", "https://github.com/splunk/attack_data",
     "Trimmed, normalised subsets of Windows Sysmon logs."),
)


# -- document model -------------------------------------------------------------------------------
# blocks: ("h1"|"h2"|"p"|"note", text) | ("ul", [text]) | ("table", headers, rows)

def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def _status(s: str) -> str:
    return STATUS_LABELS.get(s, s)


def _fmt_ts(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo:
            return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return value.strftime("%Y-%m-%dT%H:%M:%S")
    return _one_line(value)


def _ttd(ms: int | None) -> str:
    return "-" if ms is None else f"{ms / 1000:.1f} s"


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.1f}%"


def _best_executions(execs: list[dict]) -> dict[str, dict]:
    """The best execution per technique: best status, then lowest time to first match."""
    by: dict[str, list[dict]] = {}
    for e in execs:
        by.setdefault(e["technique_id"], []).append(e)
    return {tid: min(group, key=lambda e: (_BEST.index(e["status"]),
                                           e["ttd_ms"] if e["ttd_ms"] is not None else 1 << 60, e["id"]))
            for tid, group in by.items()}


def _tech_info(tid: str) -> tuple[str, tuple[str, ...]]:
    t = library.get_technique(tid)
    return (t.name, t.tactics) if t else ("(not in the technique library)", ())


def _scores(best: dict[str, dict]) -> dict[str, Any]:
    counts = {s: 0 for s in STATUSES}
    for e in best.values():
        counts[e["status"]] += 1
    tested = sum(v for k, v in counts.items() if k not in NOT_TESTED)
    score = round(100.0 * counts[DETECTED] / tested, 1) if tested else None
    return {"counts": counts, "tested": tested, "score": score}


def _build(conn: sqlite3.Connection, run_id: int, now: Any) -> tuple[str, list[tuple]]:
    run = db.get_run(conn, run_id)
    if run is None:
        raise KeyError(f"no run {run_id}")
    campaign = db.get_campaign(conn, run["campaign_id"]) or {"name": "", "description": "", "techniques": []}
    ruleset = db.get_ruleset(conn, run["ruleset_id"]) or {"rules": [], "version": run["ruleset_version"],
                                                           "created_at": "", "notes": "", "rules_json_hash": ""}
    execs = db.list_executions(conn, run_id)
    best = _best_executions(execs)
    summary = _scores(best)
    counts = summary["counts"]
    recorded = run["mode"] == "recorded"
    rules = ruleset["rules"]
    n_sigma = sum(1 for r in rules if r["origin"] == "sigmahq")
    n_custom = sum(1 for r in rules if r["origin"] == "custom")
    title = f"PurpleBench exercise report: {_one_line(run['campaign_name'])} (run {run_id})"
    B: list[tuple] = [("h1", title), ("p", f"Generated {_fmt_ts(now)}. Mode: {run['mode']}.")]

    # 1. scope
    B.append(("h2", "1. Scope"))
    B.append(("ul", [
        f"Campaign: {_one_line(campaign['name'])}",
        f"Description: {_one_line(campaign['description']) or '-'}",
        f"Campaign techniques: {len(campaign['techniques'])} ({', '.join(sorted(campaign['techniques'])) or '-'})",
        f"Run: {run_id}, started {_one_line(run['started_at'])}",
        f"Run notes: {_one_line(run['notes']) or '-'}",
        f"Rule set version: {_one_line(ruleset['version'])} ({len(rules)} rules: {n_sigma} SigmaHQ, {n_custom} custom)",
        f"Techniques tested: {summary['tested']}; detected {counts[DETECTED]}, partial {counts[PARTIAL]}, "
        f"missed {counts[MISSED]}, telemetry gap {counts[TELEMETRY_GAP]}",
        f"Coverage score (detected / tested): {_pct(summary['score'])}",
        f"Untested {counts[UNTESTED]} and did not run {counts[DID_NOT_RUN]}: excluded from the score",
    ]))
    B.append(("note", MISSED_MEANING))

    # 2. environment and mode
    B.append(("h2", "2. Environment and mode"))
    if recorded:
        names: dict[str, str] = {}
        for tid in sorted(best):
            t = library.get_technique(tid)
            if t and t.dataset.get("name"):
                names[t.dataset["name"]] = t.dataset.get("url", "")
        B.append(("p", RECORDED_NOTE))
        B.append(("p", _one_line(run["source"])))
        B.append(("table", ["Dataset", "Link", "Licence"],
                  [[n, u, "Apache-2.0"] for n, u in sorted(names.items())]))
        B.append(("p", RECORDED_LIMITS))
    else:
        m = re.match(r"Lab run on (\S+)", run["source"])
        B.append(("p", LAB_NOTE))
        B.append(("ul", [f"Target host: {_one_line(m.group(1)) if m else '(not recorded)'}",
                         f"Source: {_one_line(run['source'])}"]))
        B.append(("p", LAB_LIMITS))
    B.append(("p", TTD_NOTE))

    # 3. techniques by tactic
    B.append(("h2", "3. Techniques tested by tactic"))
    by_tactic: dict[str, list[str]] = {}
    for tid in sorted(best):
        for tac in _tech_info(tid)[1] or ("unknown",):
            by_tactic.setdefault(tac, []).append(tid)
    order = list(library.TACTICS) + ["unknown"]
    rows = []
    for tac in sorted(by_tactic, key=lambda x: order.index(x) if x in order else 99):
        tids = by_tactic[tac]
        c = {s: sum(1 for t in tids if best[t]["status"] == s) for s in STATUSES}
        tested = sum(v for k, v in c.items() if k not in NOT_TESTED)
        rows.append([library.TACTICS.get(tac, tac), ", ".join(tids), str(tested), str(c[DETECTED]),
                     _pct(round(100.0 * c[DETECTED] / tested, 1) if tested else None)])
    B.append(("table", ["Tactic", "Techniques", "Tested", "Detected", "Score"], rows))

    # 4. results
    B.append(("h2", "4. Results"))
    rows = []
    for tid in sorted(best):
        e = best[tid]
        hits = db.list_hits(conn, e["id"])
        fired = "; ".join(f"{h['title'] or h['rule_id']} ({h['relation']}{', noisy, no credit' if h['noisy'] else ''})"
                          for h in sorted(hits, key=lambda h: (h["noisy"], h["rule_id"]))) or "-"
        rows.append([tid, _tech_info(tid)[0], _status(e["status"]), fired, _ttd(e["ttd_ms"]), e["reason"]])
    B.append(("table", ["Technique", "Name", "Status", "Rules fired (relation)", "Event-time to first match", "Reason"],
              rows))

    # 5. change
    B.append(("h2", "5. Coverage change"))
    key = (run["started_at"], run_id)
    same = [r for r in db.list_runs(conn, run["campaign_id"]) if (r["started_at"], r["id"]) < key]
    prev, same_campaign = (same[-1], True) if same else (None, False)
    if prev is None:
        anyprev = [r for r in db.list_runs(conn) if (r["started_at"], r["id"]) < key]
        prev = anyprev[-1] if anyprev else None
    if prev is None:
        B.append(("p", "No previous run to compare with."))
    else:
        pbest = _best_executions(db.list_executions(conn, prev["id"]))
        psum = _scores(pbest)
        delta = (None if summary["score"] is None or psum["score"] is None
                 else round(summary["score"] - psum["score"], 1))
        if same_campaign:
            B.append(("p", f"Compared with run {prev['id']} of the same campaign (rule set "
                           f"{_one_line(prev['ruleset_version'])}, {_one_line(prev['started_at'])})."))
        else:
            B.append(("p", f"No earlier run of this campaign. Compared with run {prev['id']} of a different campaign, "
                           f"{_one_line(prev['campaign_name'])} (rule set {_one_line(prev['ruleset_version'])}, "
                           f"{_one_line(prev['started_at'])}); the technique sets differ, so only the score is "
                           "comparable and no per-technique changes are shown."))
        B.append(("ul", [f"Score: {_pct(psum['score'])} before, {_pct(summary['score'])} now"
                         + ("" if delta is None else f" ({delta:+.1f} points)")]))
        if same_campaign:
            rows = []
            for tid in sorted(set(best) | set(pbest)):
                a = pbest[tid]["status"] if tid in pbest else None
                b = best[tid]["status"] if tid in best else None
                if a != b:
                    rows.append([tid, _tech_info(tid)[0], _status(a) if a else "-", _status(b) if b else "-"])
            if rows:
                B.append(("table", ["Technique", "Name", "Before", "Now"], rows))
            else:
                B.append(("p", "No technique changed status."))

    # 6. gaps
    B.append(("h2", "6. Gaps and recommendations"))
    hints = load_gap_hints()
    gaps = sorted(db.list_gaps(conn, run_id), key=lambda g: (g["technique_id"], g["kind"], g["id"]))
    if not gaps:
        B.append(("p", "No gaps recorded for this run."))
    else:
        rows = []
        for g in gaps:
            h = hints.get(g["technique_id"], GENERIC_HINT)
            state = f"closed in run {g['closed_in_run']}" if g["status"] == "closed" and g["closed_in_run"] else g["status"]
            rows.append([g["technique_id"], _tech_info(g["technique_id"])[0], _status(g["kind"]), state,
                         g["notes"], g["telemetry_needed"] or h["telemetry_needed"], g["rule_idea"] or h["rule_idea"]])
        B.append(("table", ["Technique", "Name", "Kind", "State", "Notes", "Telemetry needed", "Rule idea"], rows))

    # 7. noisy rules
    B.append(("h2", "7. Noisy rules"))
    if recorded:
        B.append(("p", "Noise is the number of events a rule matches in the benign baseline that accompanies the "
                       "recordings. A noisy rule earns no detection credit."))
        noisy = [n for n in db.list_rule_noise(conn, run_id) if n["noisy"]]
        if noisy:
            B.append(("table", ["Rule", "Source", "Baseline hits"],
                      [[n["title"] or n["rule_id"], n["origin"] or "-", str(n["hits"])]
                       for n in sorted(noisy, key=lambda n: (-n["hits"], n["rule_id"]))]))
        else:
            B.append(("p", "No rule was noisy on the baseline."))
    else:
        B.append(("p", "Rule noise was not measured for this run (no benign baseline in lab mode)."))

    # 8. not tested
    B.append(("h2", "8. Untested and did not run"))
    skipped = [(tid, best[tid]) for tid in sorted(best) if best[tid]["status"] in NOT_TESTED]
    if skipped:
        B.append(("p", "These techniques are excluded from the score."))
        B.append(("table", ["Technique", "Name", "Status", "Reason"],
                  [[tid, _tech_info(tid)[0], _status(e["status"]), e["reason"]] for tid, e in skipped]))
    else:
        B.append(("p", "None."))

    # appendix
    B.append(("h2", "Appendix A. Rule set"))
    B.append(("p", f"Version {_one_line(ruleset['version'])}, created {_one_line(ruleset['created_at'])}, "
                   f"content hash {_one_line(ruleset['rules_json_hash'])}."))
    B.append(("table", ["Rule id", "Title", "Source", "Licence"],
              [[r["rule_id"], r["title"], "SigmaHQ" if r["origin"] == "sigmahq" else "Custom (PurpleBench)",
                "DRL 1.1"] for r in sorted(rules, key=lambda r: (r["title"], r["rule_id"]))]))
    B.append(("h2", "Appendix B. Attribution"))
    B.append(("ul", [f"{a}: {b}. {c} {d}" for a, b, c, d in ATTRIBUTION]))
    return title, B


# -- renderers --------------------------------------------------------------------------------------

_MD_PUNCT = re.compile(r"([\\`*_{}\[\]()#+!|~])|^(-)")


def _md(value: Any) -> str:
    """Untrusted text for Markdown: HTML-escape, collapse whitespace, then escape Markdown punctuation."""
    text = html.escape(_one_line(value), quote=False)
    return _MD_PUNCT.sub(lambda m: "\\" + (m.group(1) or m.group(2)), text)


def render_md(blocks: list[tuple]) -> str:
    out: list[str] = []
    for b in blocks:
        kind = b[0]
        if kind == "h1":
            out.append(f"# {_md(b[1])}\n")
        elif kind == "h2":
            out.append(f"## {_md(b[1])}\n")
        elif kind == "p":
            out.append(f"{_md(b[1])}\n")
        elif kind == "note":
            out.append(f"> {_md(b[1])}\n")
        elif kind == "ul":
            out.append("\n".join(f"- {_md(i)}" for i in b[1]) + "\n")
        elif kind == "table":
            head = "| " + " | ".join(_md(h) for h in b[1]) + " |"
            sep = "|" + "|".join(" --- " for _ in b[1]) + "|"
            rows = ["| " + " | ".join(_md(c) for c in r) + " |" for r in b[2]]
            out.append("\n".join([head, sep, *rows]) + "\n")
    return "\n".join(out)


CSS = """
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;background:#fff;max-width:1100px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.6rem;border-bottom:3px solid #7c3aed;padding-bottom:.3rem}
h2{font-size:1.2rem;margin-top:2rem;color:#5b21b6}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:13px}
th,td{border:1px solid #cbd5e1;padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#ede9fe}
.note{border-left:4px solid #7c3aed;background:#f5f3ff;padding:.5rem .8rem;margin:.8rem 0}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def render_html(title: str, blocks: list[tuple]) -> str:
    def e(v: Any) -> str:
        return html.escape(_one_line(v), quote=True)

    out = ["<!DOCTYPE html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>{e(title)}</title>", f"<style>{CSS}</style>", "</head>", "<body>"]
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2"):
            out.append(f"<{kind}>{e(b[1])}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{e(b[1])}</p>")
        elif kind == "note":
            out.append(f'<p class="note">{e(b[1])}</p>')
        elif kind == "ul":
            out.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in b[1]) + "</ul>")
        elif kind == "table":
            head = "".join(f"<th>{e(h)}</th>" for h in b[1])
            rows = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in r) + "</tr>" for r in b[2])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
    out += ["</body>", "</html>", ""]
    return "\n".join(out)


def exercise_report_md(conn: sqlite3.Connection, run_id: int, now: Any) -> str:
    return render_md(_build(conn, run_id, now)[1])


def exercise_report_html(conn: sqlite3.Connection, run_id: int, now: Any) -> bytes:
    return render_html(*_build(conn, run_id, now)).encode("utf-8")
