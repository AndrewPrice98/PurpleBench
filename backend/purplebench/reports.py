"""Purple-team exercise reports (Markdown and self-contained HTML) for one run.

Both formats are rendered from one small document model, so they carry the same content, and the numbers come
from :func:`coverage.compute_coverage` (the same code as the API), not from a second implementation. They are
deterministic: ``now`` is passed in (never read from the clock) and every list is sorted.

Every value that comes from the database (campaign name, notes, rule titles, reasons, hints) is untrusted.
HTML output escapes it with ``html.escape`` and has no scripts and no external resources. Markdown output
escapes untrusted values only (HTML entities, Markdown punctuation, autolinks, mentions, emoji codes, list
markers); fixed text wrapped in :class:`Trusted` is emitted as written so attribution URLs stay readable.
Control and format characters (including bidi overrides) are stripped from all text.
"""

from __future__ import annotations

import html
import re
import sqlite3
import unicodedata
from datetime import datetime, timezone
from typing import Any

from . import db, library, rulesets
from .attribution import ATTACK_NOTICE, ATTACK_TERMS_URL
from .coverage import GENERIC_HINT, best_execution, compute_coverage, load_gap_hints
from .scoring import (DETECTED, DID_NOT_RUN, MISSED, NOT_TESTED, PARTIAL, TELEMETRY_GAP, UNTESTED,
                      ExecutionScore, RuleHit, RunScore)

STATUS_LABELS = {DETECTED: "Detected", PARTIAL: "Partial", MISSED: "Missed", TELEMETRY_GAP: "Telemetry gap",
                 UNTESTED: "Untested", DID_NOT_RUN: "Did not run"}


class Trusted(str):
    """Fixed text written by this module (or a committed URL): emitted unescaped in Markdown."""


class Parts(tuple):
    """Trusted and untrusted pieces of one text, escaped piece by piece."""


def T(text: str) -> Trusted:
    return Trusted(text)


def L(label: str, *values: Any) -> Parts:
    """A fixed label followed by untrusted values."""
    return Parts((Trusted(label), *values))


MISSED_MEANING = T('"Missed" means that no rule in this rule set earned credit on this telemetry. It says nothing about '
                   "any product's coverage.")
RECORDED_NOTE = T("Recorded mode: nothing was executed and no lab was used. Each technique was scored by running the "
                  "rule set over a trimmed Sysmon recording from the dataset named below.")
RECORDED_LIMITS = T("Limitations: the recordings contain Sysmon events only (no Security log, no PowerShell script "
                    "block logging, no EDR telemetry), so techniques that need other sources show as missed or as "
                    "telemetry gaps. The rule set was written against these same recordings, so its coverage here is "
                    "a best case on known telemetry, not a prediction for unseen attacks.")
TTD_NOTE = T('"Event-time to first match" is measured on event timestamps from the anchor events of the test window. '
             "In recorded mode the anchors are the attack's own events, so it is close to zero and is not a "
             "detection latency.")
LAB_NOTE = T("Lab mode: not yet run against a real lab. This report is not yet validated against a real lab.")
LAB_LIMITS = T("This result comes from a run file written by the PurpleBench lab runner and is only as good as the "
               "lab that produced it. No benign baseline is collected in lab mode, so rule noise is not measured.")

ATTRIBUTION = (
    T("SigmaHQ rules: Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License . "
      "Rules come from https://github.com/SigmaHQ/sigma ; each rule's author, id and license fields are kept "
      "unchanged and the author is shown with every rule. PurpleBench's own custom rules are also DRL 1.1. "
      "Rules are provided as is, without warranty."),
    T("Atomic Red Team test metadata: MIT, Copyright (c) 2018 Red Canary, Inc., "
      "https://github.com/redcanaryco/atomic-red-team . Test names, GUIDs and descriptions."),
    T("Splunk attack_data recorded telemetry: Apache License 2.0, https://github.com/splunk/attack_data . "
      "Trimmed, normalised subsets of Windows Sysmon logs."),
    T("MITRE ATT&CK: technique and tactic ids and names are ATT&CK Enterprise v20, used under the ATT&CK Terms of "
      f"Use ({ATTACK_TERMS_URL} ). {ATTACK_NOTICE}"),
)

_ISO = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]{8,15}Z?$")
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_HOST = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def _clean(value: Any) -> str:
    """Text on one line without control or format characters (bidi overrides, zero-width, ...). None is blank."""
    if value is None:
        return ""
    text = " ".join(str(value).split())
    return "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf"))


def _safe(value: Any, pattern: re.Pattern) -> Any:
    """Mark a value that matches a strict pattern (timestamp, ATT&CK id, UUID) as trusted."""
    text = _clean(value)
    return Trusted(text) if pattern.match(text) else text


def _status(s: str) -> Any:
    return T(STATUS_LABELS[s]) if s in STATUS_LABELS else _clean(s)


def _fmt_ts(value: Any) -> Any:
    if isinstance(value, datetime):
        moment = value.astimezone(timezone.utc) if value.tzinfo else value
        return T(moment.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return _safe(value, _ISO)


def _ttd(seconds: float | None) -> Any:
    return T("-") if seconds is None else T(f"{seconds:.1f} s")


def _pct(v: float | None) -> Any:
    return T("n/a") if v is None else T(f"{v:.1f}%")


def _tech_info(tid: str) -> tuple[str, tuple[str, ...]]:
    t = library.get_technique(tid)
    return (t.name, t.tactics) if t else ("(not in the technique library)", ())


def _run_score(conn: sqlite3.Connection, run_id: int) -> tuple[RunScore, dict[int, dict]]:
    """Rebuild a :class:`RunScore` from the stored executions so coverage is computed by the shared code.
    Returns it with a map from each ExecutionScore (by identity) to its execution row."""
    scores, rows = [], {}
    for ex in db.list_executions(conn, run_id):
        name, tactics = _tech_info(ex["technique_id"])
        hits = tuple(
            RuleHit(rule_id=h["rule_id"], title=h["title"] or h["rule_id"], techniques=(), relation=h["relation"],
                    noisy=h["noisy"], noise_hits=h["noise_hits"], events=h["count"], first_ts=h["first_ts"],
                    ttd_seconds=0.0) for h in db.list_hits(conn, ex["id"]))
        es = ExecutionScore(
            technique=ex["technique_id"], name=name, tactics=tactics, status=ex["status"], reason=ex["reason"],
            atomic_test=ex["test_guid"], anchor_ts=ex["started_at"], hits=hits,
            ttd_seconds=None if ex["ttd_ms"] is None else ex["ttd_ms"] / 1000.0, out_of_window=0, tagged_rules=0)
        scores.append(es)
        rows[id(es)] = ex
    return RunScore(tuple(scores), (), 0, 0.0, 0.0), rows


def _best_rows(score: RunScore, rows: dict[int, dict]) -> dict[str, dict]:
    by: dict[str, list[ExecutionScore]] = {}
    for e in score.executions:
        by.setdefault(e.technique, []).append(e)
    return {tid: rows[id(best_execution(group))] for tid, group in by.items()}


def _rule_label(title: str | None, rule_id: str, attribution: dict[str, dict[str, str]]) -> Parts:
    author = attribution.get(rule_id, {}).get("author") or ""
    return Parts((title or rule_id, T(" (author: "), author or "unknown", T(")")))


def _build(conn: sqlite3.Connection, run_id: int, now: Any) -> tuple[Any, list[tuple]]:
    run = db.get_run(conn, run_id)
    if run is None:
        raise KeyError(f"no run {run_id}")
    campaign = db.get_campaign(conn, run["campaign_id"]) or {"name": "", "description": "", "techniques": []}
    ruleset = db.get_ruleset(conn, run["ruleset_id"]) or {"rules": [], "version": run["ruleset_version"],
                                                           "created_at": "", "notes": "", "rules_json_hash": ""}
    score, rowmap = _run_score(conn, run_id)
    cov = compute_coverage(score)
    best = _best_rows(score, rowmap)
    counts = cov.counts
    attribution = rulesets.rule_attribution()
    recorded = run["mode"] == "recorded"
    rules = ruleset["rules"]
    n_sigma = sum(1 for r in rules if r["origin"] == "sigmahq")
    n_custom = sum(1 for r in rules if r["origin"] == "custom")
    title = Parts((T("PurpleBench exercise report: "), run["campaign_name"], T(f" (run {run_id})")))
    B: list[tuple] = [("h1", title),
                      ("p", Parts((T("Generated "), _fmt_ts(now), T(". Mode: "), run["mode"], T("."))))]

    # 1. scope
    B.append(("h2", T("1. Scope")))
    ctechs = sorted(campaign["techniques"])
    B.append(("ul", [
        L("Campaign: ", campaign["name"]),
        L("Description: ", _clean(campaign["description"]) or T("-")),
        L(f"Campaign techniques: {len(ctechs)} (", ", ".join(_clean(t) for t in ctechs) or "-", T(")")),
        L(f"Run: {run_id}, started ", _fmt_ts(run["started_at"])),
        L("Run notes: ", _clean(run["notes"]) or T("-")),
        L("Rule set version: ", ruleset["version"], T(f" ({len(rules)} rules: {n_sigma} SigmaHQ, {n_custom} custom)")),
        T(f"Techniques tested: {cov.tested}; detected {counts[DETECTED]}, partial {counts[PARTIAL]}, "
          f"missed {counts[MISSED]}, telemetry gap {counts[TELEMETRY_GAP]}"),
        L("Coverage score (detected / tested): ", _pct(cov.score)),
        T(f"Untested {counts[UNTESTED]} and did not run {counts[DID_NOT_RUN]}: excluded from the score"),
    ]))
    B.append(("note", MISSED_MEANING))

    # 2. environment and mode
    B.append(("h2", T("2. Environment and mode")))
    if recorded:
        names: dict[str, str] = {}
        for tid in sorted(best):
            t = library.get_technique(tid)
            if t and t.dataset.get("name"):
                names[t.dataset["name"]] = t.dataset.get("url", "")
        B.append(("p", RECORDED_NOTE))
        B.append(("p", _clean(run["source"])))
        B.append(("table", [T("Dataset"), T("Link"), T("Licence")],
                  [[n, T(u) if u.startswith("https://github.com/splunk/attack_data/") else u, T("Apache-2.0")]
                   for n, u in sorted(names.items())]))
        B.append(("p", RECORDED_LIMITS))
    else:
        m = re.match(r"Lab run on (\S+)", run["source"] or "")
        host = m.group(1) if m and _HOST.match(m.group(1)) else None
        B.append(("p", LAB_NOTE))
        B.append(("ul", [L("Target host: ", host or T("(not recorded)")), L("Source: ", _clean(run["source"]))]))
        B.append(("p", LAB_LIMITS))
    B.append(("p", TTD_NOTE))

    # 3. techniques by tactic
    B.append(("h2", T("3. Techniques tested by tactic")))
    rows = []
    for tac in cov.tactics:
        tids = sorted(t.technique for t in cov.techniques if tac.tactic in t.tactics)
        rows.append([T(tac.name), ", ".join(tids), T(str(tac.tested)), T(str(tac.counts[DETECTED])), _pct(tac.score)])
    B.append(("table", [T(h) for h in ("Tactic", "Techniques", "Tested", "Detected", "Score")], rows))

    # 4. results
    B.append(("h2", T("4. Results")))
    rows = []
    for tid in sorted(best):
        e = best[tid]
        hits = db.list_hits(conn, e["id"])
        fired: list[Any] = []
        for h in sorted(hits, key=lambda h: (h["noisy"], h["rule_id"])):
            if fired:
                fired.append(T("; "))
            fired.extend(_rule_label(h["title"], h["rule_id"], attribution))
            fired.append(T(f" ({h['relation']}{', noisy, no credit' if h['noisy'] else ''})"))
        rows.append([_safe(tid, _TID), _tech_info(tid)[0], _status(e["status"]), Parts(fired) if fired else T("-"),
                     _ttd(None if e["ttd_ms"] is None else e["ttd_ms"] / 1000.0), e["reason"]])
    B.append(("table", [T(h) for h in ("Technique", "Name", "Status", "Rules fired (relation)",
                                       "Event-time to first match", "Reason")], rows))

    # 5. change
    B.append(("h2", T("5. Coverage change")))
    key = (run["started_at"], run_id)
    same = [r for r in db.list_runs(conn, run["campaign_id"]) if (r["started_at"], r["id"]) < key]
    prev, same_campaign = (same[-1], True) if same else (None, False)
    if prev is None:
        anyprev = [r for r in db.list_runs(conn) if (r["started_at"], r["id"]) < key]
        prev = anyprev[-1] if anyprev else None
    if prev is None:
        B.append(("p", T("No previous run to compare with.")))
    else:
        pscore, _ = _run_score(conn, prev["id"])
        pcov = compute_coverage(pscore)
        delta = None if cov.score is None or pcov.score is None else round(cov.score - pcov.score, 1)
        when = (T(f"run {prev['id']}"), T(" (rule set "), prev["ruleset_version"], T(", "),
                _fmt_ts(prev["started_at"]), T(")"))
        if same_campaign:
            B.append(("p", Parts((T("Compared with "), *when, T(" of the same campaign.")))))
        else:
            B.append(("p", Parts((T("No earlier run of this campaign. Compared with "), *when,
                                  T(" of a different campaign, "), prev["campaign_name"],
                                  T("; the technique sets differ, so only the score is comparable and no "
                                    "per-technique changes are shown.")))))
        B.append(("ul", [L("Score: ", _pct(pcov.score), T(" before, "), _pct(cov.score), T(" now"),
                           T("" if delta is None else f" ({delta:+.1f} points)"))]))
        if same_campaign:
            before = {t.technique: t.status for t in pcov.techniques}
            after = {t.technique: t.status for t in cov.techniques}
            rows = [[_safe(tid, _TID), _tech_info(tid)[0], _status(before[tid]) if tid in before else T("-"),
                     _status(after[tid]) if tid in after else T("-")]
                    for tid in sorted(set(before) | set(after)) if before.get(tid) != after.get(tid)]
            if rows:
                B.append(("table", [T(h) for h in ("Technique", "Name", "Before", "Now")], rows))
            else:
                B.append(("p", T("No technique changed status.")))

    # 6. gaps
    B.append(("h2", T("6. Gaps and recommendations")))
    hints = load_gap_hints()
    gaps = sorted(db.list_gaps(conn, run_id), key=lambda g: (g["technique_id"], g["kind"], g["id"]))
    if not gaps:
        B.append(("p", T("No gaps recorded for this run.")))
    else:
        rows = []
        for g in gaps:
            h = hints.get(g["technique_id"], GENERIC_HINT)
            state = (T(f"closed in run {g['closed_in_run']}") if g["status"] == "closed" and g["closed_in_run"]
                     else _clean(g["status"]))
            rows.append([_safe(g["technique_id"], _TID), _tech_info(g["technique_id"])[0], _status(g["kind"]), state,
                         g["notes"] + (f" Analyst notes: {g['analyst_notes']}" if g.get("analyst_notes") else ""),
                         g["telemetry_needed"] or h["telemetry_needed"], g["rule_idea"] or h["rule_idea"]])
        B.append(("table", [T(x) for x in ("Technique", "Name", "Kind", "State", "Notes", "Telemetry needed",
                                           "Rule idea")], rows))

    # 7. noisy rules
    B.append(("h2", T("7. Noisy rules")))
    if recorded:
        B.append(("p", T("Noise is the number of events a rule matches in the benign baseline that accompanies the "
                         "recordings. A noisy rule earns no detection credit.")))
        noisy = [n for n in db.list_rule_noise(conn, run_id) if n["noisy"]]
        if noisy:
            B.append(("table", [T("Rule (author)"), T("Source"), T("Baseline hits")],
                      [[_rule_label(n["title"], n["rule_id"], attribution), n["origin"] or T("-"), T(str(n["hits"]))]
                       for n in sorted(noisy, key=lambda n: (-n["hits"], n["rule_id"]))]))
        else:
            B.append(("p", T("No rule was noisy on the baseline.")))
    else:
        B.append(("p", T("Rule noise was not measured for this run (no benign baseline in lab mode).")))

    # 8. not tested
    B.append(("h2", T("8. Untested and did not run")))
    skipped = [(tid, best[tid]) for tid in sorted(best) if best[tid]["status"] in NOT_TESTED]
    if skipped:
        B.append(("p", T("These techniques are excluded from the score.")))
        B.append(("table", [T(x) for x in ("Technique", "Name", "Status", "Reason")],
                  [[_safe(tid, _TID), _tech_info(tid)[0], _status(e["status"]), e["reason"]] for tid, e in skipped]))
    else:
        B.append(("p", T("None.")))

    # appendix
    B.append(("h2", T("Appendix A. Rule set")))
    B.append(("p", L("Version ", ruleset["version"], T(", created "), _fmt_ts(ruleset["created_at"]),
                     T(", content hash "), ruleset["rules_json_hash"], T("."))))
    arows = []
    for r in sorted(rules, key=lambda r: (r["title"], r["rule_id"])):
        a = attribution.get(r["rule_id"], {})
        url = a.get("url", "")
        where: Any = a.get("file", "") or r["rule_file"]
        if url.startswith("https://github.com/SigmaHQ/sigma/blob/"):
            where = T(url)
        arows.append([_safe(r["rule_id"], _UUID), r["title"], a.get("author") or T("unknown"),
                      T("SigmaHQ") if r["origin"] == "sigmahq" else T("Custom (PurpleBench)"),
                      a.get("license") or T("DRL 1.1"), where])
    B.append(("table", [T(x) for x in ("Rule id", "Title", "Author", "Source", "Licence", "Rule file")], arows))
    B.append(("h2", T("Appendix B. Attribution")))
    B.append(("ul", list(ATTRIBUTION)))
    return title, B


# -- renderers --------------------------------------------------------------------------------------

_MD_PUNCT = re.compile(r"([\\`*_{}\[\]()#+!|~])|^(-)")
_MD_ORDERED = re.compile(r"^(\d+)([.)])")
_MD_WWW = re.compile(r"(?i)www\.")


def _md_text(value: Any) -> str:
    """Untrusted text for Markdown: HTML-escape, then neutralise anything a renderer would turn into markup:
    punctuation, ordered-list markers, autolinks (``://``, ``www.``), mentions and emoji codes (``@``, ``:``)."""
    text = html.escape(_clean(value), quote=False)
    text = _MD_PUNCT.sub(lambda m: "\\" + (m.group(1) or m.group(2)), text)
    text = _MD_ORDERED.sub(lambda m: m.group(1) + "\\" + m.group(2), text)
    text = _MD_WWW.sub(lambda m: m.group(0)[:3] + "&#46;", text)
    return text.replace("@", "&#64;").replace(":", "&#58;")


def _md(value: Any) -> str:
    if isinstance(value, Trusted):
        return str(value)
    if isinstance(value, Parts):
        return "".join(_md(p) for p in value)
    return _md_text(value)


def _plain(value: Any) -> str:
    """Flatten for HTML (which escapes everything)."""
    if isinstance(value, Trusted):
        return str(value)
    if isinstance(value, Parts):
        return "".join(_plain(p) for p in value)
    return _clean(value)


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


def render_html(title: Any, blocks: list[tuple]) -> str:
    def e(v: Any) -> str:
        return html.escape(_plain(v), quote=True)

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
