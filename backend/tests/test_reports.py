"""Exercise reports: structure, escaping, attribution, honesty notes and determinism."""

import re

import pytest

from purplebench import db, reports

NOW = "2026-11-10T12:00:00Z"
HOSTILE = '<script>alert(1)</script> "q" & [x](javascript:alert(1)) **b** | `c`'


@pytest.fixture
def seeded(seeded_db):
    c = db.connect(seeded_db)
    yield c
    c.close()


def _md(c, i):
    return reports.exercise_report_md(c, i, NOW)


def _html(c, i):
    return reports.exercise_report_html(c, i, NOW).decode("utf-8")


@pytest.mark.parametrize("run_id", [1, 2, 3, 4])
def test_every_demo_run_renders_in_both_formats(seeded, run_id):
    md, page = _md(seeded, run_id), _html(seeded, run_id)
    for heading in ("1. Scope", "2. Environment and mode", "3. Techniques tested by tactic", "4. Results",
                    "5. Coverage change", "6. Gaps and recommendations", "7. Noisy rules",
                    "8. Untested and did not run", "Appendix A. Rule set", "Appendix B. Attribution"):
        assert heading in md.replace("\\", "")
        assert heading in page
    assert page.startswith("<!DOCTYPE html>")


def test_html_is_self_contained_and_script_free(seeded):
    page = _html(seeded, 3).lower()
    assert "<script" not in page and "<link" not in page and "src=" not in page and "http-equiv" not in page
    assert "<style>" in page


def test_honesty_and_attribution_present(seeded):
    page = _html(seeded, 3)
    for text in ("no rule in this rule set earned credit on this telemetry", "Recorded mode", "Sysmon events only",
                 "best case on known telemetry", "Event-time to first match", "Splunk attack_data",
                 "Apache-2.0", "Detection Rule License (DRL) 1.1", "Atomic Red Team", "MIT",
                 "github.com/splunk/attack_data", "Custom (PurpleBench)", "SigmaHQ"):
        assert text in page, text
    assert "not yet run against a real lab" not in page  # recorded runs do not claim a lab


@pytest.mark.parametrize("run_id", [1, 4])
def test_attack_notice_in_both_report_formats(seeded, run_id):
    from purplebench.attribution import ATTACK_COPYRIGHT, ATTACK_TERMS_URL, ATTACK_TRADEMARK
    page = _html(seeded, run_id)
    md = _md(seeded, run_id)
    appendix = page.split("Appendix B.")[1]
    assert html_escape(ATTACK_COPYRIGHT) in appendix and html_escape(ATTACK_TRADEMARK) in appendix
    assert ATTACK_TERMS_URL in appendix
    flat = md.replace("\\", "")
    assert ATTACK_COPYRIGHT in flat and ATTACK_TRADEMARK in flat


def html_escape(text):
    import html
    return html.escape(text, quote=False)


def test_results_and_scope_content(seeded):
    page = _html(seeded, 3)
    assert "71.4%" in page and "T1059.001" in page and "(exact)" in page
    assert "noisy, no credit" in page
    assert "34 rules: 30 SigmaHQ, 4 custom" in page
    # untested listed separately and excluded from the score
    section = page.split("8. Untested and did not run")[1].split("Appendix A")[0]
    assert "T1558.003" in section and "excluded from the score" in section


def test_change_vs_previous_run_of_same_campaign(seeded):
    page = _html(seeded, 3)
    assert re.search(r"Compared with run 1 \(rule set v1, [^)]*\) of the same campaign", page)
    assert "points)" in page
    # a campaign's first run falls back to an earlier run of another campaign, score only
    assert "No earlier run of this campaign" in _html(seeded, 2)
    assert "No previous run to compare with." in _html(seeded, 1)


def test_gaps_have_hints_and_state(seeded):
    page = _html(seeded, 1)
    assert "Telemetry needed" in page and "closed in run 3" in page


def test_lab_mode_labelled_and_target_shown(seeded):
    seeded.execute("UPDATE runs SET mode='lab', source=? WHERE id=1",
                   ("Lab run on LAB-WS01 from a run file.",))
    seeded.commit()
    md, page = _md(seeded, 1), _html(seeded, 1)
    for out in (md.replace("\\", ""), page):
        assert "not yet run against a real lab" in out
        assert "LAB-WS01" in out
        assert "Rule noise was not measured" in out
    assert "Sysmon events only" not in page


def test_html_escapes_hostile_values(seeded):
    seeded.execute("UPDATE campaigns SET name=?, description=? WHERE id=1", (HOSTILE, HOSTILE))
    seeded.execute("UPDATE runs SET notes=?, source=? WHERE id=1", (HOSTILE, HOSTILE))
    seeded.execute("UPDATE ruleset_rules SET title=? WHERE ruleset_id=1", (HOSTILE,))
    seeded.execute("UPDATE executions SET reason=? WHERE run_id=1", (HOSTILE,))
    seeded.execute("UPDATE gaps SET notes=?, rule_idea=? WHERE run_id=1", (HOSTILE, HOSTILE))
    seeded.commit()
    page = _html(seeded, 1)
    assert "<script>" not in page and "javascript:alert" in page  # shown as text only
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<a " not in page and "onerror" not in page
    assert not re.search(r"<(?!/?(html|head|meta|title|style|body|h1|h2|p|ul|li|table|thead|tbody|tr|th|td)\b|!DOCTYPE)", page)


def test_markdown_escapes_hostile_values(seeded):
    seeded.execute("UPDATE campaigns SET name=? WHERE id=1", (HOSTILE,))
    seeded.execute("UPDATE ruleset_rules SET title=? WHERE ruleset_id=1", (HOSTILE,))
    seeded.execute("UPDATE runs SET notes=? WHERE id=1", (HOSTILE,))
    seeded.commit()
    md = _md(seeded, 1)
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert "[x](javascript" not in md and r"\[x\]\(javascript" in md
    assert "**b**" not in md and r"\*\*b\*\*" in md
    assert r"\|" in md  # the pipe in the hostile value is escaped
    # every table row has as many unescaped pipes as its header
    block = []
    for line in md.splitlines() + [""]:
        if line.startswith("|"):
            block.append(len(re.findall(r"(?<!\\)\|", line)))
        elif block:
            assert len(set(block)) == 1, block
            block = []


def test_deterministic(seeded):
    for i in (1, 2, 3, 4):
        assert _md(seeded, i) == _md(seeded, i)
        assert _html(seeded, i) == _html(seeded, i)
    assert "2026-11-10T12:00:00Z" in _md(seeded, 1).replace("\\", "")
    assert reports.exercise_report_md(seeded, 1, "other") != _md(seeded, 1)


def test_unknown_run(seeded):
    with pytest.raises(KeyError):
        _md(seeded, 99)


# -- authors and numbers -------------------------------------------------------------------------------

def test_authors_shown_for_fired_rules_and_in_appendix(seeded):
    from purplebench import rulesets
    attr = rulesets.rule_attribution()
    sigma = next(a for a in attr.values() if a["origin"] == "sigmahq" and a["author"])
    assert sigma["file"].startswith("rules/sigmahq/") and sigma["url"].startswith("https://github.com/SigmaHQ/sigma/blob/")
    assert all(a["author"] for a in attr.values())  # DRL: every bundled rule keeps its author
    page = _html(seeded, 3)
    results = page.split("4. Results")[1].split("5. Coverage change")[0]
    assert "(author: " in results and "(author: unknown)" not in results
    appendix = page.split("Appendix A.")[1]
    assert "<th>Author</th>" in appendix and "<th>Rule file</th>" in appendix
    assert "https://github.com/SigmaHQ/sigma/blob/552f3fee" in appendix and "rules/custom/" in appendix
    assert sigma["author"].split(",")[0] in appendix
    assert "https://github.com/SigmaHQ/Detection-Rule-License" in appendix.split("Appendix B.")[1]


@pytest.mark.parametrize("run_id", [1, 2, 3, 4])
def test_numbers_reconcile_with_scoring_and_coverage(seeded, run_id):
    from purplebench import coverage as cv
    score, _ = reports._run_score(seeded, run_id)
    cov = cv.compute_coverage(score)
    summary = db.run_summary(seeded, run_id)
    # executions are one per technique in the demo, so the stored summary and the shared coverage agree
    assert cov.score == summary["score"] and cov.tested == summary["tested"]
    page = _html(seeded, run_id)
    assert f"Coverage score (detected / tested): {cov.score:.1f}%" in page
    assert f"Techniques tested: {cov.tested}; detected {cov.counts['detected']}, partial {cov.counts['partial']}" in page
    for t in cov.tactics:
        assert f"<td>{t.name}</td>" in page
        assert f"<td>{t.tested}</td><td>{t.counts['detected']}</td><td>{t.score:.1f}%</td>" in page


def test_markdown_neutralises_autolinks_mentions_emoji(seeded):
    seeded.execute("UPDATE campaigns SET name=? WHERE id=1",
                   ("https://x.y www.x.y a@b.co @user :smile: 1. first 2) second",))
    seeded.commit()
    title = _md(seeded, 1).splitlines()[0]
    assert "://" not in title and "www." not in title.lower()
    assert "@" not in title and ":smile:" not in title
    assert "https&#58;//x" in title and "www&#46;x" in title and "a&#64;b" in title and "&#58;smile&#58;" in title
    # trusted attribution URLs stay readable
    assert "https://github.com/SigmaHQ/Detection-Rule-License" in _md(seeded, 1)
    # leading ordered-list markers are escaped
    seeded.execute("UPDATE runs SET notes=? WHERE id=1", ("1. first",))
    seeded.commit()
    assert "Run notes&#58; 1. first" not in _md(seeded, 1)
    assert reports._md_text("1. first") == r"1\. first" and reports._md_text("2) x") == r"2\) x"


def test_control_and_bidi_characters_stripped(seeded):
    seeded.execute("UPDATE campaigns SET name=? WHERE id=1", ("evil‮TXT​name",))
    seeded.commit()
    for out in (_md(seeded, 1), _html(seeded, 1)):
        assert "‮" not in out and "​" not in out and "" not in out
        assert "evilTXTname" in out
    assert reports._md_text(None) == "" and reports._plain(None) == ""


@pytest.mark.parametrize("source,expected", [
    ("Lab run on <script>x</script> from file", "(not recorded)"),
    ("Lab run on ", "(not recorded)"),
    ("garbage", "(not recorded)"),
    ("", "(not recorded)"),
    ("Lab run on LAB-WS01.corp from file", "LAB-WS01.corp"),
])
def test_lab_source_parsing(seeded, source, expected):
    seeded.execute("UPDATE runs SET mode='lab', source=? WHERE id=1", (source,))
    seeded.commit()
    page = _html(seeded, 1)
    assert f"Target host: {expected}" in page
    assert "<script>" not in page
    assert "not yet run against a real lab" in page
