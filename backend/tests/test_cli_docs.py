"""CLI: docs --check, demo --check, and demo loading into its own database."""

from purplebench import __main__ as cli
from purplebench import db, docsgen


def test_docs_check_passes_on_the_committed_file(capsys):
    assert cli.main(["docs", "--check"]) == 0
    assert "current" in capsys.readouterr().out


def test_docs_check_fails_when_stale(tmp_path, monkeypatch, capsys):
    stale = tmp_path / "COVERAGE.md"
    stale.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(docsgen, "OUT", stale)
    assert cli.main(["docs", "--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert cli.main(["docs"]) == 0  # regenerating fixes it
    assert cli.main(["docs", "--check"]) == 0


def test_generated_doc_names_authors_and_the_untested_technique():
    text = docsgen.render()
    assert "Florian Roth (Nextron Systems)" in text and "Detection Rule License" in text
    assert "| T1558.003 |" in text and "untested" in text.split("| T1558.003 |")[1].splitlines()[0]
    assert "T1562.001" not in text and "Defense Evasion" not in text


def test_demo_check_matches_the_committed_fixture():
    assert cli.main(["demo", "--check"]) == 0


def test_demo_loads_its_own_database_and_does_not_touch_the_configured_one(tmp_path, monkeypatch):
    other = tmp_path / "other.db"
    monkeypatch.setenv("PURPLEBENCH_DB", str(other))
    target = tmp_path / "demo.db"
    assert cli.main(["demo", "--db", str(target)]) == 0
    assert target.exists() and not other.exists()
    conn = db.connect(target)
    try:
        assert len(db.list_runs(conn)) == 4
    finally:
        conn.close()
    monkeypatch.undo()
