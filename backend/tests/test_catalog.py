import gzip
import json
import shutil

import pytest

from purplebench import __main__ as cli
from purplebench import catalog, library


@pytest.fixture
def data_copy(tmp_path):
    dst = tmp_path / "data"
    shutil.copytree(library.DATA_DIR, dst)
    return dst


def test_committed_catalog_is_consistent():
    assert catalog.check_catalog() == []


def test_cli_check_ok(capsys):
    assert cli.main(["catalog", "--check"]) == 0
    assert "OK: 26 techniques" in capsys.readouterr().out


def test_cli_check_reports_problems(data_copy, capsys):
    (data_copy / "telemetry" / "baseline.jsonl.gz").unlink()
    assert cli.main(["catalog", "--check", "--data-dir", str(data_copy)]) == 1
    assert "FAIL baseline.jsonl.gz" in capsys.readouterr().out


def _first_test_file(data):
    m = json.loads((data / "telemetry" / "manifest.json").read_text("utf-8"))
    return next(f for f in m["files"] if f["kind"] == "test")["path"]


def test_flipped_byte_is_detected(data_copy):
    p = data_copy / "telemetry" / _first_test_file(data_copy)
    raw = bytearray(p.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    p.write_bytes(bytes(raw))
    errs = catalog.check_catalog(data_copy)
    assert any("sha256 does not match" in e for e in errs)


def test_changed_event_count_is_detected_even_with_matching_hash(data_copy):
    """A consistent re-hash of altered content still fails on counts and content hash."""
    rel = _first_test_file(data_copy)
    p = data_copy / "telemetry" / rel
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        lines = fh.readlines()
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.writelines(lines[:-1])
    mpath = data_copy / "telemetry" / "manifest.json"
    m = json.loads(mpath.read_text("utf-8"))
    import hashlib
    for f in m["files"]:
        if f["path"] == rel:
            f["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
            f["bytes"] = p.stat().st_size
    m["total_bytes"] = sum(f["bytes"] for f in m["files"])
    mpath.write_text(json.dumps(m), encoding="utf-8")
    errs = catalog.check_catalog(data_copy)
    assert any("events, manifest says" in e for e in errs)
    assert any("content hash" in e for e in errs)


def test_missing_and_orphan_files_are_detected(data_copy):
    rel = _first_test_file(data_copy)
    (data_copy / "telemetry" / rel).unlink()
    shutil.copyfile(data_copy / "telemetry" / "baseline.jsonl.gz", data_copy / "telemetry" / "stray.jsonl.gz")
    errs = catalog.check_catalog(data_copy)
    assert any("missing" in e and rel in e for e in errs)
    assert any("stray.jsonl.gz: telemetry file not listed" in e for e in errs)


def test_library_manifest_mismatch_is_detected(data_copy):
    lpath = data_copy / "library.json"
    lib = json.loads(lpath.read_text("utf-8"))
    lib["techniques"][0]["atomic"]["guid"] = "00000000-0000-0000-0000-000000000000"
    lpath.write_text(json.dumps(lib), encoding="utf-8")
    library._load.cache_clear()
    errs = catalog.check_catalog(data_copy)
    assert any("Atomic GUID differs" in e for e in errs)
    library._load.cache_clear()


def test_missing_manifest(tmp_path):
    assert catalog.check_catalog(tmp_path)[0].startswith("cannot read manifest")


def test_licence_attribution_files_ship_with_the_data():
    tele = library.DATA_DIR / "telemetry"
    assert "Apache License" in (tele / "LICENSE-Apache-2.0.txt").read_text("utf-8")
    assert "MIT License" in (library.DATA_DIR / "ATOMIC_RED_TEAM_LICENSE.txt").read_text("utf-8")
    assert "trimmed" in (tele / "NOTICE.md").read_text("utf-8")
