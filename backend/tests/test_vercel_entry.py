"""The Vercel entry point (api/index.py): it loads, serves data routes in demo mode, and the request-size
limits still apply to the path Vercel's rewrite forwards."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from purplebench import api, demo

ENTRY = Path(__file__).resolve().parents[2] / "api" / "index.py"
ENV = ("PURPLEBENCH_DB", "PURPLEBENCH_DEMO", "PURPLEBENCH_TRUST_PROXY", "PURPLEBENCH_MAX_UPLOAD_MB",
       "PURPLEBENCH_ADMIN_PASSWORD_HASH", "PURPLEBENCH_SECRET_KEY", "PURPLEBENCH_GUEST")


@pytest.fixture
def entry(tmp_path, monkeypatch):
    """Load api/index.py the way Vercel does: no PurpleBench variables set except what the host provides."""
    import os

    for name in ENV:
        monkeypatch.setenv(name, "x")  # records the original state so teardown restores it
        monkeypatch.delenv(name)
    monkeypatch.setattr(api, "_seed_failed_until", 0.0)
    spec = importlib.util.spec_from_file_location("vercel_entry_under_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    defaults = {name: os.environ.get(name) for name in ENV}
    # Keep the test's database out of the real /tmp location (the default itself is asserted below).
    monkeypatch.setenv("PURPLEBENCH_DB", str(tmp_path / "vercel.db"))
    return module, defaults, TestClient(module.app)


def test_entry_exposes_the_app_with_serverless_defaults(entry):
    module, defaults, _client = entry
    assert module.app is api.app
    assert defaults["PURPLEBENCH_DB"] == "/tmp/purplebench.db"
    assert defaults["PURPLEBENCH_DEMO"] == "true"
    assert defaults["PURPLEBENCH_TRUST_PROXY"] == "true"
    assert defaults["PURPLEBENCH_MAX_UPLOAD_MB"] == "4"


def test_entry_serves_a_data_route_as_a_read_only_guest(entry):
    _module, _defaults, client = entry
    health = client.get("/api/health").json()
    assert health["demo"] is True and health["guest"] is True and health["auth_configured"] is False
    r = client.get("/api/runs")  # seeded lazily into the (tmp) database on first use
    assert r.status_code == 200 and len(r.json()) == 4
    assert client.get("/api/auth/me").json()["guest"] is True
    # a guest cannot write, and without the admin variables nobody can sign in
    assert client.post("/api/campaigns", json={"name": "x", "techniques": ["T1059.001"]}).status_code == 403
    assert client.post("/api/auth/login", json={"username": "admin", "password": "x"}).status_code == 503


def test_entry_data_routes_are_503_while_the_demo_database_is_unavailable(entry, monkeypatch):
    _module, _defaults, client = entry

    def broken():
        raise OSError("read-only file system")
    monkeypatch.setattr(demo, "ensure_seeded", broken)
    r = client.get("/api/runs")
    assert r.status_code == 503 and r.json() == {"detail": "Demo data is not available yet"}
    assert client.get("/api/health").status_code == 200  # the function itself still answers


def test_body_limits_apply_behind_the_rewrite(entry):
    """Everything except the run upload stays at 64 KiB; the upload keeps its own cap (4 MB on the demo)."""
    _module, _defaults, client = entry
    big_json = b'{"name":"' + b"a" * (70 * 1024) + b'"}'
    r = client.post("/api/campaigns", content=big_json, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and "64 KiB" in r.json()["detail"]
    # the upload path is allowed more than 64 KiB: it passes the size check and is refused later (guest, 403)
    mid = b"x" * (1024 * 1024)
    r = client.post("/api/runs", content=mid, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code != 413
    # ... but not more than the demo cap (4 MB plus multipart overhead)
    over = b"x" * (5 * 1024 * 1024)
    r = client.post("/api/runs", content=over, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 413 and "4 MB" in r.json()["detail"]
    # a trailing slash does not turn the upload into a small-body route or the reverse
    r = client.post("/api/runs/", content=mid, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code != 413


def test_vercel_config_bundles_what_the_function_reads_and_stays_small():
    import json

    root = ENTRY.parents[1]
    cfg = json.loads((root / "vercel.json").read_text(encoding="utf-8"))
    include = cfg["functions"]["api/index.py"]["includeFiles"]
    for part in ("backend/purplebench/**", "backend/data/**", "backend/rules/**"):
        assert part in include
    # Vercel's Python limit is 500 MB uncompressed; the application files are a few MB (see DECISIONS.md).
    size = sum(f.stat().st_size for d in ("backend/purplebench", "backend/data", "backend/rules")
               for f in (root / d).rglob("*") if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".db")
    assert size < 20 * 1024 * 1024, f"application files grew to {size} bytes; review the bundle budget"
    ignore = (root / ".vercelignore").read_text(encoding="utf-8").splitlines()
    for needed in ("backend/data", "backend/rules", "backend/purplebench"):
        assert needed not in ignore  # runtime data must not be excluded
    assert {"fastapi", "pyyaml", "regex", "defusedxml"} <= {
        line.split(">")[0].split("=")[0].strip().lower() for line in (root / "requirements.txt").read_text().splitlines()
        if line and not line.startswith("#")}


def test_upload_cap_is_clamped_below_vercels_body_limit(monkeypatch):
    """Vercel refuses bodies over 4.5 MB itself (a non-JSON platform error), so on Vercel the app's cap stays
    at 4 MB whatever PURPLEBENCH_MAX_UPLOAD_MB says, and /api/health reports the effective figure."""
    monkeypatch.setenv("PURPLEBENCH_MAX_UPLOAD_MB", "32")
    assert TestClient(api.app).get("/api/health").json()["max_upload_mb"] == 32
    monkeypatch.setenv("VERCEL", "1")
    assert TestClient(api.app).get("/api/health").json()["max_upload_mb"] == 4
    from purplebench import config
    assert config.max_upload_bytes() + api.MULTIPART_OVERHEAD < int(4.5 * 1024 * 1024)
