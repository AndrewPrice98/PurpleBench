"""REST API: shapes and codes, guest 403, injection, upload limits, rule authors, end-to-end on an empty DB."""

import asyncio
import json
import re

import pytest
from fastapi.testclient import TestClient

from conftest import TEST_PASSWORD, TEST_USER
from purplebench import api, config, db, demo, navigator, scoring
from test_runfile import _entry, to_xml


def _login(c):
    assert c.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD}).status_code == 200
    return c


@pytest.fixture
def admin(seeded_db):
    with TestClient(api.app) as c:
        yield _login(c)


@pytest.fixture
def guest(seeded_db, monkeypatch):
    monkeypatch.setenv("PURPLEBENCH_DEMO", "1")
    with TestClient(api.app) as c:
        yield c


@pytest.fixture
def empty(db_file):
    with TestClient(api.app) as c:
        yield _login(c)


@pytest.fixture(scope="module")
def recorded():
    return [e for e in scoring.recorded_executions() if e.anchor_ts]


def add_latest_ruleset(path):
    """The import scores with a stored rule set; an empty database has none, so store the newest demo one."""
    c = db.connect(path)
    s = demo.load_fixture()["rulesets"][-1]
    db.add_ruleset(c, s["version"], s["created_at"], s["rules_json_hash"], s["notes"], s["rules"], id=s["id"])
    c.close()


def run_file(recorded, n=2):
    return {"format": "purplebench-run", "version": 2, "mode": "lab", "target": "LAB-WS01",
            "started_at": "2026-11-10T09:00:00Z", "campaign": "Lab smoke test",
            "executions": [_entry(e) for e in recorded[:n]]}


def post_run(c, obj_or_bytes, **kw):
    raw = obj_or_bytes if isinstance(obj_or_bytes, bytes) else json.dumps(obj_or_bytes).encode()
    return c.post("/api/runs", files={"file": ("run.json", raw, "application/json")}, **kw)


# -- auth and headers ------------------------------------------------------------------------------

def test_health_public_and_headers(seeded_db):
    c = TestClient(api.app)
    r = c.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_protected_requires_login(seeded_db):
    c = TestClient(api.app)
    for path in ("/api/overview", "/api/runs", "/api/rules", "/api/gaps", "/api/campaigns"):
        assert c.get(path).status_code == 401


def test_guest_reads_and_every_write_is_403(guest):
    for path in ("/api/overview", "/api/runs", "/api/campaigns/1", "/api/coverage", "/api/rules", "/api/gaps"):
        assert guest.get(path).status_code == 200, path
    assert guest.get("/api/auth/me").json() == {"username": "guest", "guest": True}
    assert guest.post("/api/campaigns", json={"name": "x", "techniques": ["T1003.001"]}).status_code == 403
    assert guest.patch("/api/gaps/1", json={"status": "closed"}).status_code == 403
    assert post_run(guest, b"{}").status_code == 403
    assert guest.post("/api/runs", content=b"{}").status_code == 403


def test_headers_on_413(admin, monkeypatch):
    monkeypatch.setenv("PURPLEBENCH_MAX_UPLOAD_MB", "1")
    r = admin.post("/api/runs", content=b"x" * (1024 * 1024 + 70_000), headers={"content-type": "application/json"})
    assert r.status_code == 413 and r.headers["x-content-type-options"] == "nosniff"
    assert admin.get("/api/runs/nope").headers["x-frame-options"] == "DENY"


def test_last_resort_500(seeded_db, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret internals")
    monkeypatch.setattr(api, "_all_run_stats", boom)
    with TestClient(api.app, raise_server_exceptions=False) as c:
        _login(c)
        r = c.get("/api/runs")
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error"}
    assert "secret" not in r.text and r.headers["x-content-type-options"] == "nosniff"


# -- shapes ------------------------------------------------------------------------------------------

def test_overview_shape(admin):
    d = admin.get("/api/overview").json()
    assert d["counts"]["runs"] == 4 and len(d["trend"]) == 4
    assert all(t["score"] is not None for t in d["trend"])
    assert d["latest"]["run"]["id"] == d["trend"][-1]["run_id"] and d["latest"]["run"]["mode"] == "recorded"
    assert "nothing was executed" in d["latest"]["run"]["mode_note"]
    assert d["top_gaps"] and len(d["top_gaps"]) <= 5


def test_trend_scores_match_coverage(admin):
    for t in admin.get("/api/overview").json()["trend"]:
        assert admin.get(f"/api/coverage?run={t['run_id']}").json()["score"] == t["score"]


def test_campaigns_and_export_format(admin):
    assert [c["id"] for c in admin.get("/api/campaigns").json()] == [1, 2]
    c = admin.get("/api/campaigns/1").json()
    assert c["techniques"] and c["runs"]
    r = admin.get("/api/campaigns/1/export.json")
    assert r.headers["content-disposition"].startswith('attachment; filename="purplebench-campaign-1-')
    exp = r.json()
    assert set(exp) == {"format", "version", "name", "tests"}
    assert exp["format"] == "purplebench-campaign" and exp["version"] == 1
    assert exp["tests"] and all(set(t) == {"technique_id", "test_guid"} for t in exp["tests"])
    guid = re.compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    assert all(guid.match(t["test_guid"]) for t in exp["tests"])
    assert len(exp["tests"]) < len(c["techniques"])  # recorded-only techniques have no Atomic GUID


def test_runs_and_run_detail(admin):
    runs = admin.get("/api/runs").json()
    assert len(runs) == 4 and {"counts", "score", "mode_note"} <= set(runs[0])
    d = admin.get("/api/runs/1").json()
    assert d["executions"] and d["gaps"] and d["mode"] == "recorded"
    assert admin.get("/api/runs/999").status_code == 404


def test_execution_detail_events_paging_and_matches(admin):
    run = admin.get("/api/runs/3").json()
    ex = next(e for e in run["executions"] if e["status"] == "detected" and e["rules_fired"])
    d = admin.get(f"/api/executions/{ex['id']}?limit=5").json()
    assert d["hits"] and d["events"]["available"] and len(d["events"]["items"]) <= 5
    seen_match, off = False, 0
    while True:
        page = admin.get(f"/api/executions/{ex['id']}?limit=200&offset={off}").json()["events"]
        seen_match |= any(e["matched"] for e in page["items"])
        if not page["has_more"]:
            break
        off += 200
    assert seen_match
    assert admin.get(f"/api/executions/{ex['id']}?limit=201").status_code == 422
    assert admin.get(f"/api/executions/{ex['id']}?offset=-1").status_code == 422
    assert admin.get("/api/executions/1;drop").status_code == 404


def test_atomic_test_text_is_display_only(admin):
    run = admin.get("/api/runs/1").json()
    ex = next(e for e in run["executions"] if e["test_guid"])
    a = admin.get(f"/api/executions/{ex['id']}").json()["atomic_test"]
    assert a and a["command"] and "never runs" in a["note"]


def test_coverage_and_navigator(admin):
    cov = admin.get("/api/coverage?run=3").json()
    assert cov["tactics"] and cov["techniques"] and cov["run"]["id"] == 3
    r = admin.get("/api/coverage/navigator.json?run=3")
    assert "attachment" in r.headers["content-disposition"]
    layer = r.json()
    assert navigator.validate_layer(layer) == []
    meta = " ".join(m["value"] for t in layer["techniques"] for m in t["metadata"] if "rules" in m["name"])
    assert "(" in meta and "unknown author" not in meta  # "title (author)"
    assert admin.get("/api/coverage?run=x").status_code == 404


def test_reports_are_attachments(admin):
    for ext, ctype in (("md", "text/markdown"), ("html", "text/html")):
        r = admin.get(f"/api/runs/2/report.{ext}")
        assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)
        assert r.headers["content-disposition"] == f'attachment; filename="purplebench-run-2-report.{ext}"'
    assert admin.get("/api/runs/77/report.md").status_code == 404


def test_rules_list_filters_and_detail(admin):
    d = admin.get("/api/rules").json()
    assert len(d["rules"]) == 70 and "Detection-Rule-License" in d["licence_notice"]
    keys = {"id", "title", "author", "licence", "source", "file", "url", "level", "status", "techniques"}
    assert all(keys <= set(r) for r in d["rules"])
    assert any(r["status"] == "unsupported" and r["reason"] for r in d["rules"])
    assert {r["source"] for r in admin.get("/api/rules?source=custom").json()["rules"]} == {"custom"}
    assert admin.get("/api/rules?source=evil").status_code == 422
    assert admin.get("/api/rules?noisy=true").json()["rules"]
    rid = next(r["id"] for r in d["rules"] if r["source"] == "sigmahq")
    one = admin.get(f"/api/rules/{rid}").json()
    assert "title" in one["yaml"] and one["author"] and one["url"].startswith("https://")
    assert admin.get("/api/rules/not-a-uuid").status_code == 404
    assert admin.get("/api/rules/00000000-0000-0000-0000-000000000000").status_code == 404


def test_every_rule_reference_has_an_author(admin):
    """DRL 1.1: walk the main responses; every rule object has a non-empty author."""
    found = []

    def walk(o):
        if isinstance(o, dict):
            if {"id", "title", "source", "file", "licence"} <= set(o):
                found.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    paths = ["/api/overview", "/api/rules", "/api/gaps", "/api/gaps?status=closed"]
    for rid in (1, 2, 3, 4):
        paths += [f"/api/coverage?run={rid}", f"/api/runs/{rid}", f"/api/rules?run={rid}"]
        ex = admin.get(f"/api/runs/{rid}").json()["executions"]
        paths += [f"/api/executions/{e['id']}?limit=1" for e in ex[:6]]
    for p in paths:
        r = admin.get(p)
        assert r.status_code == 200, p
        walk(r.json())
    assert len(found) > 100
    assert all(isinstance(r["author"], str) and r["author"].strip() and r["author"] != "unknown" for r in found)
    gaps = admin.get("/api/gaps?status=closed").json()["gaps"]
    assert any(g["rules"] for g in gaps)  # a closed gap's notes name the rule that closed it


# -- campaigns and gaps: writes and injection ---------------------------------------------------------

def test_create_campaign_validation(admin):
    ok = admin.post("/api/campaigns", json={"name": "My <b>campaign</b>", "techniques": ["T1003.001", "T1003.001"]})
    assert ok.status_code == 201 and ok.json()["name"] == "My <b>campaign</b>" and len(ok.json()["techniques"]) == 1
    assert admin.post("/api/campaigns", json={"name": "My <b>campaign</b>", "techniques": ["T1003.001"]}).status_code == 409
    bad = [
        {"name": "x" * 201, "techniques": ["T1003.001"]},
        {"name": "a\x00b", "techniques": ["T1003.001"]},
        {"name": "a\nb", "techniques": ["T1003.001"]},
        {"name": "a‮b", "techniques": ["T1003.001"]},
        {"name": "   ", "techniques": ["T1003.001"]},
        {"name": "n", "techniques": []},
        {"name": "n", "techniques": ["T9999"]},
        {"name": "n", "techniques": ["T1003.001'; DROP TABLE campaigns;--"]},
        {"name": "n", "techniques": [1]},
        {"name": "n", "techniques": ["T1003.001"], "description": "x" * 2001},
    ]
    for body in bad:
        assert admin.post("/api/campaigns", json=body).status_code == 422, body
    assert len(admin.get("/api/campaigns").json()) == 3  # tables intact, only the one valid campaign added


def test_patch_gap(admin):
    gid = admin.get("/api/gaps?status=open").json()["gaps"][0]["id"]
    r = admin.patch(f"/api/gaps/{gid}", json={"status": "accepted", "notes": "Accepted: <script>alert(1)</script>\nline 2"})
    assert r.status_code == 200 and r.json()["status"] == "accepted" and "<script>" in r.json()["notes"]
    assert admin.patch(f"/api/gaps/{gid}", json={"status": "open"}).json()["status"] == "open"
    for body in ({"status": "bogus"}, {"notes": "x" * 2001}, {}, {"notes": "a\x00b"}, {"status": ["open"]}):
        assert admin.patch(f"/api/gaps/{gid}", json=body).status_code == 422, body
    assert admin.patch("/api/gaps/999999", json={"status": "open"}).status_code == 404
    assert admin.patch("/api/gaps/1%27%20OR%201=1", json={"status": "open"}).status_code == 404


@pytest.mark.parametrize("payload", ["' OR 1=1 --", "1; DROP TABLE runs", "..%2F..%2Fetc%2Fpasswd", "%00",
                                     "<script>x</script>", "9" * 40])
def test_injection_in_ids_and_query(admin, payload):
    for path in ("/api/runs/", "/api/executions/", "/api/campaigns/", "/api/rules/", "/api/gaps/"):
        assert admin.get(path + payload).status_code in (404, 405)
    assert admin.get("/api/coverage", params={"run": payload}).status_code in (404, 422)
    assert admin.get("/api/gaps", params={"run": payload}).status_code in (404, 422)
    assert admin.get("/api/rules", params={"source": payload}).status_code == 422
    assert admin.get("/api/gaps", params={"kind": payload}).status_code == 422
    assert len(admin.get("/api/runs").json()) == 4


def test_event_ref_traversal_is_refused(admin, db_file):
    c = db.connect(db_file)
    c.execute("UPDATE executions SET events_ref = '../../../db_secret.jsonl.gz' WHERE id = 1")
    c.commit()
    c.close()
    d = admin.get("/api/executions/1").json()
    assert d["events"]["available"] is False and d["events"]["items"] == []


# -- uploads --------------------------------------------------------------------------------------------

def test_run_upload_limits(empty, recorded, db_file, monkeypatch):
    monkeypatch.setenv("PURPLEBENCH_MAX_UPLOAD_MB", "1")
    limit = 1024 * 1024
    add_latest_ruleset(db_file)

    # 1. announced Content-Length over the cap: refused before any body is read
    sent, polled = [], []

    async def receive():
        polled.append(1)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    async def never(*a):
        raise AssertionError("inner app must not run")

    scope = {"type": "http", "method": "POST", "path": "/api/runs", "headers": [
        (b"content-length", str(limit * 50).encode()), (b"content-type", b"multipart/form-data; boundary=x")]}
    asyncio.run(api.BodyLimitMiddleware(never)(scope, receive, send))
    assert sent[0]["status"] == 413 and not polled

    # 2. chunked body with no Content-Length streams past the cap: counted and refused
    def chunks():
        for _ in range(40):
            yield b"x" * 65536
    r = empty.post("/api/runs", content=chunks(), headers={"content-type": "multipart/form-data; boundary=x"})
    assert r.status_code == 413 and "max 1 MB" in r.json()["detail"]

    # 3. a file part just over the cap, still inside the multipart allowance
    assert post_run(empty, b" " * (limit + 100)).status_code == 413

    # 4. bad content types and shapes
    assert empty.post("/api/runs", json={"a": 1}).status_code == 415
    assert empty.post("/api/runs", files={"file": ("a.exe", b"{}", "application/x-msdownload")}).status_code == 415
    assert empty.post("/api/runs", files={"other": ("a.json", b"{}", "application/json")}).status_code == 400
    assert post_run(empty, b"").status_code == 400
    assert post_run(empty, b'{"a":\x00}').status_code == 400
    assert post_run(empty, b"\xff\xfe\xfa not utf8").status_code == 400
    assert post_run(empty, b"not json").status_code == 400
    assert post_run(empty, b"[" * 5000 + b"]" * 5000).status_code == 400  # deep nesting
    assert post_run(empty, b"[1,2,3]").status_code == 400
    r = empty.post("/api/runs", data={"ruleset_id": "99"}, files={"file": ("r.json", b"{}", "application/json")})
    assert r.status_code == 400 and "rule set" in r.json()["detail"]

    # 5. too many events in one execution
    many = run_file(recorded, 1)
    many["executions"][0]["events_xml"] = ["<E/>"] * 60_000
    r = post_run(empty, many)
    assert r.status_code == 400 and "more than" in r.json()["detail"]

    # 6. a ~1 MB command line: the event is left out and counted, nothing is echoed back
    huge = run_file(recorded, 1)
    ev = recorded[0].events[0]
    big = {**ev, "fields": {**ev["fields"], "CommandLine": "A" * (limit - 2000)}}
    huge["executions"][0]["events_xml"] = [to_xml(big)]
    r = post_run(empty, huge)
    assert r.status_code == 201, r.text
    d = empty.get(f"/api/runs/{r.json()['run_id']}").json()
    assert d["executions"][0]["status"] == "did_not_run" and "AAAA" not in json.dumps(d)
    assert empty.get("/api/health").status_code == 200

    # nothing from the rejected uploads was stored
    assert len(empty.get("/api/runs").json()) == 1


def test_upload_limit_defaults(monkeypatch):
    monkeypatch.delenv("PURPLEBENCH_MAX_UPLOAD_MB", raising=False)
    assert config.max_upload_bytes() == 32 * 1024 * 1024
    monkeypatch.setenv("PURPLEBENCH_DEMO", "1")
    assert config.max_upload_bytes() == 4 * 1024 * 1024


# -- end to end on an empty database -------------------------------------------------------------------

def test_end_to_end_empty_db(empty, recorded, db_file):
    o = empty.get("/api/overview").json()
    assert o["latest"] is None and o["trend"] == [] and o["counts"]["runs"] == 0
    assert empty.get("/api/coverage").status_code == 404 and empty.get("/api/runs").json() == []
    assert empty.get("/api/rules").json()["run"] is None

    techs = sorted({e.technique for e in recorded[:3]})
    created = empty.post("/api/campaigns", json={"name": "Lab smoke test", "techniques": techs})
    assert created.status_code == 201
    cid = created.json()["id"]
    exp = empty.get(f"/api/campaigns/{cid}/export.json").json()
    assert exp["format"] == "purplebench-campaign" and exp["name"] == "Lab smoke test"
    assert {t["technique_id"] for t in exp["tests"]} <= set(techs)

    add_latest_ruleset(db_file)
    r = post_run(empty, run_file(recorded, 3))
    assert r.status_code == 201, r.text
    body = r.json()
    rid = body["run_id"]
    assert body["run"]["mode"] == "lab" and "not yet run against a real lab" in body["run"]["mode_note"]
    assert body["run"]["campaign_id"] == cid and body["tested"] >= 1

    run = empty.get(f"/api/runs/{rid}").json()
    assert len(run["executions"]) == 3
    assert all(e["status"] in {"detected", "partial", "missed", "telemetry_gap", "did_not_run"} for e in run["executions"])
    detail = empty.get(f"/api/executions/{run['executions'][0]['id']}").json()
    assert detail["events"]["source"] == "lab" and detail["events"]["available"] and detail["events"]["items"]
    fired = next((e for e in run["executions"] if e["rules_fired"]), None)
    assert fired, "at least one synthetic execution should fire a rule"
    matched, off = False, 0
    while True:
        d2 = empty.get(f"/api/executions/{fired['id']}?limit=200&offset={off}").json()
        matched |= any(e["matched"] for e in d2["events"]["items"])  # lab [channel, record_id] pairs are handled
        if not d2["events"]["has_more"]:
            break
        off += 200
    assert matched and all(h["rule"]["author"] for h in d2["hits"])

    assert empty.get(f"/api/coverage?run={rid}").json()["run"]["id"] == rid
    layer = empty.get("/api/coverage/navigator.json").json()
    assert navigator.validate_layer(layer) == [] and layer["techniques"]
    md = empty.get(f"/api/runs/{rid}/report.md")
    assert md.status_code == 200 and "Lab mode" in md.text
    assert empty.get(f"/api/runs/{rid}/report.html").status_code == 200
    assert empty.get("/api/overview").json()["latest"]["run"]["id"] == rid
