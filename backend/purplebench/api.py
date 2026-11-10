"""FastAPI application and routes. All routes live under /api. Guests (demo mode) are read-only.

Conventions follow CMMC Ready: lifespan seeding once, security headers and CSP on every response, a
pure-ASGI body limit (Content-Length precheck plus a byte counter), allow-listed filters, junk numeric ids are
404, attachments carry safe filenames, and a last-resort 500 handler never leaks internals.

Honesty: every run states its mode. "Missed" means no rule in the rule set fired on the telemetry; it never
describes a product. Every rule shown carries its author (SigmaHQ Detection Rule License 1.1).
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import sqlite3
import threading
import time
import unicodedata
from contextlib import asynccontextmanager
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Iterator, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__, auth, config, coverage as cov_mod, db, demo, library, navigator, reports, rulesets, runfile
from .coverage import _BEST
from .scoring import DEFAULT_NOISE_THRESHOLD, DEFAULT_SKEW_SECONDS, NOT_TESTED, STATUSES
from .telemetry import parse_ts

log = logging.getLogger("purplebench.api")


SEED_RETRY_SECONDS = 60.0
_seed_lock = threading.Lock()
_seed_failed_until = 0.0  # time.monotonic() until which a failed seeding is not retried


def _seed_unavailable() -> bool:
    return time.monotonic() < _seed_failed_until


def _try_seed() -> bool:
    """Seed the demo database. A failure is logged once and cached for SEED_RETRY_SECONDS so a broken
    database is not retried (and logged) on every request. Returns True when data may be served."""
    global _seed_failed_until
    with _seed_lock:
        if _seed_unavailable():
            return False
        try:
            demo.ensure_seeded()
            return True
        except Exception:
            log.exception("Demo seeding failed; not retrying for %d s", int(SEED_RETRY_SECONDS))
            _seed_failed_until = time.monotonic() + SEED_RETRY_SECONDS
            return False


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if config.demo_mode():
        await run_in_threadpool(_try_seed)
    yield


app = FastAPI(
    lifespan=lifespan,
    title="PurpleBench API",
    version=__version__,
    docs_url=None, redoc_url=None, openapi_url=None,  # served writer-only at /api/openapi.json below
    description="Purple-team detection validation: Atomic Red Team tests against Sigma rules. "
                "'Missed' means no rule in the rule set fired on this telemetry; it says nothing about any product.",
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"),
}


class SecurityHeadersMiddleware:
    """Pure ASGI, outermost: the headers are also on the 413 sent by the body limit."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for key, value in SECURITY_HEADERS.items():
                    if key.lower().encode() not in present:
                        headers.append((key.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


MULTIPART_OVERHEAD = 64 * 1024
SMALL_BODY_LIMIT = 64 * 1024  # every JSON endpoint; only the run upload may be large
UPLOAD_PATH = "/api/runs"


class _TooLarge(Exception):
    pass


async def _noop_receive():
    return {"type": "http.disconnect"}


class BodyLimitMiddleware:
    """Refuse request bodies over the upload cap (plus multipart overhead) with 413.

    An announced Content-Length is checked before any of the body is read. Bytes are also counted as they
    arrive, so a chunked request with no Content-Length cannot stream past the cap either.
    """

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _is_upload(scope) -> bool:
        return scope["method"] == "POST" and scope.get("path", "").rstrip("/") == UPLOAD_PATH

    @classmethod
    def _limit(cls, scope) -> int:
        return config.max_upload_bytes() + MULTIPART_OVERHEAD if cls._is_upload(scope) else SMALL_BODY_LIMIT

    @classmethod
    async def _reject(cls, scope, send) -> None:
        if cls._is_upload(scope):
            message = f"Request too large (max {config.max_upload_bytes() // (1024 * 1024)} MB)"
        else:
            message = f"Request too large (max {SMALL_BODY_LIMIT // 1024} KiB)"
        await JSONResponse({"detail": message}, status_code=413)({"type": "http"}, _noop_receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope)
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await self._reject(scope, send)
            return

        received = 0
        exceeded = False
        sent_any = False

        async def counting_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _TooLarge
            return message

        async def guarded_send(message):
            nonlocal sent_any
            if exceeded and not sent_any:
                return  # the framework's own "bad body" answer is replaced by the 413 below
            sent_any = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except _TooLarge:
            pass
        if exceeded and not sent_any:
            await self._reject(scope, send)


app.add_middleware(BodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)  # added last = outermost


@app.exception_handler(Exception)
async def last_resort(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500, headers=SECURITY_HEADERS)


def get_conn() -> Iterator[sqlite3.Connection]:
    try:
        conn = db.connect()
    except (sqlite3.Error, OSError):
        log.exception("Could not open the database")
        raise HTTPException(503, "The database is not available") from None
    if config.demo_mode():
        if _seed_unavailable():
            conn.close()
            raise HTTPException(503, "Demo data is not available yet")
        if not db.list_campaigns(conn):  # normally seeded at startup; this covers a cold or reset database
            conn.close()
            if not _try_seed():
                raise HTTPException(503, "Demo data is not available yet")
            conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]
Writer = Depends(auth.require_writer)

_DIGITS = re.compile(r"^[0-9]{1,9}$")


def _int_id(raw: str | None, what: str) -> int:
    """Junk ids are 404 without touching the database."""
    if raw is None or not _DIGITS.match(raw):
        raise HTTPException(404, f"{what} not found")
    return int(raw)


# -- text validation -------------------------------------------------------------------------------

_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩")


def _clean_text(value: str, what: str, *, multiline: bool = False) -> str:
    """Reject control characters (and bidi overrides) rather than silently altering the text."""
    for ch in value:
        cat = unicodedata.category(ch)
        if multiline and ch in "\n\r\t":
            continue
        if cat in ("Cc", "Cs") or (cat == "Cf" and (not multiline or ch in _BIDI)):
            raise HTTPException(422, f"{what} must not contain control characters")
    return value


# -- rules (every rule shown carries its author) -----------------------------------------------------

LICENCE = "DRL-1.1"  # SigmaHQ Detection Rule License 1.1 (the bundled custom rules are derived from it)


@lru_cache(maxsize=2)
def _rule_catalog(rules_dir: str, signature: tuple) -> dict[str, dict[str, Any]]:
    attr = rulesets.rule_attribution(rules_dir)
    out: dict[str, dict[str, Any]] = {}
    for rule in rulesets.load_all_rules(rules_dir).values():
        a = attr.get(rule.id, {})
        out[rule.id] = {
            "id": rule.id, "title": rule.title, "author": a.get("author") or rule.author or "unknown",
            "licence": LICENCE, "source": a.get("origin") or rule.origin or "custom",
            "file": a.get("file", ""), "url": a.get("url", ""), "level": rule.level,
            "status": rule.status, "reason": rule.reason if rule.status != "ok" else None,
            "techniques": list(rule.techniques), "_path": rule.path,
        }
    return out


def _rules_by_id() -> dict[str, Any]:
    return {r.id: r for r in rulesets.load_all_rules().values()}  # load_all_rules is cached


def _catalog() -> dict[str, dict[str, Any]]:
    return _rule_catalog(str(config.RULES_DIR), rulesets._signature(config.RULES_DIR))


def rule_obj(rule_id: str, title: str | None = None, origin: str | None = None) -> dict[str, Any]:
    """The public rule object. A rule id that is not bundled (should not happen) still gets every key."""
    r = _catalog().get(rule_id)
    if r is not None:
        return {k: v for k, v in r.items() if not k.startswith("_")}
    return {"id": rule_id, "title": title or rule_id, "author": "unknown", "licence": LICENCE,
            "source": origin if origin in rulesets.ORIGINS else "custom", "file": "", "url": "", "level": None,
            "status": "unsupported", "reason": "rule file is not bundled with this version", "techniques": []}


def _rules_named_in(text: str) -> list[dict[str, Any]]:
    """Bundled rules whose title appears in free text (gap notes name the rules that closed a gap)."""
    return [rule_obj(r["id"]) for r in _catalog().values() if len(r["title"]) >= 10 and r["title"] in text]


def _tech(tid: str) -> dict[str, Any]:
    t = library.get_technique(tid)
    return {"id": tid, "name": t.name if t else "(not in the technique library)",
            "tactics": list(t.tactics) if t else []}


MODE_NOTES = {
    "recorded": "Recorded mode: nothing was executed and no lab was used. Telemetry is a recording from a public dataset.",
    "lab": "Lab mode: not yet run against a real lab. The result is only as good as the lab that produced the file.",
}


def _run_out(run: dict) -> dict[str, Any]:
    return {k: run[k] for k in ("id", "campaign_id", "campaign_name", "ruleset_id", "ruleset_version", "mode",
                                "source", "started_at", "notes")} | {"mode_note": MODE_NOTES[run["mode"]]}


def _run_or_404(conn: sqlite3.Connection, raw: str | None) -> dict:
    run = db.get_run(conn, _int_id(raw, "run"))
    if run is None:
        raise HTTPException(404, "run not found")
    return run


def _latest_run(conn: sqlite3.Connection) -> dict | None:
    runs = db.list_runs(conn)
    return runs[-1] if runs else None


def _selected_run(conn: sqlite3.Connection, raw: str | None) -> dict:
    if raw is not None:
        return _run_or_404(conn, raw)
    run = _latest_run(conn)
    if run is None:
        raise HTTPException(404, "no runs yet")
    return run


def _all_run_stats(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    """Per run: best status per technique, counts, tested, score. Same rules as coverage.compute_coverage."""
    best: dict[int, dict[str, str]] = {}
    for row in conn.execute("SELECT run_id, technique_id, status FROM executions"):
        per = best.setdefault(row["run_id"], {})
        cur = per.get(row["technique_id"])
        if cur is None or _BEST.index(row["status"]) < _BEST.index(cur):
            per[row["technique_id"]] = row["status"]
    out = {}
    for rid, per in best.items():
        counts = {s: sum(1 for v in per.values() if v == s) for s in STATUSES}
        tested = sum(v for k, v in counts.items() if k not in NOT_TESTED)
        out[rid] = {"counts": counts, "tested": tested,
                    "score": round(100.0 * counts["detected"] / tested, 1) if tested else None,
                    "partial_score": round(100.0 * (2 * counts["detected"] + counts["partial"]) / (2 * tested), 1)
                    if tested else None}
    return out


_EMPTY_STATS = {"counts": {s: 0 for s in STATUSES}, "tested": 0, "score": None, "partial_score": None}


def _coverage_out(conn: sqlite3.Connection, run: dict) -> dict[str, Any]:
    score, rows = reports._run_score(conn, run["id"])
    cov = cov_mod.compute_coverage(score)
    best = reports._best_rows(score, rows)
    d = cov.to_dict()
    titles = {r["rule_id"]: r for r in conn.execute(
        "SELECT rule_id, title, origin FROM ruleset_rules WHERE ruleset_id = ?", (run["ruleset_id"],))}
    for t in d["techniques"]:
        t["execution_id"] = best[t["technique"]]["id"]
        t["rules"] = [rule_obj(r, titles[r]["title"] if r in titles else None) for r in t["rules"]]
    d["noisy_rules"] = _noisy_rules(conn, run)
    return d


def _noisy_rules(conn: sqlite3.Connection, run: dict) -> list[dict[str, Any]]:
    return [{"rule": rule_obj(n["rule_id"], n["title"], n["origin"]), "hits": n["hits"], "status": n["status"],
             "threshold": DEFAULT_NOISE_THRESHOLD}
            for n in db.list_rule_noise(conn, run["id"]) if n["noisy"]]


def _gap_out(g: dict) -> dict[str, Any]:
    out = dict(g)
    system, analyst = g["notes"] or "", g["analyst_notes"] or ""
    out["system_notes"] = system  # written by the importer; PATCH never changes it
    out["notes"] = analyst  # the analyst's own notes (PATCH)
    out["display_notes"] = (system + (" Analyst notes: " + analyst if analyst else "")).strip()
    out.pop("analyst_notes", None)
    out["technique"] = _tech(g["technique_id"])
    out["rules"] = _rules_named_in(system + " " + analyst)  # rules named in the notes, each with its author
    return out


# -- public endpoints --------------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "auth_configured": auth.is_configured(),
            "demo": config.demo_mode(), "guest": config.guest_enabled(),
            "max_upload_mb": config.max_upload_bytes() // (1024 * 1024)}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, response: Response):
    if not auth.is_configured():
        raise HTTPException(503, "Authentication is not configured. Run: python -m purplebench create-admin")
    ip = auth.client_ip(request)
    wait = auth.limiter.retry_after(ip)
    if wait:
        raise HTTPException(429, "Too many failed logins. Try again later.", headers={"Retry-After": str(wait)})
    if not auth.check_credentials(body.username, body.password):
        auth.limiter.record_failure(ip)
        raise HTTPException(401, "Invalid username or password")
    auth.limiter.reset(ip)
    token, expires = auth.issue_token(body.username)
    response.set_cookie(auth.COOKIE_NAME, token, expires=expires, httponly=True, secure=config.cookie_secure(),
                        samesite="strict", path="/api")
    return {"username": body.username, "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(auth.COOKIE_NAME, path="/api", httponly=True, secure=config.cookie_secure(),
                           samesite="strict")
    return {"ok": True}


protected = APIRouter(dependencies=[Depends(auth.require_user)])


@protected.get("/api/auth/me")
def me(user: Annotated[str, Depends(auth.require_user)]):
    return {"username": user, "guest": user == auth.GUEST_USER}


@protected.get("/api/openapi.json", include_in_schema=False)
def openapi_schema(_w: Annotated[str, Writer]):
    return app.openapi()


# -- overview ----------------------------------------------------------------------------------------

@protected.get("/api/overview")
def overview(conn: Conn):
    runs = db.list_runs(conn)
    stats = _all_run_stats(conn)
    trend = [{"run_id": r["id"], "campaign_id": r["campaign_id"], "campaign_name": r["campaign_name"],
              "started_at": r["started_at"], "ruleset_version": r["ruleset_version"], "mode": r["mode"],
              **{k: stats.get(r["id"], _EMPTY_STATS)[k] for k in ("score", "partial_score", "tested")}}
             for r in runs]
    base = {"counts": {"campaigns": len(db.list_campaigns(conn)), "runs": len(runs), "rules": len(_catalog())},
            "trend": trend, "latest": None, "top_gaps": [], "noisy_rules": []}
    if not runs:
        return base
    latest = runs[-1]
    gaps = [g for g in db.list_gaps(conn, latest["id"]) if g["status"] == "open"]
    gaps.sort(key=lambda g: (("missed", "telemetry_gap", "partial").index(g["kind"]), g["technique_id"]))
    base["latest"] = {"run": _run_out(latest), **stats.get(latest["id"], _EMPTY_STATS)}
    base["top_gaps"] = [_gap_out(g) for g in gaps[:5]]
    base["noisy_rules"] = _noisy_rules(conn, latest)
    return base


# -- library and rule sets -----------------------------------------------------------------------------

@protected.get("/api/library")
def library_list():
    return {"meta": library.library_meta(),
            "techniques": [{"id": t.attack_id, "name": t.name, "tactics": list(t.tactics),
                            "execution_kind": t.execution_kind,
                            "atomic_test": None if t.atomic is None else {"guid": t.atomic.guid, "name": t.atomic.name}}
                           for t in library.list_techniques()]}


@protected.get("/api/rulesets")
def rulesets_list(conn: Conn):
    return [{k: r[k] for k in ("id", "version", "created_at", "rules_json_hash", "notes", "rule_count")}
            for r in db.list_rulesets(conn)]


# -- campaigns ---------------------------------------------------------------------------------------

def _campaign_techniques(techniques: list[str]) -> list[dict[str, Any]]:
    out = []
    for tid in techniques:
        t = library.get_technique(tid)
        out.append({"id": tid, "name": t.name if t else "(not in the technique library)",
                    "tactics": list(t.tactics) if t else [],
                    "test_guid": t.atomic.guid if t and t.atomic else None,
                    "atomic_test": t.atomic.name if t and t.atomic else None})
    return out


@protected.get("/api/campaigns")
def campaigns(conn: Conn):
    runs = db.list_runs(conn)
    out = []
    for c in db.list_campaigns(conn):
        mine = [r for r in runs if r["campaign_id"] == c["id"]]
        out.append({"id": c["id"], "name": c["name"], "description": c["description"],
                    "technique_count": len(c["techniques"]), "run_count": len(mine),
                    "last_run_id": mine[-1]["id"] if mine else None})
    return out


def _campaign_or_404(conn: sqlite3.Connection, raw: str) -> dict:
    c = db.get_campaign(conn, _int_id(raw, "campaign"))
    if c is None:
        raise HTTPException(404, "campaign not found")
    return c


@protected.get("/api/campaigns/{campaign_id}")
def campaign(campaign_id: str, conn: Conn):
    c = _campaign_or_404(conn, campaign_id)
    stats = _all_run_stats(conn)
    return {"id": c["id"], "name": c["name"], "description": c["description"],
            "techniques": _campaign_techniques(c["techniques"]),
            "runs": [{"id": r["id"], "started_at": r["started_at"], "mode": r["mode"],
                      "ruleset_version": r["ruleset_version"],
                      **{k: stats.get(r["id"], _EMPTY_STATS)[k] for k in ("score", "tested")}}
                     for r in db.list_runs(conn, c["id"])]}


def _slug(text: str) -> str:
    return (re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40].strip("-")) or "campaign"


def _attachment(body: bytes | str, media_type: str, filename: str) -> Response:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", filename):
        raise ValueError("unsafe filename")
    data = body.encode("utf-8") if isinstance(body, str) else body
    return Response(data, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@protected.get("/api/campaigns/{campaign_id}/export.json")
def campaign_export(campaign_id: str, conn: Conn):
    """The campaign file the lab runner reads. Only tests with an Atomic Red Team GUID can be run."""
    c = _campaign_or_404(conn, campaign_id)
    tests, seen = [], set()
    for t in _campaign_techniques(c["techniques"]):
        tech = library.get_technique(t["id"])
        if t["test_guid"] and tech and tech.attack_id not in seen:
            seen.add(tech.attack_id)
            tests.append({"technique_id": tech.attack_id, "test_guid": t["test_guid"]})
    payload = {"format": "purplebench-campaign", "version": 1, "name": c["name"], "tests": tests}
    return _attachment(json.dumps(payload, indent=2) + "\n", "application/json",
                       f"purplebench-campaign-{c['id']}-{_slug(c['name'])}.json")


class CampaignBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    techniques: list[str] = Field(min_length=1, max_length=100)


@protected.post("/api/campaigns", status_code=201)
def create_campaign(_w: Annotated[str, Writer], body: CampaignBody, conn: Conn):
    name = _clean_text(body.name.strip(), "name")
    if not name:
        raise HTTPException(422, "name must not be blank")
    description = _clean_text(body.description, "description", multiline=True)
    ids: list[str] = []
    for raw in body.techniques:
        t = library.get_technique(raw) if len(raw) <= 16 else None
        if t is None:
            raise HTTPException(422, "techniques must be ids from the technique library (see GET /api/library)")
        if t.attack_id not in ids:
            ids.append(t.attack_id)
    conn.commit()  # no transaction may be open when taking the write lock
    conn.execute("BEGIN IMMEDIATE")
    try:
        if any(c["name"] == name for c in db.list_campaigns(conn)):
            conn.rollback()
            raise HTTPException(409, "a campaign with this name already exists")
        cid = db.add_campaign(conn, name, description, ids, commit=False)
        conn.commit()
    except HTTPException:
        raise
    except BaseException:
        conn.rollback()
        raise
    return campaign(str(cid), conn)


# -- runs --------------------------------------------------------------------------------------------

@protected.get("/api/runs")
def runs_list(conn: Conn):
    stats = _all_run_stats(conn)
    return [{**_run_out(r), **stats.get(r["id"], _EMPTY_STATS)} for r in db.list_runs(conn)]


@protected.get("/api/runs/{run_id}")
def run_detail(run_id: str, conn: Conn):
    run = _run_or_404(conn, run_id)
    st = _all_run_stats(conn).get(run["id"], _EMPTY_STATS)
    hit_counts = dict(conn.execute(
        "SELECT h.execution_id, COUNT(*) FROM hits h JOIN executions e ON e.id = h.execution_id "
        "WHERE e.run_id = ? GROUP BY h.execution_id", (run["id"],)).fetchall())
    titles = {x["rule_id"]: x["title"] for x in conn.execute(
        "SELECT rule_id, title FROM ruleset_rules WHERE ruleset_id = ?", (run["ruleset_id"],))}
    by_exec: dict[int, list[dict]] = {}
    for h in conn.execute(
            "SELECT h.execution_id, h.rule_id, h.relation, h.noisy FROM hits h JOIN executions e "
            "ON e.id = h.execution_id WHERE e.run_id = ? ORDER BY h.noisy, h.first_ts, h.rule_id", (run["id"],)):
        r = rule_obj(h["rule_id"], titles.get(h["rule_id"]))
        by_exec.setdefault(h["execution_id"], []).append(
            {"id": r["id"], "title": r["title"], "author": r["author"], "relation": h["relation"],
             "noisy": bool(h["noisy"])})
    execs = [{"id": e["id"], "technique": _tech(e["technique_id"]), "test_guid": e["test_guid"],
              "status": e["status"], "ttd_ms": e["ttd_ms"], "reason": e["reason"],
              "rules_fired": hit_counts.get(e["id"], 0), "rules": by_exec.get(e["id"], []), "started_at": e["started_at"], "ended_at": e["ended_at"]}
             for e in db.list_executions(conn, run["id"])]
    return {**_run_out(run), **st, "executions": execs,
            "gaps": [_gap_out(g) for g in db.list_gaps(conn, run["id"])],
            "noisy_rules": _noisy_rules(conn, run)}


def _report_name(run_id: int, ext: str) -> str:
    return f"purplebench-run-{run_id}-report.{ext}"


@protected.get("/api/runs/{run_id}/report.md")
def report_md(run_id: str, conn: Conn):
    run = _run_or_404(conn, run_id)
    return _attachment(reports.exercise_report_md(conn, run["id"], db.now_utc()),
                       "text/markdown; charset=utf-8", _report_name(run["id"], "md"))


@protected.get("/api/runs/{run_id}/report.html")
def report_html(run_id: str, conn: Conn):
    run = _run_or_404(conn, run_id)
    return _attachment(reports.exercise_report_html(conn, run["id"], db.now_utc()),
                       "text/html; charset=utf-8", _report_name(run["id"], "html"))


# -- run upload ----------------------------------------------------------------------------------------

UPLOAD_TYPES = {"application/json", "text/json", "application/octet-stream", "text/plain"}
READ_CHUNK = 1024 * 1024


@protected.post("/api/runs", status_code=201)
async def upload_run(request: Request, _w: Annotated[str, Writer], conn: Conn):
    """Import a lab run file (format purplebench-run, version 2) sent as multipart field ``file``."""
    limit = config.max_upload_bytes()
    mb = limit // (1024 * 1024)
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "multipart/form-data":
        raise HTTPException(415, "Send the run file as multipart/form-data in a field named 'file'")
    form = await request.form(max_files=1, max_fields=4)
    try:
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise HTTPException(400, "Missing file field named 'file'")
        part_type = (upload.content_type or "").split(";")[0].strip().lower()
        if part_type and part_type not in UPLOAD_TYPES:
            raise HTTPException(415, "The run file must be JSON (application/json)")
        chunks, size = [], 0
        while True:
            chunk = await upload.read(READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise HTTPException(413, f"Run file too large (max {mb} MB)")
            chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw.strip():
            raise HTTPException(400, "The uploaded file is empty")
        if b"\x00" in raw:
            raise HTTPException(400, "The run file contains NUL bytes")
        ruleset_id = None
        rs = form.get("ruleset_id")
        if rs not in (None, ""):
            if not isinstance(rs, str) or not _DIGITS.match(rs) or db.get_ruleset(conn, int(rs)) is None:
                raise HTTPException(400, "ruleset_id is not a known rule set")
            ruleset_id = int(rs)
    finally:
        await form.close()

    def do_import() -> int:
        if ruleset_id is None:
            rulesets.ensure_bundled_ruleset(conn)  # an empty database has no rule set to score with
        return runfile.import_run(conn, raw, ruleset_id=ruleset_id)

    try:
        run_id = await run_in_threadpool(do_import)
    except runfile.RunFileError as exc:
        raise HTTPException(400, str(exc)) from None
    run = db.get_run(conn, run_id)
    return {"run_id": run_id, "run": _run_out(run), **_all_run_stats(conn).get(run_id, _EMPTY_STATS),
            "url": f"/api/runs/{run_id}"}


# -- executions --------------------------------------------------------------------------------------

MAX_EVENT_PAGE = 200
FIELD_OUT_CHARS = 2000
_REF_RECORDED = re.compile(r"^[A-Za-z0-9._-]{1,64}(/[A-Za-z0-9._-]{1,128}){0,3}\.jsonl\.gz$")
_REF_LAB = re.compile(r"^lab_events/(run[0-9]{1,9}_[0-9]{1,9}\.jsonl\.gz)$")


def _events_path(mode: str, ref: str) -> Path | None:
    if mode == "lab":
        m = _REF_LAB.match(ref)
        return runfile.events_dir() / m.group(1) if m else None
    if not _REF_RECORDED.match(ref) or ".." in Path(ref).parts:
        return None
    root = (library.DATA_DIR / "telemetry").resolve()
    path = (root / ref).resolve()
    return path if path.is_relative_to(root) else None


def _match_index(hits: list[dict]) -> dict[tuple[str | None, int], list[str]]:
    """(channel or None, record id) -> rules that matched it. Recorded hits store plain record ids; lab hits
    store [channel, record id] pairs."""
    idx: dict[tuple[str | None, int], list[str]] = {}
    for h in hits:
        for ref in h["record_ids"]:
            if (isinstance(ref, (list, tuple)) and len(ref) == 2 and isinstance(ref[1], int)
                    and not isinstance(ref[1], bool)):
                key: tuple[str | None, int] = (None if ref[0] is None else str(ref[0]), ref[1])
            elif isinstance(ref, int) and not isinstance(ref, bool):
                key = (None, ref)
            else:
                continue
            idx.setdefault(key, []).append(h["rule_id"])
    return idx


def _event_out(ev: dict, matched: list[str]) -> dict[str, Any]:
    fields, cut = {}, []
    for k, v in list((ev.get("fields") or {}).items())[:200]:
        v = str(v)
        if len(v) > FIELD_OUT_CHARS:
            v = v[:FIELD_OUT_CHARS]
            cut.append(str(k)[:128])
        fields[str(k)[:128]] = v
    return {"ts": ev.get("ts"), "host": ev.get("host"), "channel": ev.get("channel"),
            "event_id": ev.get("event_id"), "record_id": ev.get("record_id"), "fields": fields,
            "truncated_fields": cut, "matched": bool(matched), "matched_rules": sorted(set(matched))}


def _page_events(path: Path, window: tuple[Any, Any] | None, idx: dict, offset: int, limit: int, *,
                 only_matched: bool = False, rule: str | None = None) -> dict[str, Any]:
    """Stream the file and keep only the requested page.

    An event is *valid* when it parses, is an object, has a usable time (when a window applies) and can be
    rendered; invalid lines are skipped and counted, identically whatever the offset, so pages never repeat or
    lose an event. Filters (matched only, one rule) apply before paging.

    With a filter the whole file is scanned, so ``total`` (distinct events passing the filters; an event matched
    by several rules counts once) and ``skipped_lines`` are exact. Without a filter the scan stops once the
    page and one more event are found: ``total`` and ``skipped_lines`` then only count what was scanned
    (``total_is_lower_bound``), because counting every line of a large lab file on each page would be costly.
    """
    items, n, skipped, has_more = [], 0, 0, False
    full_scan = only_matched or rule is not None
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
                if not isinstance(ev, dict):
                    raise TypeError
                if window is not None:
                    t = parse_ts(ev["ts"])
                    if not (window[0] <= t <= window[1]):
                        continue
                rid = ev.get("record_id")
                matched = idx.get((ev.get("channel"), rid), []) + idx.get((None, rid), [])
                if (only_matched and not matched) or (rule is not None and rule not in matched):
                    continue
                out = _event_out(ev, matched)  # validated before any paging decision
            except (AttributeError, TypeError, KeyError, ValueError, RecursionError):
                skipped += 1  # not an event object, deeply nested, or no usable time: left out and counted
                continue
            n += 1
            if n <= offset:
                continue
            if len(items) < limit:
                items.append(out)
            else:
                has_more = True
                if not full_scan:
                    break
    return {"items": items, "has_more": has_more, "skipped_lines": skipped, "total": n,
            "total_is_lower_bound": has_more and not full_scan}


@protected.get("/api/executions/{execution_id}")
def execution(execution_id: str, conn: Conn,
              limit: Annotated[int, Query(ge=1, le=MAX_EVENT_PAGE)] = 50,
              offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
              matched: bool = False,
              rule: Annotated[str | None, Query(max_length=36)] = None):
    if rule is not None and not _UUID.match(rule):
        raise HTTPException(422, "rule must be a rule id (UUID)")
    ex = db.get_execution(conn, _int_id(execution_id, "execution"))
    if ex is None:
        raise HTTPException(404, "execution not found")
    run = db.get_run(conn, ex["run_id"])
    hits = db.list_hits(conn, ex["id"])
    hits_out = [{"rule": rule_obj(h["rule_id"], h["title"], h["origin"]), "first_ts": h["first_ts"],
                 "count": h["count"], "relation": h["relation"], "noisy": h["noisy"], "noise_hits": h["noise_hits"]}
                for h in hits]
    tech = library.get_technique(ex["technique_id"])
    atomic = None
    if tech and tech.atomic and ex["test_guid"] in (None, tech.atomic.guid):
        a = tech.atomic
        atomic = {"guid": a.guid, "name": a.name, "description": a.description, "executor": a.executor,
                  "command": a.command_resolved, "cleanup_command": a.cleanup_command,
                  "elevation_required": a.elevation_required, "supported_platforms": list(a.supported_platforms),
                  "source_url": a.source_url,
                  "note": "Display only. PurpleBench never runs this command; the lab runner does, on an allow-listed target."}
    events: dict[str, Any] = {"source": run["mode"], "items": [], "offset": offset, "limit": limit,
                              "has_more": False, "available": False, "note": None, "skipped_lines": 0,
                              "total": 0, "total_is_lower_bound": False,
                              "skipped_lines_note": "Lines left out because they were not usable events. Exact "
                                                    "when a filter is used; otherwise a lower bound (only the "
                                                    "lines scanned so far are counted)."}
    path = _events_path(run["mode"], ex["events_ref"]) if ex["events_ref"] else None
    if path is None or not path.is_file():
        events["note"] = "The events for this execution are not available."
    else:
        window = None
        if run["mode"] == "recorded" and ex["started_at"]:
            start = parse_ts(ex["started_at"]) - timedelta(seconds=DEFAULT_SKEW_SECONDS)
            end = parse_ts(ex["ended_at"]) if ex["ended_at"] else start + timedelta(seconds=120 + DEFAULT_SKEW_SECONDS)
            window = (start, end)
            events["window"] = {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")}
        try:
            events.update(_page_events(path, window, _match_index(hits), offset, limit, only_matched=matched,
                                       rule=rule.lower() if rule else None))
            events["available"] = True
        except (OSError, ValueError, EOFError):
            events["note"] = "The events for this execution could not be read."
    return {"id": ex["id"], "run": _run_out(run), "technique": _tech(ex["technique_id"]), "test_guid": ex["test_guid"],
            "status": ex["status"], "reason": ex["reason"], "ttd_ms": ex["ttd_ms"],
            "ttd_note": "Time from the execution start to the first matching event (event time, clamped at 0). "
                        "It is not SIEM detection latency.",
            "started_at": ex["started_at"], "ended_at": ex["ended_at"], "atomic_test": atomic,
            "hits": hits_out, "events": events}


# -- coverage ----------------------------------------------------------------------------------------

@protected.get("/api/coverage")
def coverage(conn: Conn, run: Annotated[str | None, Query(max_length=9)] = None):
    r = _selected_run(conn, run)
    return {"run": _run_out(r), **_coverage_out(conn, r)}


@protected.get("/api/coverage/navigator.json")
def coverage_navigator(conn: Conn, run: Annotated[str | None, Query(max_length=9)] = None):
    r = _selected_run(conn, run)
    score, _rows = reports._run_score(conn, r["id"])
    name = f"PurpleBench run {r['id']}: {r['campaign_name']}"[:200]
    layer = navigator.build_layer(
        cov_mod.compute_coverage(score), name=name,
        description=f"{MODE_NOTES[r['mode']]} Rule set {r['ruleset_version']}. 'Missed' means no rule in this "
                    "rule set fired on this telemetry.")
    problems = navigator.validate_layer(layer)
    if problems:
        log.error("Navigator layer for run %s failed validation: %s", r["id"], problems[:5])
        raise HTTPException(500, "Could not build a valid Navigator layer")
    return _attachment(json.dumps(layer, indent=2) + "\n", "application/json",
                       f"purplebench-run-{r['id']}-navigator.json")


# -- rules -------------------------------------------------------------------------------------------

@protected.get("/api/rules")
def rules_list(conn: Conn, run: Annotated[str | None, Query(max_length=9)] = None,
               source: Literal["sigmahq", "custom"] | None = None,
               status: Literal["ok", "unsupported"] | None = None,
               noisy: bool | None = None):
    """Bundled rules with support status, and (for a run) hits, noise and whether its rule set enables them."""
    r = _selected_run(conn, run) if run is not None or _latest_run(conn) else None
    fired: dict[str, int] = {}
    noise: dict[str, dict] = {}
    enabled: set[str] = set()
    if r is not None:
        for rid, n in conn.execute(
                "SELECT h.rule_id, COUNT(*) FROM hits h JOIN executions e ON e.id = h.execution_id "
                "WHERE e.run_id = ? GROUP BY h.rule_id", (r["id"],)):
            fired[rid] = n
        noise = {n["rule_id"]: dict(n) for n in conn.execute("SELECT * FROM rule_noise WHERE run_id = ?", (r["id"],))}
        enabled = {x["rule_id"] for x in conn.execute(
            "SELECT rule_id FROM ruleset_rules WHERE ruleset_id = ?", (r["ruleset_id"],))}
    out = []
    for rid in sorted(_catalog(), key=lambda i: (_catalog()[i]["file"], i)):
        obj = rule_obj(rid)
        if (source and obj["source"] != source) or (status and obj["status"] != status):
            continue
        n = noise.get(rid)
        item = {**obj, "in_ruleset": rid in enabled, "executions_fired": fired.get(rid, 0),
                "baseline_hits": n["hits"] if n else None, "noisy": bool(n["noisy"]) if n else False,
                "evaluation": n["status"] if n else None}
        if noisy is not None and item["noisy"] != noisy:
            continue
        out.append(item)
    return {"run": _run_out(r) if r else None, "rules": out, "licence_notice": rulesets.DRL_URL}


_UUID = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
MAX_RULE_BYTES = 256 * 1024


@protected.get("/api/rules/{rule_id}")
def rule_detail(rule_id: str, conn: Conn):
    cat = _catalog().get(rule_id.lower()) if _UUID.match(rule_id) else None
    if cat is None:
        raise HTTPException(404, "rule not found")
    path = Path(cat["_path"])
    try:
        if path.stat().st_size > MAX_RULE_BYTES:
            raise OSError
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise HTTPException(404, "rule file not available") from None
    rule = _rules_by_id().get(cat["id"])
    hits = [dict(h) for h in conn.execute(
        "SELECT e.run_id, h.execution_id, e.technique_id, h.count, h.relation, h.noisy FROM hits h "
        "JOIN executions e ON e.id = h.execution_id WHERE h.rule_id = ? ORDER BY e.run_id, e.id LIMIT 500",
        (cat["id"],))]
    return {**rule_obj(cat["id"]), "yaml": text, "description": rule.description if rule else None,
            "references": list(rule.references) if rule else [],
            "falsepositives": list(rule.falsepositives) if rule else [],
            "sigma_status": rule.sigma_status if rule else None, "date": rule.date if rule else None,
            "modified": rule.modified if rule else None, "logsource": rule.logsource if rule else {},
            "licence_notice": rulesets.DRL_URL, "hits": hits}


# -- gaps --------------------------------------------------------------------------------------------

@protected.get("/api/gaps")
def gaps_list(conn: Conn, run: Annotated[str | None, Query(max_length=9)] = None,
              status: Literal["open", "closed", "accepted"] | None = None,
              kind: Literal["missed", "telemetry_gap", "partial"] | None = None,
              limit: Annotated[int, Query(ge=1, le=1000)] = 200,
              offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0):
    run_id = _run_or_404(conn, run)["id"] if run is not None else None
    rows = [g for g in db.list_gaps(conn, run_id)
            if (status is None or g["status"] == status) and (kind is None or g["kind"] == kind)]
    return {"total": len(rows), "limit": limit, "offset": offset,
            "gaps": [_gap_out(g) for g in rows[offset:offset + limit]]}


class GapPatch(BaseModel):
    status: Literal["open", "closed", "accepted"] | None = None
    notes: str | None = Field(default=None, max_length=2000)


@protected.patch("/api/gaps/{gap_id}")
def patch_gap(gap_id: str, _w: Annotated[str, Writer], body: GapPatch, conn: Conn):
    gid = _int_id(gap_id, "gap")
    if body.status is None and body.notes is None:
        raise HTTPException(422, "send status and/or notes")
    notes = _clean_text(body.notes, "notes", multiline=True) if body.notes is not None else None
    if not db.update_gap(conn, gid, status=body.status, notes=notes):
        raise HTTPException(404, "gap not found")
    gap = next(g for g in db.list_gaps(conn) if g["id"] == gid)
    return _gap_out(gap)


# Registered last so every @protected route above is included.
app.include_router(protected)
