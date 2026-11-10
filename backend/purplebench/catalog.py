"""Technique catalog: ATT&CK techniques mapped to Atomic tests and recorded telemetry.

``check_catalog`` validates the committed telemetry against ``data/telemetry/manifest.json`` (file
hashes, event counts by channel and event id, window metadata, orphans) and against the technique
library. CI runs it as ``python -m purplebench catalog --check``.
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

from . import library

MAX_TOTAL_BYTES = 30 * 1024 * 1024  # size budget for committed telemetry
MIN_TECHNIQUES, MAX_TECHNIQUES, MIN_TACTICS = 20, 30, 8
EVENT_KEYS = {"ts", "channel", "event_id", "host", "record_id", "fields"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(data_dir: Path | str | None = None) -> dict[str, Any]:
    root = Path(data_dir) if data_dir else library.DATA_DIR
    with open(root / "telemetry" / "manifest.json", encoding="utf-8") as fh:
        return json.load(fh)


def _scan_file(path: Path) -> tuple[int, str, dict[str, dict[str, int]], list[str]]:
    """Return (event count, content sha256, counts by channel/event id, problems)."""
    problems: list[str] = []
    h = hashlib.sha256()
    n = 0
    by: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    prev = ""
    with gzip.open(path, "rb") as gz:
        for raw in gz:
            h.update(raw)
            ev = json.loads(raw)
            n += 1
            if set(ev) != EVENT_KEYS:
                problems.append(f"line {n}: unexpected keys {sorted(set(ev) ^ EVENT_KEYS)}")
                break
            if ev["ts"] < prev:
                problems.append(f"line {n}: events are not in timestamp order")
                break
            prev = ev["ts"]
            by[ev["channel"]][str(ev["event_id"])] += 1
    counts = {ch: dict(sorted(c.items(), key=lambda kv: int(kv[0]))) for ch, c in sorted(by.items())}
    return n, h.hexdigest(), counts, problems


def check_catalog(data_dir: Path | str | None = None) -> list[str]:
    """Return a list of problems; empty means the catalog is consistent."""
    root = Path(data_dir) if data_dir else library.DATA_DIR
    tele = root / "telemetry"
    errors: list[str] = []
    try:
        manifest = load_manifest(root)
    except (OSError, ValueError) as exc:
        return [f"cannot read manifest: {exc}"]

    files = manifest.get("files", [])
    listed = {f["path"] for f in files}
    if len(listed) != len(files):
        errors.append("manifest lists a path more than once")

    total = 0
    for f in files:
        p = tele / f["path"]
        if not p.is_file():
            errors.append(f"{f['path']}: file listed in manifest is missing")
            continue
        total += p.stat().st_size
        if _sha256(p) != f["sha256"]:
            errors.append(f"{f['path']}: sha256 does not match manifest")
            continue
        if p.stat().st_size != f["bytes"]:
            errors.append(f"{f['path']}: size does not match manifest")
        try:
            n, content_hash, counts, problems = _scan_file(p)
        except (OSError, ValueError, EOFError) as exc:
            errors.append(f"{f['path']}: unreadable ({type(exc).__name__})")
            continue
        errors.extend(f"{f['path']}: {x}" for x in problems)
        if n != f["events"]:
            errors.append(f"{f['path']}: {n} events, manifest says {f['events']}")
        if content_hash != f["content_sha256"]:
            errors.append(f"{f['path']}: content hash does not match manifest")
        if counts != f["by_channel"]:
            errors.append(f"{f['path']}: event counts by channel/event id do not match manifest")
        if f["kind"] == "test":
            w = f.get("window") or {}
            if w.get("method") not in ("process-creation-anchor", "whole-file-head"):
                errors.append(f"{f['path']}: window method missing or unknown")
            if f["license"] != "Apache-2.0" or not f.get("source", {}).get("url"):
                errors.append(f"{f['path']}: licence or source URL missing")
    if total > MAX_TOTAL_BYTES:
        errors.append(f"telemetry is {total} bytes, over the {MAX_TOTAL_BYTES} budget")
    if total != manifest.get("total_bytes"):
        errors.append("manifest total_bytes does not match the files")

    on_disk = {p.relative_to(tele).as_posix() for p in tele.rglob("*.jsonl.gz")}
    for orphan in sorted(on_disk - listed):
        errors.append(f"{orphan}: telemetry file not listed in manifest")

    if not any(f["kind"] == "baseline" for f in files):
        errors.append("manifest has no baseline file")
    for name in ("LICENSE-Apache-2.0.txt", "NOTICE.md"):
        if not (tele / name).is_file():
            errors.append(f"telemetry/{name} is missing (licence attribution)")

    # Library <-> manifest consistency.
    try:
        techs = library.list_techniques(root / "library.json")
    except (OSError, ValueError, KeyError) as exc:
        errors.append(f"cannot read library.json: {exc}")
        return errors
    if not MIN_TECHNIQUES <= len(techs) <= MAX_TECHNIQUES:
        errors.append(f"library has {len(techs)} techniques, expected {MIN_TECHNIQUES}-{MAX_TECHNIQUES}")
    tactics = {x for t in techs for x in t.tactics}
    if len(tactics) < MIN_TACTICS:
        errors.append(f"library covers {len(tactics)} tactics, expected at least {MIN_TACTICS}")
    test_files = {f["path"]: f for f in files if f["kind"] == "test"}
    seen_ids: set[str] = set()
    for t in techs:
        if t.attack_id in seen_ids:
            errors.append(f"{t.attack_id}: duplicate technique")
        seen_ids.add(t.attack_id)
        bad_tactics = [x for x in t.tactics if x not in library.TACTICS]
        if bad_tactics or not t.tactics:
            errors.append(f"{t.attack_id}: unknown or missing tactics {bad_tactics}")
        f = test_files.get(t.telemetry)
        if f is None:
            errors.append(f"{t.attack_id}: telemetry file {t.telemetry} is not in the manifest")
            continue
        if f["technique"] != t.attack_id:
            errors.append(f"{t.attack_id}: manifest file belongs to {f['technique']}")
        if (t.atomic.guid if t.atomic else None) != f["atomic_guid"]:
            errors.append(f"{t.attack_id}: Atomic GUID differs between library and manifest")
        want_kind = library.EXECUTION_ATOMIC if t.atomic else library.EXECUTION_RECORDED
        if t.execution_kind != want_kind:
            errors.append(f"{t.attack_id}: execution_kind {t.execution_kind!r} does not match atomic link")
        if t.atomic is None and f["link"] != "recorded":
            errors.append(f"{t.attack_id}: no Atomic test but link is {f['link']!r}")
        if t.atomic is not None and f["link"] == "recorded":
            errors.append(f"{t.attack_id}: Atomic test set but link is 'recorded'")
        if t.atomic is not None and "windows" not in t.atomic.supported_platforms:
            errors.append(f"{t.attack_id}: Atomic test is not a Windows test")
    for path in sorted(set(test_files) - {t.telemetry for t in techs}):
        errors.append(f"{path}: manifest test file has no technique in the library")
    return errors
