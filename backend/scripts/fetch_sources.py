"""Download the untrusted source files (Splunk attack_data logs and manifests, Atomic Red Team YAML).

Usage: python -I scripts/fetch_sources.py <sources_dir>

Sequential, streamed, resumable by size check. Nothing downloaded is executed or imported.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SPLUNK_COMMIT = "c8af10d015d392fca97f9eb65181e9f06bc18e40"
ATOMIC_COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/" + SPLUNK_COMMIT + "/"
RAW_SPLUNK = "https://raw.githubusercontent.com/splunk/attack_data/" + SPLUNK_COMMIT + "/"
RAW_ATOMIC = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/" + ATOMIC_COMMIT + "/"
UA = "purplebench-dataset-builder"


def _get(url: str, dest: Path, expect: int | None = None) -> None:
    if dest.exists() and (expect is None or dest.stat().st_size == expect):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
                while chunk := r.read(1 << 20):
                    f.write(chunk)
            if expect is not None and dest.stat().st_size != expect:
                raise OSError(f"size mismatch {dest.stat().st_size} != {expect}")
            return
        except (urllib.error.URLError, OSError) as e:
            print("retry", url, e, file=sys.stderr)
            time.sleep(3 * (attempt + 1))
    raise SystemExit(f"failed: {url}")


def main(argv: list[str]) -> None:
    root = Path(argv[1])
    cands = json.loads(Path(__file__).resolve().parent.parent.joinpath("data/technique_candidates.json").read_text("utf-8"))
    for c in cands:
        rel = c["path"]  # datasets/attack_techniques/<id>/<set>/windows-sysmon.log
        folder = rel.rsplit("/", 1)[0]
        did = c["dataset_id"]
        # dataset manifest yml: name unknown, list via the log folder's yml; fetch known names through the API listing
        listing = root / "listings" / f"{did}.json"
        _get(f"https://api.github.com/repos/splunk/attack_data/contents/{folder}?ref={SPLUNK_COMMIT}", listing)
        for item in json.loads(listing.read_text("utf-8")):
            if item["name"].endswith(".yml"):
                _get(RAW_SPLUNK + item["path"], root / "yml" / f"{did}.yml")
        _get(RAW_ATOMIC + f"atomics/{c['attack_id']}/{c['attack_id']}.yaml", root / "atomics" / f"{c['attack_id']}.yaml")
        print("meta", did, flush=True)
    for c in cands:
        print("log", c["dataset_id"], c["size"], flush=True)
        _get(MEDIA + c["path"], root / "logs" / f"{c['dataset_id']}.log", c["size"])
    _get(RAW_SPLUNK + "LICENSE", root / "licenses" / "splunk-attack_data-LICENSE.txt")
    _get(RAW_ATOMIC + "LICENSE.txt", root / "licenses" / "atomic-red-team-LICENSE.txt")
    print("done")


if __name__ == "__main__":
    main(sys.argv)
