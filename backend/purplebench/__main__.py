"""Command line: ``python -m purplebench catalog --check``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, catalog, library


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="purplebench")
    ap.add_argument("--version", action="version", version=f"purplebench {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cat = sub.add_parser("catalog", help="technique library and recorded telemetry")
    cat.add_argument("--check", action="store_true", required=True,
                     help="validate the manifest against the committed files")
    cat.add_argument("--data-dir", help="data directory (default: backend/data)")
    args = ap.parse_args(argv)

    errors = catalog.check_catalog(args.data_dir)
    if errors:
        for e in errors:
            print("FAIL", e)
        print(f"{len(errors)} problem(s)")
        return 1
    manifest = catalog.load_manifest(args.data_dir)
    lib = Path(args.data_dir) / "library.json" if args.data_dir else None
    techs = library.list_techniques(lib)
    tests = [f for f in manifest["files"] if f["kind"] == "test"]
    print(f"OK: {len(techs)} techniques, {len(tests)} test files, "
          f"{sum(f['events'] for f in manifest['files'])} events, {manifest['total_bytes']} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
