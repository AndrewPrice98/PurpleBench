"""Command line: catalog, docs, demo, serve and create-admin (``python -m purplebench --help``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, catalog, library


def _catalog(args: argparse.Namespace) -> int:
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


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        import getpass

        password = getpass.getpass("Admin password: ")
        if password != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")
    if len(password) < 12:
        sys.exit("Use at least 12 characters.")
    return password


def _update_env_file(path: Path, values: dict[str, str]) -> None:
    """Set keys in a .env file, keeping any other lines as they are."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(values)
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in remaining.items()]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def _create_admin(args: argparse.Namespace) -> int:
    import secrets

    from . import config
    from .auth import hash_password

    password = _read_password(args)
    values = {
        "PURPLEBENCH_ADMIN_USER": args.username,
        "PURPLEBENCH_ADMIN_PASSWORD_HASH": hash_password(password),
        # Reuse an existing secret so current sessions stay valid, unless asked to rotate.
        "PURPLEBENCH_SECRET_KEY": (config.secret_key() if config.secret_key() and not args.rotate_secret
                                   else secrets.token_urlsafe(48)),
    }
    if args.print:
        print("Set these environment variables on your host. Keep them secret.\n")
        for key, value in values.items():
            print(f"{key}={value}")
        print("PURPLEBENCH_TRUST_PROXY=true")
        return 0
    _update_env_file(config.ENV_FILE, {**values, "PURPLEBENCH_COOKIE_SECURE": "false"})
    print(f"Admin '{args.username}' saved to {config.ENV_FILE} (git-ignored).")
    print("Restart the API to pick it up. For a hosted deployment, run again with --print.")
    return 0


DEFAULT_DEMO_DB = Path(__file__).resolve().parent.parent / "data" / "demo.db"


def _server_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    parser.add_argument("--reload", action="store_true", help="restart when the code changes (development)")


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("purplebench.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def _remove_db(path: Path) -> None:
    for candidate in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        candidate.unlink(missing_ok=True)


def _demo(args: argparse.Namespace) -> int:
    """Load the recorded-mode demo into its own database file, then optionally serve it."""
    import os

    if args.check:
        import importlib.util

        script = Path(__file__).resolve().parent.parent / "scripts" / "build_demo.py"
        spec = importlib.util.spec_from_file_location("build_demo", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.main(["--check"])
    path = Path(args.db or DEFAULT_DEMO_DB).resolve()
    # The demo always runs on its own file, never on PURPLEBENCH_DB from backend/.env.
    os.environ["PURPLEBENCH_DB"] = str(path)
    if args.reset:
        _remove_db(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    from . import db, demo

    conn = db.connect(path)
    try:
        if demo.seed(conn):
            print(f"Loaded the recorded-mode demo into {path}")
        else:
            print(f"{path} already holds a demo; left as it is (use --reset to reload)")
        for r in db.list_runs(conn):
            print(f"  run {r['id']}: campaign {r['campaign_id']}, {r['mode']} mode, started {r['started_at']}")
    finally:
        conn.close()
    if args.serve:
        # Demo mode: read-only guests unless an admin signs in (see create-admin).
        os.environ["PURPLEBENCH_DEMO"] = "true"
        return _serve(args)
    return 0


def _docs(args: argparse.Namespace) -> int:
    from . import docsgen

    text = docsgen.render()
    if args.check:
        current = docsgen.OUT.read_text(encoding="utf-8").replace("\r\n", "\n") if docsgen.OUT.exists() else ""
        if current != text:
            print("docs/COVERAGE.md is out of date; run: python -m purplebench docs", file=sys.stderr)
            return 1
        print("OK: docs/COVERAGE.md is current")
        return 0
    docsgen.OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(docsgen.OUT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"wrote {docsgen.OUT}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="purplebench")
    ap.add_argument("--version", action="version", version=f"purplebench {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cat = sub.add_parser("catalog", help="technique library and recorded telemetry")
    cat.add_argument("--check", action="store_true", required=True,
                     help="validate the manifest against the committed files")
    cat.add_argument("--data-dir", help="data directory (default: backend/data)")
    cat.set_defaults(func=_catalog)
    admin = sub.add_parser("create-admin", help="set the dashboard login (writes backend/.env)")
    admin.add_argument("--username", default="admin")
    admin.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    admin.add_argument("--print", action="store_true",
                       help="print the variables for a hosting provider instead of writing .env")
    admin.add_argument("--rotate-secret", action="store_true", help="new signing secret (logs everyone out)")
    admin.set_defaults(func=_create_admin)
    docs = sub.add_parser("docs", help="generate docs/COVERAGE.md (Sigma support and demo coverage)")
    docs.add_argument("--check", action="store_true", help="exit 1 if the committed file is stale")
    docs.set_defaults(func=_docs)
    demo = sub.add_parser("demo", help="load the recorded-mode demo into a separate database")
    demo.add_argument("--db", type=Path, default=None, metavar="PATH", help=f"demo database file (default: {DEFAULT_DEMO_DB})")
    demo.add_argument("--reset", action="store_true", help="delete the demo database first and reload it")
    demo.add_argument("--serve", action="store_true", help="start the API on it afterwards (demo mode)")
    demo.add_argument("--check", action="store_true",
                      help="verify data/demo_fixture.json matches a rebuild with the real evaluator (CI)")
    _server_args(demo)
    demo.set_defaults(func=_demo)
    serve = sub.add_parser("serve", help="run the API server")
    _server_args(serve)
    serve.set_defaults(func=_serve)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
