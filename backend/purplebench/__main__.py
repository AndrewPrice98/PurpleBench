"""Command line: ``python -m purplebench catalog --check`` and ``python -m purplebench create-admin``."""

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
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
