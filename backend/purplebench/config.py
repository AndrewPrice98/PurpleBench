"""Runtime configuration, read from environment variables.

Values are read through functions (not module constants) so tests can
override them with environment variables at any time.

For local development, variables can also live in backend/.env (git-ignored).
Real environment variables always win, so a hosting provider's settings
(for example hosting-provider project environment variables) take precedence.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"
RULES_DIR = BACKEND_DIR / "rules"
DEMO_FIXTURE = DATA_DIR / "demo_fixture.json"
ENV_FILE = BACKEND_DIR / ".env"


def load_env_file(path: Path = ENV_FILE) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, optional quotes.
    Never overrides variables that are already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_env_file()


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def db_path() -> Path:
    return Path(os.environ.get("PURPLEBENCH_DB", DATA_DIR / "purplebench.db"))


def max_upload_bytes() -> int:
    """Largest accepted run-file upload: 32 MB locally (the run-file format cap), 4 MB on the hosted demo
    (a serverless function has little memory). ``PURPLEBENCH_MAX_UPLOAD_MB`` overrides either."""
    default = "4" if demo_mode() else "32"
    try:
        mb = float(os.environ.get("PURPLEBENCH_MAX_UPLOAD_MB") or default)
    except ValueError:
        mb = float(default)
    return max(1, int(mb * 1024 * 1024))


# -- authentication --------------------------------------------------------------------

def admin_user() -> str:
    return os.environ.get("PURPLEBENCH_ADMIN_USER", "admin")


def admin_password_hash() -> str:
    return os.environ.get("PURPLEBENCH_ADMIN_PASSWORD_HASH", "")


def secret_key() -> str:
    """Key that signs session tokens. Must be long and random; rotating it logs everyone out."""
    return os.environ.get("PURPLEBENCH_SECRET_KEY", "")


def session_hours() -> float:
    return float(os.environ.get("PURPLEBENCH_SESSION_HOURS", "8"))


def cookie_secure() -> bool:
    """Send the session cookie over HTTPS only. On by default (production); the local
    .env written by `create-admin` turns it off for plain-http development."""
    return _flag("PURPLEBENCH_COOKIE_SECURE", True)


def demo_mode() -> bool:
    """Hosted demo: data is seeded from the recorded-mode demo runs."""
    return _flag("PURPLEBENCH_DEMO", False)


def guest_enabled() -> bool:
    """Anonymous read-only access. Defaults to on in demo mode, off everywhere else."""
    return _flag("PURPLEBENCH_GUEST", demo_mode())


def trust_proxy() -> bool:
    """Use X-Forwarded-For for the client IP. Enable only behind a proxy you control."""
    return _flag("PURPLEBENCH_TRUST_PROXY", False)
