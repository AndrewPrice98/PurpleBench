"""Vercel entry point: serves the PurpleBench FastAPI app as a Python serverless function.

vercel.json rewrites every /api/* request here; FastAPI routes on the original path, so the body-size
limits (BodyLimitMiddleware matches /api/runs) see the same path as they do locally.
Each function instance builds its own SQLite database in /tmp from backend/data/demo_fixture.json on its
first request (recorded mode only; nothing is executed and no lab is involved). Until that database exists,
data routes answer 503. /tmp is per instance and is lost on a cold start, so the hosted demo resets itself.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# The admin variables (PURPLEBENCH_ADMIN_PASSWORD_HASH, PURPLEBENCH_SECRET_KEY) are optional here: without them
# visitors browse as a read-only guest and nobody can sign in.
# Serverless defaults; any of these can be overridden in Vercel's environment settings.
os.environ.setdefault("PURPLEBENCH_DB", "/tmp/purplebench.db")  # /tmp is the only writable path
os.environ.setdefault("PURPLEBENCH_DEMO", "true")
os.environ.setdefault("PURPLEBENCH_TRUST_PROXY", "true")  # Vercel sets X-Forwarded-For itself
os.environ.setdefault("PURPLEBENCH_MAX_UPLOAD_MB", "4")  # Vercel caps request bodies at 4.5 MB

from purplebench.api import app  # noqa: E402

# No seeding here: the app seeds lazily (at startup, or on the first data request if that failed) and answers
# 503 "Demo data is not available yet" while it cannot. A broken /tmp must not stop the function from loading.

__all__ = ["app"]
