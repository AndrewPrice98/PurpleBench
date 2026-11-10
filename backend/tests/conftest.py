"""Shared pytest fixtures: known admin credentials and database fixtures."""

import pytest

from purplebench.auth import hash_password, limiter

TEST_USER = "admin"
TEST_PASSWORD = "correct horse battery staple"
# Few iterations keep the suite fast; production hashes use auth.DEFAULT_ITERATIONS.
TEST_HASH = hash_password(TEST_PASSWORD, iterations=1_000)


@pytest.fixture(autouse=True)
def auth_env(monkeypatch):
    """Known admin credentials for every test, regardless of any local backend/.env."""
    monkeypatch.setenv("PURPLEBENCH_ADMIN_USER", TEST_USER)
    monkeypatch.setenv("PURPLEBENCH_ADMIN_PASSWORD_HASH", TEST_HASH)
    monkeypatch.setenv("PURPLEBENCH_SECRET_KEY", "test-secret-" + "x" * 40)
    monkeypatch.setenv("PURPLEBENCH_COOKIE_SECURE", "false")  # TestClient talks plain http
    monkeypatch.setenv("PURPLEBENCH_TRUST_PROXY", "false")
    monkeypatch.delenv("PURPLEBENCH_DEMO", raising=False)
    monkeypatch.delenv("PURPLEBENCH_GUEST", raising=False)
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def db_file(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv("PURPLEBENCH_DB", str(path))
    return path


@pytest.fixture
def conn(db_file):
    from purplebench import db

    c = db.connect(db_file)
    yield c
    c.close()


@pytest.fixture
def seeded_db(db_file):
    """A database holding the recorded-mode demo (runs 1 to 4)."""
    from purplebench import db, demo

    c = db.connect(db_file)
    try:
        assert demo.seed(c)
    finally:
        c.close()
    return db_file
