"""Configuration: blank environment values mean "unset", and backend/.env.example works as shipped."""

import os

import pytest
from fastapi.testclient import TestClient

from conftest import TEST_HASH, TEST_PASSWORD, TEST_USER
from purplebench import api, config, db

ENV_EXAMPLE = config.BACKEND_DIR / ".env.example"
NAMES = [
    "PURPLEBENCH_ADMIN_USER", "PURPLEBENCH_ADMIN_PASSWORD_HASH", "PURPLEBENCH_SECRET_KEY", "PURPLEBENCH_DB",
    "PURPLEBENCH_DATA_DIR", "PURPLEBENCH_SESSION_HOURS", "PURPLEBENCH_COOKIE_SECURE", "PURPLEBENCH_TRUST_PROXY",
    "PURPLEBENCH_MAX_UPLOAD_MB", "PURPLEBENCH_DEMO", "PURPLEBENCH_GUEST",
]


def _clear(monkeypatch):
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)


def test_env_example_loaded_verbatim_starts_the_app(monkeypatch, tmp_path):
    _clear(monkeypatch)
    config.load_env_file(ENV_EXAMPLE)
    # the loader writes straight into os.environ; make sure the test undoes it
    for name in NAMES:
        if name in os.environ:
            monkeypatch.setenv(name, os.environ[name])
    # an owner fills in the secrets (create-admin does this); everything else stays as copied
    monkeypatch.setenv("PURPLEBENCH_ADMIN_PASSWORD_HASH", TEST_HASH)
    monkeypatch.setenv("PURPLEBENCH_SECRET_KEY", "test-secret-" + "x" * 40)
    monkeypatch.setenv("PURPLEBENCH_COOKIE_SECURE", "false")
    monkeypatch.setenv("PURPLEBENCH_DATA_DIR", "")  # a blank value must not break library lookups either
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    with TestClient(api.app) as c:
        assert c.get("/api/health").status_code == 200
        r = c.post("/api/auth/login", json={"username": TEST_USER, "password": TEST_PASSWORD})
        assert r.status_code == 200
        assert c.get("/api/auth/me").json()["username"] == TEST_USER


@pytest.mark.parametrize("name", NAMES)
def test_blank_values_equal_unset_for_every_getter(monkeypatch, name):
    _clear(monkeypatch)
    getters = [config.db_path, config.max_upload_bytes, config.admin_user, config.admin_password_hash,
               config.secret_key, config.session_hours, config.cookie_secure, config.demo_mode,
               config.guest_enabled, config.trust_proxy]
    unset = [g() for g in getters]
    monkeypatch.setenv(name, "")
    assert [g() for g in getters] == unset


def test_blank_db_path_opens_the_default_file_name(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("PURPLEBENCH_DB", "")
    assert config.db_path() == config.DATA_DIR / "purplebench.db"


def test_invalid_session_hours_falls_back(monkeypatch):
    monkeypatch.setenv("PURPLEBENCH_SESSION_HOURS", "soon")
    assert config.session_hours() == 8.0


def test_blank_db_does_not_break_connect(monkeypatch, tmp_path):
    monkeypatch.setenv("PURPLEBENCH_DB", "")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    c = db.connect()
    c.close()
    assert (tmp_path / "purplebench.db").exists()
