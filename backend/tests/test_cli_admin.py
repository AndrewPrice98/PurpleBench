import io

import pytest

from purplebench import auth, config
from purplebench.__main__ import main


def test_create_admin_writes_env_file(tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text("KEEP=me\n", encoding="utf-8")
    monkeypatch.setattr(config, "ENV_FILE", env)
    monkeypatch.setenv("PURPLEBENCH_SECRET_KEY", "")
    monkeypatch.setattr("sys.stdin", io.StringIO("a long enough password\n"))
    assert main(["create-admin", "--username", "boss", "--password-stdin"]) == 0
    values = dict(line.split("=", 1) for line in env.read_text(encoding="utf-8").splitlines())
    assert values["KEEP"] == "me" and values["PURPLEBENCH_ADMIN_USER"] == "boss"
    assert values["PURPLEBENCH_COOKIE_SECURE"] == "false" and len(values["PURPLEBENCH_SECRET_KEY"]) >= 32
    assert auth.verify_password("a long enough password", values["PURPLEBENCH_ADMIN_PASSWORD_HASH"])
    assert "a long enough password" not in capsys.readouterr().out


def test_create_admin_print_does_not_write(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("sys.stdin", io.StringIO("a long enough password\n"))
    assert main(["create-admin", "--password-stdin", "--print"]) == 0
    out = capsys.readouterr().out
    assert "PURPLEBENCH_ADMIN_PASSWORD_HASH=pbkdf2_sha256:" in out and "PURPLEBENCH_TRUST_PROXY=true" in out
    assert not (tmp_path / ".env").exists()


def test_create_admin_rejects_short_password(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit):
        main(["create-admin", "--password-stdin"])
