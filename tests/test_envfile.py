import logging

from reviewer.envfile import load_env_file, parse_env


def test_parse_variants():
    text = (
        "# comment\n\nGITHUB_TOKEN=abc123\nexport A=1\nB=\"quoted val\"\nC='x'\n"
        "D=plain # trailing\nbad line\n1BAD=x\n"
    )
    assert parse_env(text) == {"GITHUB_TOKEN": "abc123", "A": "1", "B": "quoted val", "C": "x", "D": "plain"}


def test_load_sets_missing_but_real_env_wins(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("T_ONE=fromfile\nT_TWO=fromfile\nT_EMPTY=\n", encoding="utf-8")
    monkeypatch.delenv("T_ONE", raising=False)
    monkeypatch.delenv("T_EMPTY", raising=False)
    monkeypatch.setenv("T_TWO", "fromshell")
    names = load_env_file(f)
    import os
    assert names == ["T_ONE"]
    assert os.environ["T_ONE"] == "fromfile" and os.environ["T_TWO"] == "fromshell"
    assert "T_EMPTY" not in os.environ
    monkeypatch.delenv("T_ONE")


def test_bom_and_missing_file(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_bytes("﻿T_BOM=ok\n".encode("utf-8"))
    monkeypatch.delenv("T_BOM", raising=False)
    assert load_env_file(f) == ["T_BOM"]
    import os
    monkeypatch.delenv("T_BOM")
    assert load_env_file(tmp_path / "nope.env") == []


def test_values_never_logged(tmp_path, monkeypatch, caplog):
    f = tmp_path / ".env"
    f.write_text("T_SECRET=ghp_SUPERSECRETVALUE1234567890\n")
    monkeypatch.delenv("T_SECRET", raising=False)
    with caplog.at_level(logging.DEBUG, logger="agent"):
        load_env_file(f)
    assert "T_SECRET" in caplog.text and "SUPERSECRET" not in caplog.text
    monkeypatch.delenv("T_SECRET", raising=False)

