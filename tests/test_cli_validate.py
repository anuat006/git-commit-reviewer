import pytest

import reviewer.cli as cli
from reviewer.cli import build_parser, main, parse_repo, validate_args


def args(tmp_path, commit="04a72c072a", *extra):
    return build_parser().parse_args(["--repo", str(tmp_path), "--commit", commit, *extra])


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("ISSUE_REPO", "APPROVAL_TTL", "REVIEWER_LOG_LEVEL", "AUDIT_LOG"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cli, "load_env_file", lambda *a, **k: [])      # never read the real .env


def test_parser_has_only_repo_commit_model():
    dests = {a.dest for a in build_parser()._actions if a.dest != "help"}
    assert dests == {"repo", "commit", "model"}
    assert args(".").model == "local"
    assert args(".", "abcd", "--model", "copilot").model == "copilot"
    with pytest.raises(SystemExit):
        args(".", "abcd", "--model", "gpt")


def test_valid_settings_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSUE_REPO", "https://github.com/o/tracker.git")
    monkeypatch.setenv("APPROVAL_TTL", "300")
    monkeypatch.setenv("AUDIT_LOG", "x.jsonl")
    cfg = validate_args(args(tmp_path))
    assert (cfg.issue_repo, cfg.approval_ttl, cfg.audit_log, cfg.log_level) == ("o/tracker", 300, "x.jsonl", "INFO")


def test_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("ISSUE_REPO", "o/t")
    cfg = validate_args(args(tmp_path))
    assert cfg.approval_ttl == 120 and cfg.audit_log == "audit_log.jsonl"


def test_reports_every_problem(tmp_path, monkeypatch):
    monkeypatch.setenv("APPROVAL_TTL", "0")
    monkeypatch.setenv("REVIEWER_LOG_LEVEL", "LOUD")
    a = build_parser().parse_args(["--repo", str(tmp_path / "missing"), "--commit", "zzz"])
    with pytest.raises(ValueError) as e:
        validate_args(a)
    for part in ("--repo", "--commit", "ISSUE_REPO", "APPROVAL_TTL", "REVIEWER_LOG_LEVEL"):
        assert part in str(e.value)


def test_parse_repo_variants():
    for v in ("https://github.com/anuat006/issue-tracker", "github.com/anuat006/issue-tracker/",
              "https://github.com/anuat006/issue-tracker.git", "anuat006/issue-tracker"):
        assert parse_repo(v) == "anuat006/issue-tracker"
    for bad in ("", "justname", "https://example.com/a/b/c"):
        with pytest.raises(ValueError):
            parse_repo(bad)


def test_main_returns_2_and_starts_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "McpClient", lambda *a, **k: pytest.fail("must not start the MCP client"))
    monkeypatch.setattr(cli, "ModelGateway", lambda *a, **k: pytest.fail("must not start the model"))
    assert main(["--repo", str(tmp_path / "nope"), "--commit", "abc1"]) == 2
    assert "--repo" in capsys.readouterr().err


def test_main_uses_issue_repo_and_ttl_from_env(tmp_path, monkeypatch):
    seen = {}

    class FakeAgent:
        def __init__(self, client, gate, audit, llm=None):
            seen["ttl"], seen["llm"] = gate.ttl, llm
        def run(self, req):
            seen["req"] = req
            from reviewer.schemas import ReviewOutcome
            return ReviewOutcome(status="clean", request=req, message="ok")

    class FakeGateway:
        label = "fake"
        def __init__(self, provider): seen["provider"] = provider
        def start(self): pass
        def close(self): seen["closed"] = True

    monkeypatch.setattr(cli, "RootAgent", FakeAgent)
    monkeypatch.setattr(cli, "McpClient", lambda *a, **k: object())
    monkeypatch.setattr(cli, "ModelGateway", FakeGateway)
    monkeypatch.setenv("ISSUE_REPO", "https://github.com/anuat006/issue-tracker")
    monkeypatch.setenv("APPROVAL_TTL", "45")
    monkeypatch.setenv("AUDIT_LOG", str(tmp_path / "a.jsonl"))
    assert main(["--repo", str(tmp_path), "--commit", "abc1", "--model", "copilot"]) == 0
    assert seen["req"].github_repo == "anuat006/issue-tracker" and seen["ttl"] == 45
    assert seen["provider"] == "copilot" and seen["closed"]
