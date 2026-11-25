import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from reviewer.agent import RootAgent
from reviewer.approval import ApprovalGate, issue_token
from reviewer.audit import AuditLog
from reviewer.mcp_client import McpClient
from reviewer.schemas import ReviewRequest
from reviewer_server import git_tool, github_tool, scanner

ROOT = Path(__file__).resolve().parents[1]
SECRET = "srv-secret"
FAKE_AWS = "AKIAFAKEFAKEFAKE1234"            # fake credential, never real


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "demo"
    r.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    g = lambda *a: subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True, env=env)
    g("init", "-q")
    (r / "README.md").write_text("hello\n")
    g("add", "."); g("commit", "-qm", "init")
    (r / "config.py").write_text(f'AWS_KEY = "{FAKE_AWS}"\nDEBUG = True\n')
    g("add", "."); g("commit", "-qm", "add config")
    sha = subprocess.run(["git", "-C", str(r), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return r, sha


def script(path: Path, body: str) -> str:
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


FAKE_GITLEAKS = '''
import json, sys
a = sys.argv[1:]
open(__file__ + ".args", "w").write(json.dumps(a))
report = a[a.index("--report-path") + 1]
json.dump([
 {"RuleID": "aws-access-token", "Description": "AWS key", "StartLine": 1, "File": "config.py",
  "Match": "AWS_KEY = \\"REDACTED\\"", "Secret": "REDACTED"},
 {"RuleID": "unsafe-config-debug", "Description": "Debug mode enabled", "StartLine": 2,
  "File": "config.py", "Match": "DEBUG = REDACTED", "Secret": "REDACTED"},
], open(report, "w"))
'''

import threading  # noqa: E402
import time  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402


class FakeGitHub:
    """Local stand-in for api.github.com: records requests, answers as configured."""

    def __init__(self, status=201, body=None, delay=0.0):
        self.status, self.delay, self.requests = status, delay, []
        self.body = body
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "json": json.loads(raw)})
                time.sleep(outer.delay)
                repo = self.path.split("/repos/")[1].rsplit("/issues", 1)[0]
                body = outer.body if outer.body is not None else {
                    "number": 42, "html_url": f"https://github.com/{repo}/issues/42"}
                data = json.dumps(body).encode()
                try:
                    self.send_response(outer.status); self.send_header("Content-Length", str(len(data)))
                    self.end_headers(); self.wfile.write(data)
                except OSError:
                    pass

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


@pytest.fixture
def gh_api(monkeypatch):
    made = []

    def make(**kw):
        g = FakeGitHub(**kw); made.append(g)
        monkeypatch.setenv("GITHUB_API_URL", g.url)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_FAKEtokenFAKEtokenFAKEtokenFAKE0000")
        monkeypatch.setenv("REVIEWER_APPROVAL_SECRET", SECRET)
        github_tool._consumed.clear()
        return g
    yield make
    for g in made:
        g.close()


ISSUE_ARGS = dict(github_repo="o/r", repository="./demo", commit_id="abc123", title="t", body="b")



def test_get_commit_diff_lists_nested_and_unusual_paths_and_logs_them(repo, caplog):
    r, _ = repo
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    (r / "src" / "sub dir").mkdir(parents=True)
    (r / "src" / "sub dir" / "my file.py").write_text("x = 1\n")
    (r / "docs").mkdir()
    (r / "docs" / "d\u00f3c.txt").write_text("hi\n")
    subprocess.run(["git", "-C", str(r), "add", "."], check=True, env=env)
    subprocess.run(["git", "-C", str(r), "commit", "-qm", "paths"], check=True, env=env)
    sha = subprocess.run(["git", "-C", str(r), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    caplog.set_level("INFO", logger="server")
    res = git_tool.get_commit_diff(str(r), sha)
    assert res["data"]["changed_files"] == ["docs/d\u00f3c.txt", "src/sub dir/my file.py"]
    assert "2 file(s) extracted" in caplog.text
    assert "src/sub dir/my file.py" in caplog.text and str(r.resolve()) in caplog.text


def test_get_commit_diff_returns_files_and_handle_not_diff(repo):
    r, sha = repo
    res = git_tool.get_commit_diff(str(r), sha[:8])
    assert res["success"] and res["data"]["changed_files"] == ["config.py"]
    assert res["data"]["commit_id"] == sha and res["data"]["repository"] == str(r.resolve())
    assert FAKE_AWS not in json.dumps(res) and "diff_handle" not in res["data"]


@pytest.mark.parametrize("bad", ["--output=x", "zzzz", "", "abc;rm"])
def test_get_commit_diff_rejects_bad_ids(repo, bad):
    assert not git_tool.get_commit_diff(str(repo[0]), bad)["success"]


def test_get_commit_diff_unknown_commit_and_repo(repo, tmp_path):
    assert not git_tool.get_commit_diff(str(repo[0]), "deadbeef")["success"]
    assert not git_tool.get_commit_diff(str(tmp_path / "nope"), "deadbeef")["success"]


def test_scan_maps_gitleaks_report_and_uses_redact_and_single_commit(repo, tmp_path, monkeypatch):
    r, sha = repo
    fake = script(tmp_path / "gitleaks", FAKE_GITLEAKS)
    monkeypatch.setenv("GITLEAKS_BIN", fake)
    d = git_tool.get_commit_diff(str(r), sha)
    assert set(d["data"]) == {"repository", "commit_id", "changed_files"}     # no diff, no handle
    res = scanner.scan_commit(d["data"])
    assert res["success"]
    f = {x["rule"]: x for x in res["data"]["findings"]}
    assert f["api_token"]["severity"] == "HIGH" and f["unsafe_config"]["severity"] == "MEDIUM"
    assert f["unsafe_config"]["evidence"] == "Debug mode enabled"
    assert FAKE_AWS not in json.dumps(res)
    args = json.loads(Path(fake + ".args").read_text())
    assert "--redact" in args and f"--log-opts=-1 {sha}" in args and "--config" in args


def test_scan_errors_cleanly(repo, monkeypatch):
    good = git_tool.get_commit_diff(str(repo[0]), repo[1])["data"]
    for bad in ("nope", None, {}, {**good, "commit_id": "--output=x"}, {**good, "commit_id": good["commit_id"][:10]},
                {**good, "commit_id": "0" * 40}, {**good, "repository": "/no/such/dir"},
                {**good, "changed_files": "config.py"}):
        res = scanner.scan_commit(bad)
        assert not res["success"] and res["error"], bad
    monkeypatch.setenv("GITLEAKS_BIN", "/nonexistent/gitleaks")
    assert not scanner.scan_commit(good)["success"]


def test_issue_tool_posts_to_github_api_with_token_and_scrubbed_body(gh_api):
    g = gh_api()
    tok = issue_token(SECRET, "./demo", "abc123")
    res = github_tool.create_security_issue(**{**ISSUE_ARGS, "body": f'key = "{FAKE_AWS}"'}, approval_token=tok)
    assert res["success"] and res["data"] == {"issue_number": 42, "issue_url": "https://github.com/o/r/issues/42"}
    req = g.requests[0]
    assert req["path"] == "/repos/o/r/issues"
    assert req["headers"]["Authorization"] == "Bearer ghp_FAKEtokenFAKEtokenFAKEtokenFAKE0000"
    assert req["headers"]["Accept"] == "application/vnd.github+json"
    assert FAKE_AWS not in req["json"]["body"] and set(req["json"]) == {"title", "body"}
    assert "ghp_FAKE" not in json.dumps(res)                         # token never in a result


def test_issue_tool_requires_valid_single_use_token(gh_api):
    g = gh_api()
    assert not github_tool.create_security_issue(**ISSUE_ARGS, approval_token="")["success"]
    assert g.requests == []                                          # GitHub never contacted
    tok = issue_token(SECRET, "./demo", "abc123")
    assert github_tool.create_security_issue(**ISSUE_ARGS, approval_token=tok)["success"]
    assert not github_tool.create_security_issue(**ISSUE_ARGS, approval_token=tok)["success"]    # replay
    assert len(g.requests) == 1
    other = issue_token(SECRET, "./demo", "different")
    assert not github_tool.create_security_issue(**ISSUE_ARGS, approval_token=other)["success"]  # wrong commit


def test_issue_tool_rejects_bad_repo_name(gh_api):
    g = gh_api()
    res = github_tool.create_security_issue(**{**ISSUE_ARGS, "github_repo": "not a repo; rm"},
                                            approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"] and g.requests == []


def test_issue_tool_without_github_token_says_how_to_fix(gh_api, monkeypatch):
    g = gh_api()
    monkeypatch.delenv("GITHUB_TOKEN"); monkeypatch.delenv("GH_TOKEN", raising=False)
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"] and "GITHUB_TOKEN" in res["error"] and g.requests == []


@pytest.mark.parametrize("status,hint", [(401, "token rejected"), (403, "forbidden"), (404, "not found"),
                                         (410, "disabled"), (422, "rejected the issue")])
def test_issue_tool_maps_github_errors(gh_api, status, hint):
    gh_api(status=status, body={"message": "Nope"})
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"] and f"HTTP {status}" in res["error"] and hint in res["error"]


def test_issue_tool_timeout_reports_unknown_outcome(gh_api, monkeypatch):
    g = gh_api(delay=1.5)
    monkeypatch.setattr(github_tool, "API_TIMEOUT", 0.3)
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"] and "may or may not exist" in res["summary"]
    assert len(g.requests) == 1                                      # and it was not retried


def test_issue_tool_rejects_unverifiable_success(gh_api):
    gh_api(body={"number": 5, "html_url": "https://evil.example/issues/5"})
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"]
    gh_api(body={"unexpected": True})
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"]


def test_issue_tool_accepts_github_canonical_repo_case(gh_api):
    gh_api(body={"number": 9, "html_url": "https://github.com/Owner/Repo/issues/9"})
    res = github_tool.create_security_issue(**{**ISSUE_ARGS, "github_repo": "owner/repo"},
                                            approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert res["success"] and res["data"]["issue_number"] == 9


def test_issue_tool_unreachable_github(monkeypatch):
    monkeypatch.setenv("GITHUB_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("GITHUB_TOKEN", "x"); monkeypatch.setenv("REVIEWER_APPROVAL_SECRET", SECRET)
    github_tool._consumed.clear()
    res = github_tool.create_security_issue(**ISSUE_ARGS, approval_token=issue_token(SECRET, "./demo", "abc123"))
    assert not res["success"] and "network error" in res["error"]


def test_end_to_end_agent_with_real_mcp_server(repo, tmp_path, monkeypatch, caplog, capfd, gh_api):
    g = gh_api()
    caplog.set_level("INFO", logger="agent")
    r, sha = repo
    gl = script(tmp_path / "gitleaks", FAKE_GITLEAKS)
    env = {"REVIEWER_APPROVAL_SECRET": SECRET, "GITLEAKS_BIN": gl, "PYTHONPATH": str(ROOT),
           "GITHUB_API_URL": g.url, "GITHUB_TOKEN": "ghp_FAKEtokenFAKEtokenFAKEtokenFAKE0000"}
    client = McpClient(sys.executable, ["-m", "reviewer_server"], env=env)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    gate = ApprovalGate(SECRET, input_fn=lambda p: "yes", output_fn=lambda s: None)
    out = RootAgent(client, gate, audit).run(ReviewRequest(str(r), sha, "owner/security-demo"))
    assert out.status == "issue_created" and out.issue_number == 42, out.message
    assert len(g.requests) == 1 and g.requests[0]["path"] == "/repos/owner/security-demo/issues"
    assert out.diagnosis.severity == "HIGH"
    assert FAKE_AWS not in (tmp_path / "audit.jsonl").read_text()
    assert audit.trail().count("create_security_issue") == 1
    assert "-> calling get_commit_diff" in caplog.text and "<- create_security_issue success=True" in caplog.text
    server_log = capfd.readouterr().err                      # the server process logs to stderr
    for tool in ("get_commit_diff", "scan_commit", "create_security_issue"):
        assert f"{tool} called" in server_log, server_log
    assert FAKE_AWS not in server_log and "ghp_FAKE" not in server_log and "ghp_FAKE" not in (tmp_path / "audit.jsonl").read_text()


def test_logged_decorator_survives_tool_crash(caplog):
    from reviewer_server.common import logged

    @logged
    def boom(x: str) -> dict:
        raise RuntimeError("kaboom")

    res = boom(x="y")
    assert res["success"] is False and "kaboom" in res["error"]


def test_scan_logs_enough_to_troubleshoot(repo, tmp_path, monkeypatch, caplog):
    r, sha = repo
    monkeypatch.setenv("GITLEAKS_BIN", script(tmp_path / "gitleaks", FAKE_GITLEAKS))
    caplog.set_level("DEBUG", logger="server")
    scanner._version_cache.clear()
    scanner.scan_commit(git_tool.get_commit_diff(str(r), sha)["data"])
    text = caplog.text
    for expected in ("input ok", "using gitleaks=", "running:", "--redact", f"--log-opts=-1 {sha}",
                     "gitleaks exit=0", "report written", "2 raw finding(s)",
                     "gitleaks_rule=aws-access-token -> api_token/HIGH/high at config.py:1",
                     "gitleaks_rule=unsafe-config-debug -> unsafe_config/MEDIUM/high", "result 2 finding(s)"):
        assert expected in text, (expected, text)
    assert FAKE_AWS not in text


def test_scan_logs_why_it_failed(repo, tmp_path, monkeypatch, caplog):
    caplog.set_level("DEBUG", logger="server")
    scanner.scan_commit({"repository": "/nope"})
    assert "invalid input" in caplog.text
    good = git_tool.get_commit_diff(str(repo[0]), repo[1])["data"]   # needs git: do it before editing PATH
    monkeypatch.setenv("GITLEAKS_BIN", "")
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: None)   # no gitleaks anywhere
    scanner.scan_commit(good)
    assert "gitleaks not found" in caplog.text
    monkeypatch.undo()
    failing = script(tmp_path / "gitleaks", "import sys\nprint('boom: bad flag', file=sys.stderr)\nsys.exit(2)\n")
    monkeypatch.setenv("GITLEAKS_BIN", failing)
    res = scanner.scan_commit(good)
    assert not res["success"] and "gitleaks exit=2" in caplog.text and "boom: bad flag" in caplog.text


def test_evidence_is_readable_when_gitleaks_match_is_only_a_fragment():
    from reviewer_server.scanner import _readable
    assert _readable({"Match": 'REDACTED"'}, "aws-access-token") == "aws-access-token: value redacted"
    assert _readable({"Match": "REDACTED"}, "x") == "x: value redacted"
    assert _readable({"Match": 'AWS_KEY = "REDACTED"'}, "x") == 'AWS_KEY = "REDACTED"'
    assert _readable({}, "x") == "x: value redacted"
