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

FAKE_GH = '''
import sys
body = sys.stdin.read()
open(__file__ + ".body", "w").write(body)
repo = sys.argv[sys.argv.index("--repo") + 1]
print(f"https://github.com/{repo}/issues/42")
'''


def test_get_commit_diff_returns_files_and_handle_not_diff(repo):
    r, sha = repo
    res = git_tool.get_commit_diff(str(r), sha[:8])
    assert res["success"] and res["data"]["changed_files"] == ["config.py"]
    assert res["data"]["commit_id"] == sha and FAKE_AWS not in json.dumps(res)


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
    h = git_tool.get_commit_diff(str(r), sha)["data"]["diff_handle"]
    res = scanner.scan_commit(h)
    assert res["success"]
    f = {x["rule"]: x for x in res["data"]["findings"]}
    assert f["api_token"]["severity"] == "HIGH" and f["unsafe_config"]["severity"] == "MEDIUM"
    assert f["unsafe_config"]["evidence"] == "Debug mode enabled"
    assert FAKE_AWS not in json.dumps(res)
    args = json.loads(Path(fake + ".args").read_text())
    assert "--redact" in args and f"--log-opts=-1 {sha}" in args and "--config" in args


def test_scan_errors_cleanly(repo, monkeypatch):
    assert not scanner.scan_commit("nope")["success"]
    h = git_tool.get_commit_diff(str(repo[0]), repo[1])["data"]["diff_handle"]
    monkeypatch.setenv("GITLEAKS_BIN", "/nonexistent/gitleaks")
    assert not scanner.scan_commit(h)["success"]


def test_issue_tool_requires_valid_single_use_token(tmp_path, monkeypatch):
    gh = script(tmp_path / "gh", FAKE_GH)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("REVIEWER_APPROVAL_SECRET", SECRET)
    github_tool._consumed.clear()
    args = dict(github_repo="o/r", repository="./demo", commit_id="abc123", title="t",
                body=f'key = "{FAKE_AWS}"')
    assert not github_tool.create_security_issue(**args, approval_token="")["success"]
    assert not Path(gh + ".body").exists()                         # gh never ran
    tok = issue_token(SECRET, "./demo", "abc123")
    ok = github_tool.create_security_issue(**args, approval_token=tok)
    assert ok["success"] and ok["data"] == {"issue_number": 42, "issue_url": "https://github.com/o/r/issues/42"}
    assert FAKE_AWS not in Path(gh + ".body").read_text()          # body scrubbed again
    assert not github_tool.create_security_issue(**args, approval_token=tok)["success"]   # replay


def test_issue_tool_rejects_bad_repo_name(monkeypatch):
    monkeypatch.setenv("REVIEWER_APPROVAL_SECRET", SECRET)
    tok = issue_token(SECRET, "r", "c")
    res = github_tool.create_security_issue("not a repo; rm", "r", "c", "t", "b", tok)
    assert not res["success"]


def test_end_to_end_agent_with_real_mcp_server(repo, tmp_path, monkeypatch):
    r, sha = repo
    gl = script(tmp_path / "gitleaks", FAKE_GITLEAKS)
    script(tmp_path / "gh", FAKE_GH)
    env = {"REVIEWER_APPROVAL_SECRET": SECRET, "GITLEAKS_BIN": gl, "PYTHONPATH": str(ROOT),
           "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    client = McpClient(sys.executable, ["-m", "reviewer_server"], env=env)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    gate = ApprovalGate(SECRET, input_fn=lambda p: "yes", output_fn=lambda s: None)
    out = RootAgent(client, gate, audit).run(ReviewRequest(str(r), sha, "owner/security-demo"))
    assert out.status == "issue_created" and out.issue_number == 42, out.message
    assert out.diagnosis.severity == "HIGH"
    assert FAKE_AWS not in (tmp_path / "audit.jsonl").read_text()
    assert audit.trail().count("create_security_issue") == 1
