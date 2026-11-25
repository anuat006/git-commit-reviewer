import os
import pytest
from reviewer_server import git_tool, scanner

REPO = os.environ.get("DEMO_REPO")
pytestmark = pytest.mark.skipif(not REPO, reason="set DEMO_REPO")


def scan(sha):
    d = git_tool.get_commit_diff(REPO, sha)
    assert d["success"], d["error"]
    s = scanner.scan_commit(d["data"])
    assert s["success"], s["error"]
    return s["data"]["findings"]


def test_password_commit_is_flagged():
    findings = scan("4f68ee26c7")
    pw = [f for f in findings if f["rule"] == "password"]
    assert pw and pw[0]["file"] == "db_config.py" and pw[0]["severity"] == "HIGH"
    assert "Sup3rS3cret" not in str(findings)        # evidence must be redacted


def test_clean_commit_has_no_password_finding():
    assert scan("7955777f9e") == []