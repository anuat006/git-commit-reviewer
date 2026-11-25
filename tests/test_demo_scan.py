"""Integration test: get_commit_diff -> scan_commit on EVERY commit of the demo repo.

Needs: gitleaks installed (or GITLEAKS_BIN), the demo repo, and its demo_expected.json.

    PowerShell:
      $env:DEMO_REPO = "C:\\workspace\\gitspace\\test\\demo-repo\\demo"
      python -m pytest tests/test_demo_scan.py -v --log-cli-level=INFO

demo_expected.json is looked up next to the demo folder (override with $env:DEMO_EXPECTED).
"""
import json
import logging
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import make_demo_repo as demo  # noqa: E402  (only for the known FAKE_* secrets)
from reviewer_server import git_tool, scanner  # noqa: E402

log = logging.getLogger("server")
REPO = os.environ.get("DEMO_REPO")
HAVE_GITLEAKS = bool(os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks"))
FAKE_SECRETS = [demo.FAKE_AWS_KEY, demo.FAKE_GH_PAT, demo.FAKE_DB_PASSWORD, demo.FAKE_SVC_PASSWORD]

pytestmark = [pytest.mark.skipif(not REPO, reason="set DEMO_REPO to the demo repo path"),
              pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed (or set GITLEAKS_BIN)")]


def _rows():
    if not REPO:
        return []
    p = Path(os.environ.get("DEMO_EXPECTED") or Path(REPO).parent / "demo_expected.json")
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


ROWS = _rows()


def test_expected_manifest_found():
    assert ROWS, "demo_expected.json not found next to the demo repo (or set DEMO_EXPECTED)"


@pytest.mark.parametrize("row", ROWS, ids=[f"{r['n']}-{r['sha'][:7]}-{r['expected']}" for r in ROWS])
def test_get_diff_then_scan(row):
    d = git_tool.get_commit_diff(REPO, row["sha"])                      # step 1
    assert d["success"], d["error"]
    assert d["data"]["changed_files"], "commit should change at least one file"

    s = scanner.scan_commit(d["data"])                   # step 2
    assert s["success"], s["error"]
    findings = s["data"]["findings"]
    found = {f["rule"] for f in findings}
    expected = set(row["expected_rules"])
    log.info("commit %s expected=%s found=%s", row["sha"][:10], sorted(expected), sorted(found))

    if row["expected"] == "clean":
        assert findings == [], f"clean commit produced findings: {sorted(found)}"
    else:
        assert expected <= found, f"missing expected rule(s): {sorted(expected - found)}"
        if found - expected:                         # e.g. gitleaks' generic rule also fired
            log.warning("extra findings beyond expectation: %s", sorted(found - expected))

    blob = json.dumps(findings)                      # redaction: no full secret in any result
    for secret in FAKE_SECRETS:
        assert secret not in blob
