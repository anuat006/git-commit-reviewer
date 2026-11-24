"""create_security_issue: create ONE GitHub issue via the `gh` CLI, only with a valid approval token."""
from __future__ import annotations

import os
import re
import subprocess

from reviewer.approval import SECRET_ENV, verify_token
from reviewer.redact import scrub

from .common import result, run

GH_TIMEOUT = 40.0
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_consumed: set = set()            # approval nonces already used (single use)


def create_security_issue(github_repo: str, repository: str, commit_id: str, title: str,
                          body: str, approval_token: str) -> dict:
    secret = os.environ.get(SECRET_ENV)
    if not secret:
        return result(False, "Server not configured", error="approval secret missing")
    ok, why = verify_token(secret, approval_token or "", repository, commit_id, _consumed)
    if not ok:
        return result(False, "Rejected: no valid human approval", error=why)
    if not _REPO.match(github_repo or ""):
        return result(False, "Invalid GitHub repository", error="expected owner/name")
    try:
        proc = run(["gh", "issue", "create", "--repo", github_repo,
                    "--title", scrub(title)[:200], "--body-file", "-"],
                   GH_TIMEOUT, stdin=scrub(body))
    except subprocess.TimeoutExpired:
        # Outcome unknown: the issue may exist. Report it; the agent never retries this.
        return result(False, "gh timed out; issue may or may not exist",
                      error="timeout - check the repository before retrying manually")
    except FileNotFoundError:
        return result(False, "GitHub CLI not installed", error="gh executable not found")
    if proc.returncode != 0:
        return result(False, "gh failed", error=(proc.stderr or "")[-300:].strip() or f"exit {proc.returncode}")
    m = re.search(rf"https://github\.com/{re.escape(github_repo)}/issues/(\d+)", proc.stdout)
    if not m:
        return result(False, "Issue URL not found in gh output", error="could not verify issue creation")
    return result(True, f"Issue #{m.group(1)} created",
                  {"issue_number": int(m.group(1)), "issue_url": m.group(0)})
