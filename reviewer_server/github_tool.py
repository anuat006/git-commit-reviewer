"""create_security_issue: create ONE GitHub issue through the GitHub REST API,
only with a valid human-approval token.

Auth: a token in the SERVER's environment (GITHUB_TOKEN or GH_TOKEN). It never passes through
the agent, the tool arguments, the logs or the audit file.
  - fine-grained token: repository permission "Issues: Read and write" on the test repo
  - classic token: `repo` scope (private repo) or `public_repo`
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import urllib.error
import urllib.request

from reviewer.approval import SECRET_ENV, verify_token
from reviewer.redact import scrub, scrub_keeping

from .common import result

log = logging.getLogger("server")

API_TIMEOUT = 40.0
API_BASE_ENV = "GITHUB_API_URL"            # default https://api.github.com (tests point it elsewhere)
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_consumed: set = set()                     # approval nonces already used (single use)

_HTTP_HINTS = {
    401: "token rejected - check GITHUB_TOKEN is valid and not expired",
    403: "forbidden - token lacks 'Issues: write' on this repo, or rate limit / SSO restriction",
    404: "repo not found, or the token cannot see it (private repos return 404)",
    410: "issues are disabled for this repository",
    422: "GitHub rejected the issue content",
    429: "rate limited - wait and try again manually",
}


def _token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def create_security_issue(github_repo: str, repository: str, commit_id: str, title: str,
                          body: str, approval_token: str) -> dict:
    secret = os.environ.get(SECRET_ENV)
    if not secret:
        return result(False, "Server not configured", error="approval secret missing")
    ok, why = verify_token(secret, approval_token or "", repository, commit_id, _consumed)
    if not ok:
        log.warning("create_security_issue: REJECTED - %s", why)
        return result(False, "Rejected: no valid human approval", error=why)
    if not _REPO.match(github_repo or ""):
        return result(False, "Invalid GitHub repository", error="expected owner/name")
    token = _token()
    if not token:
        log.error("create_security_issue: no GitHub token in the server environment")
        return result(False, "GitHub token missing",
                      error="set GITHUB_TOKEN (e.g. PowerShell: $env:GITHUB_TOKEN = (gh auth token))")

    base = os.environ.get(API_BASE_ENV, "https://api.github.com").rstrip("/")
    url = f"{base}/repos/{github_repo}/issues"
    payload = json.dumps({"title": scrub_keeping(title, [commit_id])[:200],
                          "body": scrub_keeping(body, [commit_id])}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security-commit-reviewer",
        "Content-Type": "application/json",
    })
    log.info("create_security_issue: POST %s (title %d chars, body %d chars)", url, len(title), len(body))
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:                 # GitHub answered: the issue was NOT created
        try:
            msg = json.loads(exc.read().decode("utf-8", "replace")).get("message", "")
        except Exception:
            msg = ""
        hint = _HTTP_HINTS.get(exc.code, "")
        log.warning("create_security_issue: GitHub HTTP %s %s | %s", exc.code, msg[:120], hint)
        return result(False, f"GitHub returned HTTP {exc.code}",
                      error=scrub(f"HTTP {exc.code}: {msg[:150]} {('- ' + hint) if hint else ''}".strip()))
    except (TimeoutError, socket.timeout):
        log.error("create_security_issue: timed out after %ss - outcome UNKNOWN", API_TIMEOUT)
        return result(False, "GitHub timed out; issue may or may not exist",
                      error="timeout - check the repository's issues before retrying manually")
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            log.error("create_security_issue: timed out after %ss - outcome UNKNOWN", API_TIMEOUT)
            return result(False, "GitHub timed out; issue may or may not exist",
                          error="timeout - check the repository's issues before retrying manually")
        log.error("create_security_issue: cannot reach GitHub: %s", exc.reason)
        return result(False, "Could not reach GitHub",
                      error=f"network error: {exc.reason} - the issue was probably not created; check before retrying")

    try:
        data = json.loads(raw.decode("utf-8"))
        number, html_url = data["number"], data["html_url"]
    except (ValueError, KeyError, TypeError):
        log.error("create_security_issue: HTTP %s but unreadable response", status)
        return result(False, "Unreadable GitHub response", error=f"HTTP {status} without issue number/url - check the repo")
    m = re.match(rf"^https://github\.com/{re.escape(github_repo)}/issues/(\d+)$", str(html_url), re.I)
    if status != 201 or not isinstance(number, int) or not m or int(m.group(1)) != number:
        log.error("create_security_issue: response not verifiable (HTTP %s)", status)
        return result(False, "Could not verify issue creation", error=f"unexpected response (HTTP {status})")
    log.info("create_security_issue: created #%s %s", number, html_url)
    return result(True, f"Issue #{number} created", {"issue_number": number, "issue_url": html_url})
