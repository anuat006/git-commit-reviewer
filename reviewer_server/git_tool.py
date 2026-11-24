"""get_commit_diff: read one commit from a local repo.

The raw diff stays inside this process (keyed by an opaque handle). It is never returned
to the agent, so no secret can leak through the tool result or the audit log.
"""
from __future__ import annotations

import re
import secrets
import subprocess
from pathlib import Path

from .common import result, run

_SHA = re.compile(r"^[0-9a-fA-F]{4,64}$")
GIT_TIMEOUT = 20.0
_store: dict[str, dict] = {}          # diff_handle -> {repo, sha}


def lookup(handle: str) -> dict | None:
    return _store.get(handle)


def get_commit_diff(repository: str, commit_id: str) -> dict:
    repo = Path(repository).expanduser()
    if not repo.is_dir():
        return result(False, "Repository not found", error=f"not a directory: {repository}")
    if not _SHA.match(commit_id or ""):
        return result(False, "Invalid commit id", error="commit_id must be a hex SHA (4-64 chars)")
    try:
        sha = run(["git", "-C", str(repo), "rev-parse", "--verify", f"{commit_id}^{{commit}}"],
                  GIT_TIMEOUT)
        if sha.returncode != 0:
            return result(False, "Commit not found", error=sha.stderr.strip()[:200] or "unknown commit")
        full = sha.stdout.strip()
        files = run(["git", "-C", str(repo), "diff-tree", "--no-commit-id", "--name-only",
                     "-r", "--root", full], GIT_TIMEOUT)
        if files.returncode != 0:
            return result(False, "Could not list changed files", error=files.stderr.strip()[:200])
    except subprocess.TimeoutExpired:
        return result(False, "git timed out", error=f"git timed out after {GIT_TIMEOUT}s")
    except FileNotFoundError:
        return result(False, "git not installed", error="git executable not found")
    changed = [f for f in files.stdout.splitlines() if f]
    handle = secrets.token_hex(8)
    _store[handle] = {"repo": str(repo), "sha": full}
    return result(True, f"{len(changed)} file(s) changed in {full[:10]}",
                  {"diff_handle": handle, "commit_id": full, "changed_files": changed})
