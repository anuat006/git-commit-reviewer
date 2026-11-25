"""get_commit_diff: identify one commit of a local repo and list its changed files.

Stateless. The result (repository, full commit_id, changed_files) is exactly what
scan_commit needs as input. The raw diff is never returned, so no secret can leak
through a tool result, the agent state or the logs.
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from .common import result, run

_SHA = re.compile(r"^[0-9a-fA-F]{4,64}$")
GIT_TIMEOUT = 20.0
log = logging.getLogger("server")

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
                     "-r", "-z", "--root", full], GIT_TIMEOUT)      # -z: exact names, no quoting
        if files.returncode != 0:
            return result(False, "Could not list changed files", error=files.stderr.strip()[:200])
    except subprocess.TimeoutExpired:
        return result(False, "git timed out", error=f"git timed out after {GIT_TIMEOUT}s")
    except FileNotFoundError:
        return result(False, "git not installed", error="git executable not found")
    changed = [f for f in files.stdout.split("\0") if f]
    log.info("commit %s: %d file(s) extracted:", full[:10], len(changed))
    for f in changed:
        log.info("    %s   (%s)", f, repo.resolve() / f)
    return result(True, f"{len(changed)} file(s) changed in {full[:10]}",
                  {"repository": str(repo.resolve()), "commit_id": full, "changed_files": changed})
