"""scan_commit: run Gitleaks on exactly one commit and map the report to our schema."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from reviewer.redact import scrub

from .git_tool import _SHA
from .common import result, run

SCAN_TIMEOUT = 60.0
log = logging.getLogger("server")
RULES = Path(__file__).with_name("rules.toml")

# gitleaks RuleID -> (our rule type, severity, confidence, recommendation)
_RECO = {
    "password": "Remove the password from the code and history, rotate it, load it from a secret manager or env var.",
    "api_token": "Revoke and rotate the token, purge it from history, load it from a secret manager.",
    "unsafe_config": "Replace with a secure value and review the deployment configuration.",
}


def _readable(item: dict, rule_id: str) -> str:
    """Gitleaks' redacted Match is sometimes just a fragment such as REDACTED" (some token rules match
    only the value). When it carries no context, say what was found instead of echoing the fragment."""
    match = str(item.get("Match", "")).strip()
    rest = match.replace("REDACTED", "").strip(" \t\"'=:;,()[]{}")
    if rest:                                   # e.g. DB_PASSWORD = "REDACTED": keep the context
        return match
    return f"{rule_id}: value redacted"


def classify(rule_id: str) -> tuple[str, str, str]:
    """-> (rule type, severity, confidence)"""
    if rule_id == "hardcoded-password":
        return "password", "HIGH", "medium"
    if rule_id.startswith("unsafe-config"):
        return "unsafe_config", "MEDIUM", "high"
    if rule_id == "generic-api-key":              # entropy based: more likely a false positive
        return "api_token", "HIGH", "medium"
    return "api_token", "HIGH", "high"


def _gitleaks() -> str | None:
    return os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks")


_version_cache: dict[str, str] = {}


def _version(binary: str) -> str:
    if binary not in _version_cache:
        try:
            p = run([binary, "version"], 10.0)
            _version_cache[binary] = (p.stdout or p.stderr or "?").strip().splitlines()[0][:40]
        except Exception as exc:                      # troubleshooting aid only
            _version_cache[binary] = f"unknown ({type(exc).__name__})"
    return _version_cache[binary]


def _run_logged(cmd: list[str]) -> subprocess.CompletedProcess:
    log.info("scan_commit: running: %s", subprocess.list2cmdline(cmd))
    t0 = time.monotonic()
    proc = run(cmd, SCAN_TIMEOUT)
    err_tail = scrub((proc.stderr or "").strip()[-1500:])
    log.info("scan_commit: gitleaks exit=%s in %.2fs", proc.returncode, time.monotonic() - t0)
    if err_tail:
        (log.warning if proc.returncode != 0 else log.debug)("scan_commit: gitleaks stderr: %s", err_tail)
    return proc


def _invoke(binary: str, repo: str, sha: str, report: str) -> subprocess.CompletedProcess:
    common = ["--config", str(RULES), "--redact", "--report-format", "json",
              "--report-path", report, "--exit-code", "0", "--no-banner"]
    proc = _run_logged([binary, "git", repo, f"--log-opts=-1 {sha}", *common])
    if proc.returncode != 0 and "unknown command" in (proc.stderr or "").lower():
        log.warning("scan_commit: this gitleaks has no 'git' command (older than 8.19?); retrying with 'detect'")
        proc = _run_logged([binary, "detect", "--source", repo, f"--log-opts=-1 {sha}", *common])
    return proc


def _validate(diff_result) -> tuple[str, str, list[str]] | str:
    """Check the get_commit_diff output we were handed. Returns (repo, sha, files) or an error."""
    if not isinstance(diff_result, dict):
        return "diff_result must be the data object returned by get_commit_diff"
    repo, sha, files = diff_result.get("repository"), diff_result.get("commit_id"), diff_result.get("changed_files")
    if not isinstance(repo, str) or not Path(repo).is_dir():
        return "diff_result.repository is not an existing directory"
    if not isinstance(sha, str) or not _SHA.match(sha) or len(sha) not in (40, 64):
        return "diff_result.commit_id must be a full 40/64-char hex commit id"
    if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        return "diff_result.changed_files must be a list of paths"
    check = run(["git", "-C", repo, "cat-file", "-e", f"{sha}^{{commit}}"], 20.0)
    if check.returncode != 0:
        return "commit not found in repository"
    return repo, sha, files


def scan_commit(diff_result: dict) -> dict:
    """Stateless: input is the `data` returned by get_commit_diff."""
    parsed = _validate(diff_result)
    if isinstance(parsed, str):
        log.warning("scan_commit: invalid input - %s", parsed)
        return result(False, "Invalid scan input", error=parsed)
    repo, sha, changed = parsed
    log.info("scan_commit: input ok  repository=%s commit=%s changed_files=%d", repo, sha[:10], len(changed))
    binary = _gitleaks()
    if not binary:
        log.error("scan_commit: gitleaks not found (checked $GITLEAKS_BIN and PATH). Install it or set GITLEAKS_BIN")
        return result(False, "gitleaks not installed",
                      error="gitleaks executable not found (install it or set GITLEAKS_BIN)")
    log.info("scan_commit: using gitleaks=%s version=%s rules=%s", binary, _version(binary), RULES)
    with tempfile.TemporaryDirectory() as tmp:
        report = str(Path(tmp) / "report.json")
        try:
            proc = _invoke(binary, repo, sha, report)
        except subprocess.TimeoutExpired:
            log.error("scan_commit: gitleaks timed out after %ss", SCAN_TIMEOUT)
            return result(False, "gitleaks timed out", error=f"gitleaks timed out after {SCAN_TIMEOUT}s")
        except FileNotFoundError:
            log.error("scan_commit: cannot execute %s", binary)
            return result(False, "gitleaks not runnable", error=f"cannot execute {binary}")
        if proc.returncode != 0:
            return result(False, "gitleaks failed", error=scrub((proc.stderr or "")[-300:]).strip() or f"exit {proc.returncode}")
        rp = Path(report)
        if rp.exists():
            log.info("scan_commit: report written (%d bytes)", rp.stat().st_size)
        else:
            log.info("scan_commit: gitleaks wrote no report file - treating as 0 findings")
        try:
            raw = json.loads(rp.read_text(encoding="utf-8") or "[]") if rp.exists() else []
        except ValueError as exc:
            log.error("scan_commit: report is not valid JSON: %r", exc)
            return result(False, "Unreadable gitleaks report", error=repr(exc))

    log.info("scan_commit: gitleaks reported %d raw finding(s)", len(raw))
    known = {c.replace("\\", "/") for c in changed}
    findings = []
    for item in raw:
        rule_id = str(item.get("RuleID", ""))
        kind, severity, confidence = classify(rule_id)
        fname = str(item.get("File", "?"))
        if known and fname.replace("\\", "/") not in known:
            log.warning("scan_commit: finding in %s is not among the %d changed file(s)", fname, len(changed))
        # secrets: gitleaks already redacted the match; config findings are not secrets,
        # so describe the rule instead of echoing the line.
        evidence = item.get("Description", rule_id) if kind == "unsafe_config" else _readable(item, rule_id)
        f = {"rule": kind, "file": fname, "line": int(item.get("StartLine", 0) or 0),
             "evidence": scrub(str(evidence))[:200], "severity": severity,
             "confidence": confidence, "recommendation": _RECO[kind]}
        findings.append(f)
        log.info("scan_commit:   finding gitleaks_rule=%s -> %s/%s/%s at %s:%d  evidence=%s",
                 rule_id, kind, severity, confidence, fname, f["line"], f["evidence"])
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f["rule"]] = by_type.get(f["rule"], 0) + 1
    log.info("scan_commit: result %d finding(s) %s", len(findings), by_type or "")
    return result(True, f"{len(findings)} finding(s)", {"findings": findings})
