"""scan_commit: run Gitleaks on exactly one commit and map the report to our schema."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from reviewer.redact import scrub

from . import git_tool
from .common import result, run

SCAN_TIMEOUT = 60.0
RULES = Path(__file__).with_name("rules.toml")

# gitleaks RuleID -> (our rule type, severity, confidence, recommendation)
_RECO = {
    "password": "Remove the password from the code and history, rotate it, load it from a secret manager or env var.",
    "api_token": "Revoke and rotate the token, purge it from history, load it from a secret manager.",
    "unsafe_config": "Replace with a secure value and review the deployment configuration.",
}


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


def _invoke(binary: str, repo: str, sha: str, report: str) -> subprocess.CompletedProcess:
    common = ["--config", str(RULES), "--redact", "--report-format", "json",
              "--report-path", report, "--exit-code", "0", "--no-banner"]
    new = [binary, "git", repo, f"--log-opts=-1 {sha}", *common]
    proc = run(new, SCAN_TIMEOUT)
    if proc.returncode != 0 and "unknown command" in (proc.stderr or "").lower():
        # gitleaks < 8.19 uses `detect`
        old = [binary, "detect", "--source", repo, f"--log-opts=-1 {sha}", *common]
        proc = run(old, SCAN_TIMEOUT)
    return proc


def scan_commit(diff_handle: str) -> dict:
    entry = git_tool.lookup(diff_handle)
    if entry is None:
        return result(False, "Unknown diff handle", error="call get_commit_diff first")
    binary = _gitleaks()
    if not binary:
        return result(False, "gitleaks not installed",
                      error="gitleaks executable not found (install it or set GITLEAKS_BIN)")
    with tempfile.TemporaryDirectory() as tmp:
        report = str(Path(tmp) / "report.json")
        try:
            proc = _invoke(binary, entry["repo"], entry["sha"], report)
        except subprocess.TimeoutExpired:
            return result(False, "gitleaks timed out", error=f"gitleaks timed out after {SCAN_TIMEOUT}s")
        except FileNotFoundError:
            return result(False, "gitleaks not runnable", error=f"cannot execute {binary}")
        if proc.returncode != 0:
            return result(False, "gitleaks failed", error=(proc.stderr or "")[-300:].strip() or f"exit {proc.returncode}")
        try:
            raw = json.loads(Path(report).read_text(encoding="utf-8") or "[]") if Path(report).exists() else []
        except ValueError as exc:
            return result(False, "Unreadable gitleaks report", error=repr(exc))

    findings = []
    for item in raw:
        rule_id = str(item.get("RuleID", ""))
        kind, severity, confidence = classify(rule_id)
        # secrets: gitleaks already redacted the match; config findings are not secrets,
        # so describe the rule instead of echoing the line.
        evidence = item.get("Description", rule_id) if kind == "unsafe_config" else item.get("Match", "")
        findings.append({
            "rule": kind, "file": item.get("File", "?"), "line": int(item.get("StartLine", 0) or 0),
            "evidence": scrub(str(evidence))[:200], "severity": severity,
            "confidence": confidence, "recommendation": _RECO[kind],
        })
    return result(True, f"{len(findings)} finding(s)", {"findings": findings})
