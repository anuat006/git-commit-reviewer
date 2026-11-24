"""Shared helpers: safe subprocess runner and the standard result envelope."""
from __future__ import annotations

import subprocess
from typing import Any, Optional


def result(success: bool, summary: str, data: Optional[dict[str, Any]] = None,
           error: Optional[str] = None) -> dict[str, Any]:
    """Standard envelope required by the capstone: success, summary, redacted data, error."""
    return {"success": success, "summary": summary, "data": data or {}, "error": error}


def run(cmd: list[str], timeout: float, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    """No shell, text mode, bounded by a timeout (raises subprocess.TimeoutExpired)."""
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, shell=False)
