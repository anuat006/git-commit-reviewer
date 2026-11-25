"""Shared helpers: safe subprocess runner and the standard result envelope."""
from __future__ import annotations

import functools
import logging
import subprocess
import time
from typing import Any, Optional


def result(success: bool, summary: str, data: Optional[dict[str, Any]] = None,
           error: Optional[str] = None) -> dict[str, Any]:
    """Standard envelope required by the capstone: success, summary, redacted data, error."""
    return {"success": success, "summary": summary, "data": data or {}, "error": error}


def run(cmd: list[str], timeout: float, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    """No shell, text mode, bounded by a timeout (raises subprocess.TimeoutExpired)."""
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, shell=False)


log = logging.getLogger("server")


def logged(fn):
    """Log every tool invocation and its outcome (identifiers only, never diffs/bodies/tokens)."""
    from reviewer.logsetup import fmt_args

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        shown = fmt_args(kwargs or dict(zip(fn.__code__.co_varnames, args)))
        log.info("%s called  %s", fn.__name__, shown)
        t0 = time.monotonic()
        try:
            res = fn(*args, **kwargs)
        except Exception as exc:                      # never let a tool crash the server
            log.exception("%s crashed", fn.__name__)
            return result(False, "Internal tool error", error=repr(exc)[:200])
        log.info("%s -> success=%s (%.2fs) | %s%s", fn.__name__, res.get("success"),
                 time.monotonic() - t0, res.get("summary", ""),
                 f" | error={res['error']}" if res.get("error") else "")
        return res
    return wrapper
