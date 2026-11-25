"""Console logging (stderr). Used by the CLI and, in its own process, by the MCP server.

Examples of what you will see:
  12:01:03 agent    -> calling get_commit_diff  repository=C:\\demo commit_id=04a72c072a  (attempt 1/2)
  12:01:03 server   get_commit_diff called  repository=C:\\demo commit_id=04a72c072a
  12:01:03 server   get_commit_diff -> success=True | 1 file(s) changed in 04a72c072a
  12:01:03 agent    <- get_commit_diff success=True (0.08s) | 1 file(s) changed in 04a72c072a
"""
from __future__ import annotations

import logging
import os
import sys

LEVEL_ENV = "REVIEWER_LOG_LEVEL"


def setup_logging(level: str | None = None) -> None:
    level = (level or os.environ.get(LEVEL_ENV) or "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)      # stdout is reserved for MCP stdio in the server
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)-8s %(message)s", "%H:%M:%S"))
    for name in ("agent", "audit", "server"):
        lg = logging.getLogger(name)
        lg.handlers[:] = [handler]
        lg.setLevel(getattr(logging, level, logging.INFO))
        lg.propagate = False


def fmt_args(args: dict) -> str:
    """Identifiers only: never bodies, diffs or tokens."""
    from .audit import safe_inputs
    return " ".join(f"{k}={v}" for k, v in safe_inputs(args).items())
