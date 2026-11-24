"""Step-by-step JSONL activity log. Never records raw diffs, bodies or tokens."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .redact import scrub

# Argument keys that may never be logged, only their presence.
_NEVER_LOG = {"diff", "body", "approval_token", "payload", "evidence"}
_MAX_STR = 120


def safe_inputs(args: dict[str, Any]) -> dict[str, Any]:
    """Reduce tool arguments to identifiers only."""
    out: dict[str, Any] = {}
    for k, v in (args or {}).items():
        if k in _NEVER_LOG:
            out[k] = "<omitted>"
        elif isinstance(v, str):
            out[k] = scrub(v) if len(v) <= _MAX_STR else f"<str len={len(v)}>"
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = f"<{type(v).__name__}>"
    return out


class AuditLog:
    def __init__(self, path: Optional[str] = "audit_log.jsonl", echo: bool = False):
        self.path = Path(path) if path else None
        self.echo = echo
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, *, tool: str = "", reason: str = "",
               inputs: Optional[dict] = None, outcome: str = "",
               human_decision: Optional[str] = None, **extra: Any) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "step": len(self.entries) + 1,
            "event": event,
            "tool": tool,
            "reason": scrub(reason),
            "inputs": safe_inputs(inputs or {}),
            "outcome": scrub(outcome),
            "human_decision": human_decision,
        }
        entry.update({k: (scrub(v) if isinstance(v, str) else v) for k, v in extra.items()})
        with self._lock:
            self.entries.append(entry)
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
        if self.echo:
            print(f"[audit {entry['step']:02d}] {event} {tool} -> {entry['outcome']}")
        return entry

    def trail(self) -> str:
        """Compact 'git -> scanner -> approval -> github' style chain."""
        return " -> ".join(e["tool"] or e["event"] for e in self.entries)
