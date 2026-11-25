"""Tiny .env loader (no dependency).

Rules: KEY=VALUE per line; '#' comments and blank lines ignored; optional `export `;
surrounding quotes stripped; variables ALREADY set in the real environment win (so a value
typed in the terminal overrides the file). Only variable NAMES are ever logged, never values.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

log = logging.getLogger("agent")
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"      # project root
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not _KEY.match(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()      # trailing comment
        out[key] = value
    return out


def load_env_file(path: str | os.PathLike | None = None, override: bool = False) -> list[str]:
    """Load the file into os.environ. Returns the NAMES of variables it set."""
    p = Path(path) if path else DEFAULT_ENV_FILE
    if not p.is_file():
        log.debug("no .env file at %s", p)
        return []
    set_names = []
    for key, value in parse_env(p.read_text(encoding="utf-8-sig")).items():   # utf-8-sig: Notepad BOM
        if value and (override or key not in os.environ):
            os.environ[key] = value
            set_names.append(key)
    log.info("loaded %d variable(s) from %s: %s", len(set_names), p, ", ".join(set_names) or "-")
    return set_names
