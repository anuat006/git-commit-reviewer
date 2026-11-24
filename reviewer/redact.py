"""Defensive redaction. Tools should already redact; the agent re-scrubs anything it
logs or publishes so a misbehaving tool can never leak a full secret."""
from __future__ import annotations

import re

_PATTERNS = [
    # key = "value" / key: value for sensitive-looking keys
    re.compile(
        r"(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth)"
        r"[\w-]*\s*[:=]\s*)(['\"]?)([^\s'\",;]{4,})(\2)"
    ),
]
_TOKEN_SHAPES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),  # long opaque strings
]


def mask(value: str) -> str:
    """Keep at most 2 leading chars of long values; never reveal the rest."""
    if len(value) <= 8:
        return "****"
    return f"{value[:2]}****[{len(value)} chars]"


def scrub(text: str) -> str:
    if not text:
        return text
    for pat in _PATTERNS:
        text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{mask(m.group(3))}{m.group(4)}", text)
    for pat in _TOKEN_SHAPES:
        text = pat.sub(lambda m: mask(m.group(0)), text)
    return text


def scrub_obj(obj):
    """Recursively scrub strings in dict/list structures."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        return {k: scrub_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v) for v in obj]
    return obj
