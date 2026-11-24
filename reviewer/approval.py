"""Human gate + short-lived, single-use approval tokens.

The token is an HMAC over (repo, commit, expiry, nonce) using a per-run secret that is
shared with the MCP server process via env REVIEWER_APPROVAL_SECRET.
The issue tool calls `verify_token` and rejects otherwise, so
the gate can not be bypassed by simply calling the tool.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable, Optional

SECRET_ENV = "REVIEWER_APPROVAL_SECRET"
DEFAULT_TTL = 120  # seconds


def _sig(secret: str, repo: str, commit: str, expiry: int, nonce: str) -> str:
    msg = f"{repo}|{commit}|{expiry}|{nonce}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def issue_token(secret: str, repo: str, commit: str, ttl: int = DEFAULT_TTL) -> str:
    expiry = int(time.time()) + ttl
    nonce = secrets.token_hex(8)
    return f"{expiry}.{nonce}.{_sig(secret, repo, commit, expiry, nonce)}"


def verify_token(secret: str, token: str, repo: str, commit: str,
                 consumed: Optional[set] = None) -> tuple[bool, str]:
    """Server-side check. Pass a persistent `consumed` set to enforce single use."""
    try:
        expiry_s, nonce, sig = token.split(".")
        expiry = int(expiry_s)
    except (ValueError, AttributeError):
        return False, "malformed approval token"
    if not hmac.compare_digest(sig, _sig(secret, repo, commit, expiry, nonce)):
        return False, "invalid approval token"
    if time.time() > expiry:
        return False, "approval token expired"
    if consumed is not None:
        if nonce in consumed:
            return False, "approval token already used"
        consumed.add(nonce)
    return True, "ok"


@dataclass
class Approval:
    approved: bool
    token: Optional[str] = None
    decision: str = "no"


class ApprovalGate:
    """Terminal yes/no prompt. Only an explicit 'yes'/'y' mints a token."""

    def __init__(self, secret: str, ttl: int = DEFAULT_TTL,
                 input_fn: Callable[[str], str] = input,
                 output_fn: Callable[[str], None] = print):
        self.secret = secret
        self.ttl = ttl
        self.input_fn = input_fn
        self.output_fn = output_fn

    def request(self, summary: str, repo: str, commit: str) -> Approval:
        self.output_fn(summary)
        try:
            answer = self.input_fn("Create GitHub issue with redacted details? [yes/no]: ")
        except (EOFError, KeyboardInterrupt):
            return Approval(False, None, "no")
        if answer.strip().lower() in ("yes", "y"):
            return Approval(True, issue_token(self.secret, repo, commit, self.ttl), "yes")
        return Approval(False, None, "no")
