"""CLI:  python -m reviewer --repo <local repo> --commit <id> [--model local|copilot]

Everything else (issue repo, tokens, approval TTL, log level, audit file) comes from .env.
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import secrets
import sys
from dataclasses import dataclass

from .agent import RootAgent
from .approval import DEFAULT_TTL, SECRET_ENV, ApprovalGate
from .audit import AuditLog
from .envfile import load_env_file
from .llm import LLMError
from .logsetup import LEVEL_ENV, setup_logging
from .mcp_client import McpClient
from .model_gateway import PROVIDERS, ModelGateway
from .schemas import ReviewRequest

ISSUE_REPO_ENV = "ISSUE_REPO"
APPROVAL_TTL_ENV = "APPROVAL_TTL"
AUDIT_LOG_ENV = "AUDIT_LOG"
DEFAULT_AUDIT_LOG = "audit_log.jsonl"
log = logging.getLogger("agent")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{4,64}$")
_LEVELS = ("DEBUG", "INFO", "WARNING")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reviewer", description="Autonomous security commit reviewer")
    p.add_argument("--repo", required=True, help="local repository path, e.g. ./demo")
    p.add_argument("--commit", required=True, help="commit id to review")
    p.add_argument("--model", default="local", choices=PROVIDERS,
                   help="local = Ollama (started if needed), copilot = GitHub Models (needs GITHUB_MODELS_TOKEN)")
    return p


def parse_repo(value: str) -> str:
    """Accept 'owner/name' or 'https://github.com/owner/name[.git][/]' and return 'owner/name'."""
    v = (value or "").strip()
    v = re.sub(r"^(?:https?://)?(?:www\.)?github\.com/", "", v, flags=re.I).rstrip("/")
    v = v[:-4] if v.lower().endswith(".git") else v
    if not _REPO.match(v):
        raise ValueError(f"{ISSUE_REPO_ENV} in .env: expected owner/name or a github.com URL, got {value!r}")
    return v


@dataclass
class Settings:
    """Validated run settings: the CLI arguments plus the values that come from .env."""
    issue_repo: str          # owner/name
    approval_ttl: int        # seconds the human approval stays valid
    log_level: str
    audit_log: str


def validate_args(a: argparse.Namespace) -> Settings:
    """Check the parsed arguments and the .env values BEFORE anything is started.
    Returns Settings; raises ValueError listing every problem."""
    problems: list[str] = []
    if not os.path.isdir(a.repo):
        problems.append(f"--repo: folder not found: {a.repo}")
    if not _COMMIT.match(a.commit or ""):
        problems.append(f"--commit: expected 4-64 hex characters, got {a.commit!r}")

    issue_repo = ""
    try:
        issue_repo = parse_repo(os.environ.get(ISSUE_REPO_ENV, ""))
    except ValueError as e:
        problems.append(str(e))

    ttl, raw_ttl = DEFAULT_TTL, os.environ.get(APPROVAL_TTL_ENV, "").strip()
    if raw_ttl:
        try:
            ttl = int(raw_ttl)
            if ttl <= 0:
                raise ValueError
        except ValueError:
            problems.append(f"{APPROVAL_TTL_ENV} in .env: expected a positive number of seconds, got {raw_ttl!r}")

    level = (os.environ.get(LEVEL_ENV) or "INFO").upper()
    if level not in _LEVELS:
        problems.append(f"{LEVEL_ENV} in .env: expected one of {', '.join(_LEVELS)}, got {level!r}")

    if problems:
        raise ValueError("\n  ".join(problems))
    return Settings(issue_repo, ttl, level, os.environ.get(AUDIT_LOG_ENV) or DEFAULT_AUDIT_LOG)


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    loaded = load_env_file()                                  # .env in the project folder
    setup_logging(os.environ.get(LEVEL_ENV))
    log.info("loaded .env variables: %s", ", ".join(loaded) or "-")
    try:
        cfg = validate_args(a)                                # fail fast: nothing is started if wrong
    except ValueError as e:
        print(f"error:\n  {e}", file=sys.stderr)
        return 2
    log.info("issue tracker repo: %s | approval TTL: %ss", cfg.issue_repo, cfg.approval_ttl)

    secret = secrets.token_hex(32)                            # per-run; shared only with the MCP server
    audit = AuditLog(cfg.audit_log)
    client = McpClient(sys.executable, ["-m", "reviewer_server"],
                       env={SECRET_ENV: secret, LEVEL_ENV: cfg.log_level})
    gateway = ModelGateway(a.model)                           # model name: REVIEWER_MODEL in .env
    try:
        gateway.start()
    except LLMError as e:                 # the model only writes the explanation; the review still works
        log.warning("model gateway: %s unavailable (%s); using rule-based text", gateway.label, e)
        gateway = None
    agent = RootAgent(client, ApprovalGate(secret, ttl=cfg.approval_ttl), audit, llm=gateway)
    try:
        out = agent.run(ReviewRequest(a.repo, a.commit, cfg.issue_repo))
    finally:
        if gateway is not None:
            gateway.close()                   # stops ollama only if this run started it

    print(f"\nResult : {out.status}")
    print(f"Detail : {out.message}")
    print(f"Trail  : {audit.trail()}")
    print(f"Log    : {cfg.audit_log}")
    return 0 if out.status in ("clean", "issue_created", "declined") else 1


if __name__ == "__main__":
    raise SystemExit(main())
