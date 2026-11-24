"""CLI: python -m reviewer --repo ./demo --commit abc123 --github-repo owner/security-demo"""
from __future__ import annotations

import argparse
import secrets
import shlex
import sys

from .agent import RootAgent
from .approval import SECRET_ENV, ApprovalGate
from .audit import AuditLog
from .llm import OllamaClient
from .mcp_client import McpClient
from .schemas import ReviewRequest


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reviewer", description="Autonomous security commit reviewer")
    p.add_argument("--repo", required=True, help="local repository path, e.g. ./demo")
    p.add_argument("--commit", required=True, help="commit id to review")
    p.add_argument("--github-repo", required=True, help="owner/name for the issue")
    p.add_argument("--mcp-command", default=f"{sys.executable} -m reviewer_server",
                   help="command that starts the local MCP server (stdio)")
    p.add_argument("--model", default=None,
                   help="Ollama model (default: $REVIEWER_MODEL or llama3.1; see `ollama list`)")
    p.add_argument("--no-llm", action="store_true", help="skip the model; use rule-based text")
    p.add_argument("--audit-log", default="audit_log.jsonl")
    p.add_argument("--approval-ttl", type=int, default=120)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    secret = secrets.token_hex(32)          # per-run; shared only with the MCP server
    audit = AuditLog(a.audit_log, echo=True)
    parts = shlex.split(a.mcp_command)
    client = McpClient(parts[0], parts[1:], env={SECRET_ENV: secret})
    agent = RootAgent(client, ApprovalGate(secret, ttl=a.approval_ttl), audit,
                      llm=None if a.no_llm else OllamaClient(a.model))
    out = agent.run(ReviewRequest(a.repo, a.commit, a.github_repo))

    print(f"\nResult : {out.status}")
    print(f"Detail : {out.message}")
    print(f"Trail  : {audit.trail()}")
    print(f"Log    : {a.audit_log}")
    return 0 if out.status in ("clean", "issue_created", "declined") else 1


if __name__ == "__main__":
    raise SystemExit(main())
