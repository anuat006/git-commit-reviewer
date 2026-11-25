"""MCP server: three tools, structured JSON results (success, summary, data, error)."""
from __future__ import annotations

try:                                        # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
except ImportError:                         # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as _Server

from .common import logged
from .git_tool import get_commit_diff as _diff
from .github_tool import create_security_issue as _issue
from .scanner import scan_commit as _scan

mcp = _Server("security-commit-reviewer")


@mcp.tool()
@logged
def get_commit_diff(repository: str, commit_id: str) -> dict:
    """Identify one commit of a local git repository. Returns {repository, commit_id,
    changed_files}: pass this `data` object to scan_commit. The raw diff is never returned."""
    return _diff(repository, commit_id)


@mcp.tool()
@logged
def scan_commit(diff_result: dict) -> dict:
    """Scan a commit for hard-coded passwords, API tokens and unsafe configuration.
    Input: the `data` object returned by get_commit_diff. Evidence is always redacted."""
    return _scan(diff_result)


@mcp.tool()
@logged
def create_security_issue(github_repo: str, repository: str, commit_id: str, title: str,
                          body: str, approval_token: str) -> dict:
    """Create ONE redacted GitHub issue. Rejected unless approval_token was minted after a
    human typed yes."""
    return _issue(github_repo, repository, commit_id, title, body, approval_token)
