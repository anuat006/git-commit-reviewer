"""MCP server: three tools, structured JSON results (success, summary, data, error)."""
from __future__ import annotations

try:                                        # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
except ImportError:                         # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as _Server

from .git_tool import get_commit_diff as _diff
from .github_tool import create_security_issue as _issue
from .scanner import scan_commit as _scan

mcp = _Server("security-commit-reviewer")


@mcp.tool()
def get_commit_diff(repository: str, commit_id: str) -> dict:
    """Read one commit from a local git repository. Returns changed files and an opaque
    diff_handle. The raw diff is never returned."""
    return _diff(repository, commit_id)


@mcp.tool()
def scan_commit(diff_handle: str) -> dict:
    """Scan the commit behind diff_handle for hard-coded passwords, API tokens and unsafe
    configuration. Evidence is always redacted."""
    return _scan(diff_handle)


@mcp.tool()
def create_security_issue(github_repo: str, repository: str, commit_id: str, title: str,
                          body: str, approval_token: str) -> dict:
    """Create ONE redacted GitHub issue. Rejected unless approval_token was minted after a
    human typed yes."""
    return _issue(github_repo, repository, commit_id, title, body, approval_token)
