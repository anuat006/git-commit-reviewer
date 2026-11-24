"""Throwaway MCP server used ONLY by tests to exercise McpClient. Not the real tools."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server  # noqa: E402
except ImportError:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as _Server  # noqa: E402

from reviewer.approval import SECRET_ENV, verify_token  # noqa: E402

mcp = _Server("stub")
_used: set = set()


@mcp.tool()
def get_commit_diff(repository: str, commit_id: str) -> dict:
    return {"success": True, "summary": "1 file", "error": None,
            "data": {"diff_handle": "h1", "changed_files": ["config.py"]}}


@mcp.tool()
def scan_commit(diff_handle: str) -> dict:
    return {"success": True, "summary": "1 finding", "error": None, "data": {"findings": [
        {"rule": "api_token", "file": "config.py", "line": 3, "evidence": "API_KEY = 'AK****'",
         "severity": "HIGH", "confidence": "high"}]}}


@mcp.tool()
def create_security_issue(github_repo: str, repository: str, commit_id: str, title: str,
                          body: str, approval_token: str) -> dict:
    ok, why = verify_token(os.environ[SECRET_ENV], approval_token, repository, commit_id, _used)
    if not ok:
        return {"success": False, "summary": "rejected", "data": {}, "error": why}
    return {"success": True, "summary": "created", "error": None,
            "data": {"issue_number": 7, "issue_url": f"https://github.com/{github_repo}/issues/7"}}


if __name__ == "__main__":
    mcp.run()
