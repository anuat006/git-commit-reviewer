"""Thin MCP client: connects to ONE local MCP server over stdio and calls its tools.

The official `mcp` SDK is async; the agent is synchronous, so the session lives on a
private event loop in a background thread and calls are bridged with a timeout.
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import json
import os
import threading
from contextlib import AsyncExitStack
from typing import Any, Optional


class McpUnavailable(Exception):
    """Server could not start or is missing required tools."""


class ToolTimeout(Exception):
    """A tool call exceeded its timeout."""


class ToolCallError(Exception):
    """Transport/protocol failure (not a tool-reported success=False)."""


class McpClient:
    def __init__(self, command: str, args: Optional[list[str]] = None,
                 env: Optional[dict[str, str]] = None, startup_timeout: float = 15.0):
        self.command, self.args = command, args or []
        self.env, self.startup_timeout = env or {}, startup_timeout
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stack: Optional[AsyncExitStack] = None
        self._session = None

    # ---- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        try:
            import mcp  # noqa: F401
        except ImportError as exc:
            raise McpUnavailable("`mcp` package not installed (pip install mcp)") from exc
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        fut = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        try:
            fut.result(timeout=self.startup_timeout)
        except Exception as exc:
            fut.cancel()
            self.close()
            raise McpUnavailable(f"MCP server failed to start: {exc!r}") from exc

    async def _connect(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(command=self.command, args=self.args,
                                       env={**os.environ, **self.env})
        self._stack = AsyncExitStack()
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

    def close(self) -> None:
        loop, stack = self._loop, self._stack
        if loop and stack:
            try:
                asyncio.run_coroutine_threadsafe(stack.aclose(), loop).result(timeout=5)
            except Exception:
                pass
        if loop:
            loop.call_soon_threadsafe(loop.stop)
        self._session = self._stack = self._loop = None

    # ---- tools -------------------------------------------------------------
    def list_tools(self) -> list[str]:
        res = self._run(self._session.list_tools(), self.startup_timeout)
        return [t.name for t in res.tools]

    def call_tool(self, name: str, args: dict[str, Any], timeout: float) -> dict[str, Any]:
        if not self._session:
            raise ToolCallError("MCP session not started")
        return self._parse(self._run(self._session.call_tool(name, args), timeout))

    def _run(self, coro, timeout: float):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=timeout)
        except cf.TimeoutError as exc:
            fut.cancel()
            raise ToolTimeout(f"timed out after {timeout}s") from exc
        except Exception as exc:
            raise ToolCallError(repr(exc)) from exc

    @staticmethod
    def _parse(res) -> dict[str, Any]:
        """Prefer structuredContent; otherwise JSON in the first text block."""
        sc = getattr(res, "structuredContent", None)
        if isinstance(sc, dict):
            payload = sc["result"] if set(sc) == {"result"} else sc
            if isinstance(payload, dict):
                return payload
        for block in getattr(res, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    break
        raise ToolCallError("MCP tool returned no parseable JSON")
