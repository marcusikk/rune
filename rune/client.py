"""Fetch tool metadata from a live MCP server over stdio.

rune connects, completes the handshake, lists the tools, and disconnects. It
never calls a tool and never reads resources or prompts, so listing a poisoned
server's tools is the only thing that touches it.

The mcp SDK is an optional dependency; it is imported lazily so the offline
manifest scanner works with no third-party packages installed.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any


class LiveScanError(RuntimeError):
    """Raised when the server cannot be reached or listed."""


def fetch_tools(command: str, args: list[str], *, timeout: float = 20.0) -> list[dict[str, Any]]:
    """Spawn an MCP stdio server, list its tools, and return them as dicts."""
    try:
        return asyncio.run(_fetch(command, args, timeout))
    except LiveScanError:
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        raise LiveScanError(str(exc)) from exc


async def _fetch(command: str, args: list[str], timeout: float) -> list[dict[str, Any]]:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import get_default_environment, stdio_client
    except ImportError as exc:
        raise LiveScanError(
            "live scanning needs the mcp package: pip install 'rune-scan[live]'"
        ) from exc

    params = StdioServerParameters(
        command=command,
        args=args,
        env=get_default_environment(),
    )

    async def run() -> list[dict[str, Any]]:
        # Send the server's own stderr nowhere; we only trust list_tools output.
        with open(os.devnull, "w", encoding="ascii") as errsink:
            async with stdio_client(params, errlog=errsink) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    return [tool.model_dump(mode="json") for tool in listed.tools]

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise LiveScanError(f"server did not respond within {timeout:.0f}s") from exc
