"""Fetch model-facing metadata from a live MCP server over stdio.

rune connects, completes the handshake, and lists the server's tools, prompts
and resources, then disconnects. Listing is all it does: it never calls a tool,
reads a resource's body, or renders a prompt, so nothing the server can execute
is triggered. The name, description and schema a listing returns are exactly the
text a client's model reads as trusted context, which is the surface rune scans.

Prompts and resources are only listed when the server advertises them in its
capabilities, and a server that advertises but fails to list them is treated as
having none rather than failing the whole scan.

The mcp SDK is an optional dependency; it is imported lazily so the offline
manifest scanner works with no third-party packages installed.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any


class LiveScanError(RuntimeError):
    """Raised when the server cannot be reached or listed."""


def fetch_metadata(
    command: str, args: list[str], *, timeout: float = 20.0
) -> dict[str, list[dict[str, Any]]]:
    """Spawn an MCP stdio server and list its tools, prompts and resources.

    Returns a dict keyed by kind (``tool``/``prompt``/``resource``) so the same
    scanner path handles a live server and a saved manifest.
    """
    try:
        return asyncio.run(_fetch(command, args, timeout))
    except LiveScanError:
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        raise LiveScanError(str(exc)) from exc


async def _fetch(
    command: str, args: list[str], timeout: float
) -> dict[str, list[dict[str, Any]]]:
    try:
        from mcp import ClientSession, McpError, StdioServerParameters
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

    async def run() -> dict[str, list[dict[str, Any]]]:
        # Send the server's own stderr nowhere; we only trust the listings.
        with open(os.devnull, "w", encoding="ascii") as errsink:
            async with stdio_client(params, errlog=errsink) as (read, write):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    caps = init.capabilities

                    tools = [t.model_dump(mode="json") for t in (await session.list_tools()).tools]

                    prompts: list[dict[str, Any]] = []
                    if caps.prompts is not None:
                        try:
                            listed = await session.list_prompts()
                            prompts = [p.model_dump(mode="json") for p in listed.prompts]
                        except McpError:
                            prompts = []

                    resources: list[dict[str, Any]] = []
                    if caps.resources is not None:
                        try:
                            r_listed = await session.list_resources()
                            resources = [r.model_dump(mode="json") for r in r_listed.resources]
                        except McpError:
                            resources = []
                        try:
                            t_listed = await session.list_resource_templates()
                            resources += [
                                t.model_dump(mode="json") for t in t_listed.resourceTemplates
                            ]
                        except McpError:
                            pass

                    return {"tool": tools, "prompt": prompts, "resource": resources}

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise LiveScanError(f"server did not respond within {timeout:.0f}s") from exc
