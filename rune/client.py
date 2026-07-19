"""Fetch model-facing metadata from a live MCP server over stdio or HTTP.

rune connects, completes the handshake, and lists the server's tools, prompts
and resources, then disconnects. Listing is all it does: it never calls a tool,
reads a resource's body, or renders a prompt, so nothing the server can execute
is triggered. The name, description and schema a listing returns are exactly the
text a client's model reads as trusted context, which is the surface rune scans.

All three transports (stdio, Streamable HTTP, and the deprecated HTTP+SSE) run
the identical listing pass in ``_collect``, so a remote server is scanned exactly
as deeply as a local stdio one: the handshake ``instructions`` and ``serverInfo``
plus all three listings, not just the ``tools/list`` reply a hand-written curl
would capture.

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
                    return await _collect(session, McpError)

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise LiveScanError(f"server did not respond within {timeout:.0f}s") from exc


def fetch_metadata_http(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = 20.0
) -> dict[str, list[dict[str, Any]]]:
    """List a remote Streamable HTTP MCP server's metadata over the real transport.

    Same return shape and the same read-only listing pass as the stdio path, so a
    hosted server gets the full scan (handshake instructions, tools, prompts and
    resources) instead of only the one reply a captured curl can carry.
    """
    try:
        return asyncio.run(_fetch_http(url, headers or {}, timeout))
    except LiveScanError:
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        raise LiveScanError(_http_reason(exc)) from exc


def _leaves(exc: BaseException) -> list[BaseException]:
    """Flatten an ExceptionGroup to the real errors inside it.

    The SDK runs the transport in a task group, so a plain 401 arrives wrapped
    as "unhandled errors in a TaskGroup", which tells a user nothing. Duck-types
    on ``exceptions`` rather than isinstance so the 3.10 backport works too.
    """
    inner = getattr(exc, "exceptions", None)
    if not inner:
        return [exc]
    return [leaf for sub in inner for leaf in _leaves(sub)]


def _http_reason(exc: Exception, *, path_hint: str = "/mcp") -> str:
    """Describe a transport failure without echoing request headers.

    An auth header value must never reach the terminal or a CI log, so the
    message is built from the status/class of the failure, not from a repr of
    the request that carried it. ``path_hint`` is the endpoint suffix the
    transport usually ends in, so a 404 points at ``/mcp`` for --http and ``/sse``
    for --sse rather than guessing.
    """
    leaves = _leaves(exc)
    for leaf in leaves:
        status = getattr(getattr(leaf, "response", None), "status_code", None)
        if status in (401, 403):
            return f"server returned HTTP {status}: the endpoint needs credentials (see --header)"
        if status == 404:
            return (
                "server returned HTTP 404: check the URL includes the MCP "
                f"path (often {path_hint})"
            )
        if status is not None:
            return f"server returned HTTP {status}"

    primary = leaves[0] if leaves else exc
    return f"{type(primary).__name__}: {primary}"


async def _fetch_http(
    url: str, headers: dict[str, str], timeout: float
) -> dict[str, list[dict[str, Any]]]:
    # streamablehttp_client is the entry point that exists across the whole
    # mcp>=1.0 range this package declares. Newer SDKs also expose
    # streamable_http_client, which takes a caller-built httpx client instead of
    # headers/timeout; using it here would mean a second, untestable code path
    # for the older SDKs still in range, so rune stays on the compatible one.
    try:
        from mcp import ClientSession, McpError
        from mcp.client.streamable_http import streamablehttp_client
    except ImportError as exc:
        raise LiveScanError(
            "live scanning needs the mcp package: pip install 'rune-scan[live]'"
        ) from exc

    async def run() -> dict[str, list[dict[str, Any]]]:
        async with (
            streamablehttp_client(url, headers=headers or None, timeout=timeout) as (
                read,
                write,
                _session_id,
            ),
            ClientSession(read, write) as session,
        ):
            return await _collect(session, McpError)

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise LiveScanError(f"server did not respond within {timeout:.0f}s") from exc


def fetch_metadata_sse(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = 20.0
) -> dict[str, list[dict[str, Any]]]:
    """List a remote MCP server's metadata over the deprecated HTTP+SSE transport.

    The older two-endpoint ``/sse`` transport is still what many hosted servers
    speak. Same return shape and the same read-only listing pass as the stdio and
    Streamable HTTP paths, so such a server gets the full scan (handshake
    instructions, tools, prompts and resources) instead of only the one reply a
    captured curl can carry.
    """
    try:
        return asyncio.run(_fetch_sse(url, headers or {}, timeout))
    except LiveScanError:
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        raise LiveScanError(_http_reason(exc, path_hint="/sse")) from exc


async def _fetch_sse(
    url: str, headers: dict[str, str], timeout: float
) -> dict[str, list[dict[str, Any]]]:
    try:
        from mcp import ClientSession, McpError
        from mcp.client.sse import sse_client
    except ImportError as exc:
        raise LiveScanError(
            "live scanning needs the mcp package: pip install 'rune-scan[live]'"
        ) from exc

    async def run() -> dict[str, list[dict[str, Any]]]:
        # sse_client yields (read, write); it holds a long-lived GET stream open
        # for server->client messages, so the connect timeout and the overall
        # wait_for below are what bound a server that accepts the socket but never
        # sends its endpoint event.
        async with (
            sse_client(url, headers=headers or None, timeout=timeout) as (read, write),
            ClientSession(read, write) as session,
        ):
            return await _collect(session, McpError)

    try:
        return await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise LiveScanError(f"server did not respond within {timeout:.0f}s") from exc


async def _collect(session: Any, mcp_error: type[Exception]) -> dict[str, list[dict[str, Any]]]:
    """Run the handshake and list every metadata surface on an open session.

    Shared by both transports so neither can drift into scanning less than the
    other. ``mcp_error`` is passed in because the SDK is imported lazily.
    """
    init = await session.initialize()
    caps = init.capabilities

    # The server's own instructions and serverInfo are the first trusted text a
    # client feeds its model, so scan them too.
    server: list[dict[str, Any]] = []
    entity: dict[str, Any] = {}
    if isinstance(init.instructions, str) and init.instructions:
        entity["instructions"] = init.instructions
    if init.serverInfo is not None:
        entity["serverInfo"] = init.serverInfo.model_dump(mode="json")
    if entity:
        server = [entity]

    tools = [t.model_dump(mode="json") for t in (await session.list_tools()).tools]

    prompts: list[dict[str, Any]] = []
    if caps.prompts is not None:
        try:
            listed = await session.list_prompts()
            prompts = [p.model_dump(mode="json") for p in listed.prompts]
        except mcp_error:
            prompts = []

    resources: list[dict[str, Any]] = []
    if caps.resources is not None:
        try:
            r_listed = await session.list_resources()
            resources = [r.model_dump(mode="json") for r in r_listed.resources]
        except mcp_error:
            resources = []
        try:
            t_listed = await session.list_resource_templates()
            resources += [t.model_dump(mode="json") for t in t_listed.resourceTemplates]
        except mcp_error:
            pass

    return {
        "tool": tools,
        "prompt": prompts,
        "resource": resources,
        "server": server,
    }
