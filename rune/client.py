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
would capture. Each listing is paginated by the protocol, and every page is
fetched: a scan that stopped at the first ``nextCursor`` would let a server hide
a poisoned tool on page two and still be told CLEAN.

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


# A single listing that never stops paging is refused after this many distinct
# cursors. It is far past any real listing (a server with tens of thousands of
# tools still pages in well under this) and exists only so an endless stream of
# fresh cursors ends as _list_all's own named refusal, not as the scan timeout
# firing mid-loop and reaching the user as an opaque task-group teardown error.
_MAX_LISTING_PAGES = 1000


def fetch_metadata(
    command: str,
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: float = 20.0,
) -> dict[str, list[dict[str, Any]]]:
    """Spawn an MCP stdio server and list its tools, prompts and resources.

    Returns a dict keyed by kind (``tool``/``prompt``/``resource``) so the same
    scanner path handles a live server and a saved manifest.

    ``env`` and ``cwd`` are what an MCP client config records beside the command,
    and a server that needs them does not start without them. ``env`` is layered
    over the SDK's safe default environment rather than replacing it, which is
    how a client applies it: an entry naming one API key must not also strip the
    PATH the command is found on.
    """
    try:
        return asyncio.run(_fetch(command, args, env, cwd, timeout))
    except LiveScanError:
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        raise _own_refusal(exc) or LiveScanError(str(exc)) from exc


async def _fetch(
    command: str,
    args: list[str],
    env: dict[str, str] | None,
    cwd: str | None,
    timeout: float,
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
        env={**get_default_environment(), **(env or {})},
        cwd=cwd,
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
        raise _own_refusal(exc) or LiveScanError(_http_reason(exc)) from exc


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


def _own_refusal(exc: Exception) -> LiveScanError | None:
    """Pull rune's own refusal back out of a task group's wrapper, if one is in it.

    A refusal raised inside _collect (a pagination loop, a too-old SDK) crosses
    the SDK's task-group teardown on its way out, and when a child task also
    fails while unwinding, it arrives wrapped in an ExceptionGroup whose str()
    is the useless "unhandled errors in a TaskGroup". The refusal is the error
    that decided the outcome, so it is the one the user gets.
    """
    for leaf in _leaves(exc):
        if isinstance(leaf, LiveScanError):
            return leaf
    return None


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
    # mcp>=1.9 range this package declares. Newer SDKs also expose
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
        raise _own_refusal(exc) or LiveScanError(_http_reason(exc, path_hint="/sse")) from exc


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


async def _list_all(method: Any, field: str, what: str) -> list[Any]:
    """Follow one listing's pagination to its last page and return every item.

    The MCP listing calls are paginated: a server may answer with one page and a
    ``nextCursor`` naming the next, and a client is expected to keep asking. A
    scanner that reads only the first page hands an attacker the easiest evasion
    there is, a poisoned tool parked on page two, so every cursor is followed
    until a page arrives without one.

    A cursor rune has already sent back means the server is walking the listing
    in a circle. That is refused by name rather than ridden until the timeout,
    and the cursor's value is server-supplied text, so the message does not
    quote it. A server inventing endless *distinct* cursors slips that guard,
    since no cursor ever repeats, so the loop carries its own page bound: it
    stops with a named refusal after ``_MAX_LISTING_PAGES`` cursors rather than
    running until the scan timeout, whose teardown race would otherwise mask the
    real cause behind an opaque task-group error.
    """
    items: list[Any] = []
    seen: set[str] = set()
    result = await method()
    while True:
        items.extend(getattr(result, field))
        cursor = result.nextCursor
        if cursor is None:
            return items
        if cursor in seen:
            raise LiveScanError(
                f"server's {what} listing repeats a pagination cursor instead "
                "of ending; refusing to follow it in a circle"
            )
        if len(seen) >= _MAX_LISTING_PAGES:
            raise LiveScanError(
                f"server's {what} listing did not end after {_MAX_LISTING_PAGES} "
                "pages of distinct cursors; refusing to page it further"
            )
        seen.add(cursor)
        try:
            call = method(cursor=cursor)
        except TypeError as exc:
            # An SDK older than 1.9 has no cursor parameter. Left alone this
            # surfaces as "unexpected keyword argument", which blames rune's
            # code for what is a version gap with a one-line fix.
            raise LiveScanError(
                f"this server pages its {what} listing, and following the "
                "cursor needs mcp>=1.9: pip install -U mcp"
            ) from exc
        result = await call


async def _collect(session: Any, mcp_error: type[Exception]) -> dict[str, list[dict[str, Any]]]:
    """Run the handshake and list every metadata surface on an open session.

    Shared by both transports so neither can drift into scanning less than the
    other. ``mcp_error`` is passed in because the SDK is imported lazily.

    Every listing is fetched through :func:`_list_all`, so a paginated server is
    scanned to its last page before anything is judged.
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

    listed_tools = await _list_all(session.list_tools, "tools", "tools")
    tools = [t.model_dump(mode="json") for t in listed_tools]

    prompts: list[dict[str, Any]] = []
    if caps.prompts is not None:
        try:
            listed = await _list_all(session.list_prompts, "prompts", "prompts")
            prompts = [p.model_dump(mode="json") for p in listed]
        except mcp_error:
            prompts = []

    resources: list[dict[str, Any]] = []
    if caps.resources is not None:
        try:
            r_listed = await _list_all(session.list_resources, "resources", "resources")
            resources = [r.model_dump(mode="json") for r in r_listed]
        except mcp_error:
            resources = []
        try:
            t_listed = await _list_all(
                session.list_resource_templates, "resourceTemplates", "resource templates"
            )
            resources += [t.model_dump(mode="json") for t in t_listed]
        except mcp_error:
            pass

    return {
        "tool": tools,
        "prompt": prompts,
        "resource": resources,
        "server": server,
    }
