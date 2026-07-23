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

A credential handed to a remote scan is scoped to the origin of the URL it was
given for. The endpoint on the other end is the thing being audited, so it is
not trusted to redirect rune's headers somewhere else: see ``_OriginLock``.

The mcp SDK is an optional dependency; it is imported lazily so the offline
manifest scanner works with no third-party packages installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
from collections.abc import Callable
from typing import Any


class LiveScanError(RuntimeError):
    """Raised when the server cannot be reached or listed."""


# How long one server gets to accept the connection, complete the handshake and
# hand back all three listings. Enough for a server that is already installed,
# and the CLI's --timeout is what covers the one that has to fetch itself first.
DEFAULT_TIMEOUT = 20.0


def _budget(timeout: float) -> str:
    """Render a timeout budget for a message: 20s, and 0.5s when fractional.

    ``%g`` rather than a fixed precision, because a budget printed back as the
    "0s" a `.0f` makes of half a second reads as a rune bug rather than as the
    number the user typed.
    """
    return f"{timeout:g}s"


def _timed_out(timeout: float) -> LiveScanError:
    """The one message every transport raises when its budget runs out.

    It names the flag because the usual cause is not a broken server: a command
    like ``npx -y some-mcp-server`` downloads the package on its first run, and
    the fix is more time rather than a different config.
    """
    return LiveScanError(f"server did not respond within {_budget(timeout)} (see --timeout)")


async def _run_within(coro: Any, timeout: float) -> Any:
    """Run ``coro`` and turn "it did not finish in time" into ``_timed_out``.

    ``asyncio.wait_for`` normally does this itself, by cancelling the coroutine
    and catching the ``CancelledError`` that falls out of it. But the SDK's
    transports run their own ``TaskGroup`` inside, and on a loaded runner the
    cancellation can reach one of that group's own tasks mid I/O instead of
    unwinding cleanly, which then raises something else entirely (a broken
    pipe, wrapped as "unhandled errors in a TaskGroup") that ``wait_for`` has no
    reason to treat as its own timeout, so it lets that wrapper text out
    unconverted instead. Racing the coroutine against a plain sleep sidesteps
    the guesswork: once the clock, and not the coroutine's own exception, is
    what decided the outcome, whatever the cancelled task then raises while it
    unwinds is expected teardown noise, not the story to tell the caller.
    """
    task = asyncio.ensure_future(coro)
    done, _pending = await asyncio.wait({task}, timeout=timeout)
    if task not in done:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        raise _timed_out(timeout)
    return task.result()


def fetch_metadata(
    command: str,
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
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
        raise LiveScanError(str(exc)) from exc


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

    return await _run_within(run(), timeout)


def fetch_metadata_http(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, list[dict[str, Any]]]:
    """List a remote Streamable HTTP MCP server's metadata over the real transport.

    Same return shape and the same read-only listing pass as the stdio path, so a
    hosted server gets the full scan (handshake instructions, tools, prompts and
    resources) instead of only the one reply a captured curl can carry.

    ``headers`` are scoped to ``url``'s own origin: see ``_OriginLock``.
    """
    lock = _OriginLock(url, headers or {})
    return _guarded(lambda: asyncio.run(_fetch_http(url, headers or {}, timeout, lock)), lock)


def _guarded(
    run: Callable[[], dict[str, list[dict[str, Any]]]],
    lock: _OriginLock,
    *,
    path_hint: str = "/mcp",
) -> dict[str, list[dict[str, Any]]]:
    """Run a remote scan, and let a credential leaving the origin outrank its outcome.

    Whatever another origin answered is not the scan the user asked for, and a
    failure it caused is not the failure worth reporting: "server returned HTTP
    404" sends somebody looking for a typo in a URL that was never the problem.
    So the lock is checked on every path out, including the successful one, where
    the metadata is dropped rather than reported under the endpoint that was
    typed.
    """
    try:
        metadata = run()
    except LiveScanError:
        lock.check()
        raise
    except Exception as exc:  # surfaced to the CLI as an operational error
        lock.check()
        raise LiveScanError(_http_reason(exc, path_hint=path_hint)) from exc
    lock.check()
    return metadata


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


# The port a scheme uses when a URL does not name one. Origins are compared as
# whole triples, so leaving the default implicit would read https://host and
# https://host:443 as two different places to send a token.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: Any) -> tuple[str, str, int]:
    """The (scheme, host, port) triple a credential is scoped to.

    ``raw_host`` rather than ``host``: httpx hands back an internationalised
    host decoded to Unicode, and this triple is printed in a refusal, so taking
    the IDNA form keeps a look-alike hostname out of rune's own prose. It is
    also the form that makes two spellings of one host compare equal.
    """
    host = url.raw_host.decode("ascii", "replace").lower()
    return (url.scheme, host, url.port or _DEFAULT_PORTS.get(url.scheme, 0))


def _stays_on_origin(target: tuple[str, str, int], other: tuple[str, str, int]) -> bool:
    """Whether talking to ``other`` is still talking to ``target``.

    Deliberately httpx's own rule for keeping an ``Authorization`` header across
    a redirect: the same scheme, host and port, or the plain-to-TLS upgrade of
    one host, which puts the credential in front of the host it was meant for
    over a better transport rather than handing it to somebody else. Matching
    that rule rather than inventing one means rune's headers and httpx's are
    scoped to the same place, so no header is protected less than Authorization.
    """
    if target == other:
        return True
    return (
        target[1] == other[1]
        and (target[0], target[2]) == ("http", 80)
        and (other[0], other[2]) == ("https", 443)
    )


def _show_origin(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    if ":" in host:  # an IPv6 literal is written bracketed inside a URL
        host = f"[{host}]"
    if port and port != _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


class _OriginLock:
    """Keep a scan's credentials on the origin the user named.

    rune is pointed at servers precisely because they are not trusted yet, and a
    server answers redirects. httpx drops an ``Authorization`` header when a
    redirect leaves the origin, but a hosted MCP server is as likely to want
    ``X-Api-Key`` or a vendor's own header, and those rode along untouched: a
    302 was all it took to collect the token of anyone who scanned the endpoint.

    The lock strips every header rune was handed off any request that leaves
    that origin, and remembers where the request was going, so the run reports a
    redirect it refused to follow with credentials instead of a scan of
    somewhere else. Being an httpx request hook rather than redirect-specific
    logic, it covers every request the transport makes, including the POST an
    HTTP+SSE server sends the client to its own announced endpoint.
    """

    def __init__(self, url: str, headers: dict[str, str]) -> None:
        self._url = url
        # No credentials means nothing to keep anywhere: the lock stays inactive,
        # no hook is installed, and the scan follows a redirect as it always did.
        self._names = tuple(headers)
        # Read in factory(), the first point where httpx is known to be present.
        # Nothing consults it before then, since nothing calls the hook.
        self._origin = ("", "", 0)
        self.left_for: str | None = None

    @property
    def active(self) -> bool:
        return bool(self._names)

    async def __call__(self, request: Any) -> None:
        destination = _origin(request.url)
        if _stays_on_origin(self._origin, destination):
            return
        for name in self._names:
            request.headers.pop(name, None)
        if self.left_for is None:
            # The first hand-off is the one to report; a chain of redirects past
            # it says nothing more about where the credentials were headed.
            self.left_for = _show_origin(destination)

    def factory(self, base: Any) -> Any:
        """Wrap the SDK's own httpx client factory so the hook rides along.

        Wrapping rather than building a client here keeps the SDK's redirect and
        timeout defaults the SDK's, so an upgrade cannot leave rune quietly
        using different transport settings than the client it is standing in for.

        This is also where the target origin is read, rather than in ``__init__``:
        parsing it needs httpx, and a rune installed without the live extra has
        to reach its own "install the mcp package" message instead of an
        ImportError from a library the user never asked for.
        """
        import httpx

        self._origin = _origin(httpx.URL(self._url))

        def build(headers: Any = None, timeout: Any = None, auth: Any = None) -> Any:
            client = base(headers=headers, timeout=timeout, auth=auth)
            hooks = dict(client.event_hooks)
            hooks["request"] = [*hooks.get("request", []), self]
            client.event_hooks = hooks
            return client

        return build

    def check(self) -> None:
        """Raise if this scan's credentials were asked to leave their origin."""
        if self.left_for is None:
            return
        raise LiveScanError(
            f"endpoint redirected to {self.left_for}, a different origin: the "
            "credentials for this scan were not sent there and nothing that "
            "answered has been scanned. Point rune at the endpoint you mean to "
            "audit rather than at one that hands your token somewhere else"
        )


def _client_factory(transport: Any, lock: _OriginLock) -> dict[str, Any]:
    """The ``httpx_client_factory`` keyword for a transport, when one is needed.

    Empty when the scan carries no credentials, which is what keeps an
    unauthenticated scan working on any SDK in range. When it does carry them,
    an SDK too old to take the hook is named as the thing to upgrade: silently
    scanning without the lock would be the leak this exists to close.
    """
    if not lock.active:
        return {}
    if "httpx_client_factory" not in inspect.signature(transport).parameters:
        raise LiveScanError(
            "sending a header to a remote server needs mcp>=1.10, the release "
            "that lets rune keep your credentials on one origin across a "
            "redirect: pip install -U mcp"
        )
    # The SDK's own default factory, which is what the transport would have
    # called for itself; rune only decorates the client it returns.
    from mcp.shared._httpx_utils import create_mcp_http_client

    return {"httpx_client_factory": lock.factory(create_mcp_http_client)}


async def _fetch_http(
    url: str, headers: dict[str, str], timeout: float, lock: _OriginLock
) -> dict[str, list[dict[str, Any]]]:
    # streamablehttp_client is the entry point that exists across the whole
    # mcp>=1.10 range this package declares. Newer SDKs also expose
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

    locked = _client_factory(streamablehttp_client, lock)

    async def run() -> dict[str, list[dict[str, Any]]]:
        async with (
            streamablehttp_client(url, headers=headers or None, timeout=timeout, **locked) as (
                read,
                write,
                _session_id,
            ),
            ClientSession(read, write) as session,
        ):
            return await _collect(session, McpError)

    return await _run_within(run(), timeout)


def fetch_metadata_sse(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, list[dict[str, Any]]]:
    """List a remote MCP server's metadata over the deprecated HTTP+SSE transport.

    The older two-endpoint ``/sse`` transport is still what many hosted servers
    speak. Same return shape and the same read-only listing pass as the stdio and
    Streamable HTTP paths, so such a server gets the full scan (handshake
    instructions, tools, prompts and resources) instead of only the one reply a
    captured curl can carry.

    ``headers`` are scoped to ``url``'s own origin: see ``_OriginLock``.
    """
    lock = _OriginLock(url, headers or {})
    return _guarded(
        lambda: asyncio.run(_fetch_sse(url, headers or {}, timeout, lock)),
        lock,
        path_hint="/sse",
    )


async def _fetch_sse(
    url: str, headers: dict[str, str], timeout: float, lock: _OriginLock
) -> dict[str, list[dict[str, Any]]]:
    try:
        from mcp import ClientSession, McpError
        from mcp.client.sse import sse_client
    except ImportError as exc:
        raise LiveScanError(
            "live scanning needs the mcp package: pip install 'rune-scan[live]'"
        ) from exc

    locked = _client_factory(sse_client, lock)

    async def run() -> dict[str, list[dict[str, Any]]]:
        # sse_client yields (read, write); it holds a long-lived GET stream open
        # for server->client messages, so the connect timeout and the overall
        # budget below are what bound a server that accepts the socket but never
        # sends its endpoint event.
        async with (
            sse_client(url, headers=headers or None, timeout=timeout, **locked) as (read, write),
            ClientSession(read, write) as session,
        ):
            return await _collect(session, McpError)

    return await _run_within(run(), timeout)


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
