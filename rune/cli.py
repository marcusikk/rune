"""Command-line entry point for rune."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, TextIO

from .models import Severity
from .report import render_json, render_sarif, render_text
from .scan import scan_targets

_VERSION = "0.1.0"

_EXIT_CLEAN = 0
_EXIT_FINDING = 1
_EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rune",
        description="Scan an MCP server's tool metadata for hidden instructions "
        "before you wire it into an agent.",
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        help="path to a tools manifest (JSON array of tools or a "
        "{\"tools\": [...]} object); - reads it from stdin",
    )
    parser.add_argument(
        "--manifest",
        dest="manifest_flag",
        metavar="FILE",
        help="same as the positional manifest argument",
    )
    parser.add_argument(
        "--stdio",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="spawn a live stdio MCP server and scan it: --stdio CMD [ARGS...]",
    )
    parser.add_argument(
        "--http",
        metavar="URL",
        help="scan a live Streamable HTTP MCP server at URL (often ends in /mcp)",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="send an extra HTTP header with --http, e.g. "
        "'Authorization: Bearer TOKEN'; repeatable",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        default="medium",
        help="lowest severity that sets a non-zero exit (default: medium)",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="suppress findings recorded in FILE; anything new still fails",
    )
    parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="write the current findings to FILE as a baseline and exit 0",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="emit SARIF 2.1.0 for GitHub/GitLab code scanning",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI color in text output"
    )
    parser.add_argument("--version", action="version", version=f"rune {_VERSION}")
    return parser


# The manifest keys that carry each kind of listing.
_MANIFEST_KEYS = {"tools": "tool", "prompts": "prompt", "resources": "resource"}

# The MCP initialize-response fields a client feeds to its model, each mapped to
# the JSON type it must have. "instructions" is documented as a hint the client
# MAY add to the system prompt, and "serverInfo" carries the display name and
# title. Both are trusted context a poisoned server can load before a single tool
# is listed, so both are scanned. This mapping is the only definition of what
# counts as server metadata; _server_entity reads it rather than repeating it.
_SERVER_KEYS = {"instructions": str, "serverInfo": dict}


# The conventional stand-in for stdin, so a listing can be piped straight in
# (curl .../tools/list | rune --manifest -) without a temporary file.
_STDIN_ARG = "-"


def _load_manifest(path: str, stdin: TextIO) -> dict[str, list[dict[str, Any]]]:
    if path == _STDIN_ARG:
        text = stdin.read()
        if not text.strip():
            # Empty stdin is an operational error, not a clean scan: a gate that
            # reports 0 findings on no input at all is the wrong kind of quiet.
            raise ValueError("no JSON on stdin")
    else:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    return _normalize(_parse_document(text))


# Returned by _sse_payload when the input carries no SSE framing at all, so the
# caller re-raises the original JSON error rather than a misleading SSE one.
_NO_SSE = object()


def _parse_document(text: str) -> Any:
    """Parse the input as JSON, falling back to an SSE (text/event-stream) reply.

    An MCP Streamable HTTP server answers a tools/list POST with an event stream,
    not a bare JSON body: the reply arrives framed as ``event: message`` then
    ``data: {json}`` and a blank line. When the text is not JSON, lift the
    JSON-RPC message out of the SSE ``data:`` frames so the same
    ``curl ... | rune -`` pipe works against those servers, instead of forcing
    the framing to be stripped by hand first. The lifted message flows through
    the same _normalize path as a plain body, so nothing downstream changes.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        payload = _sse_payload(text)
        if payload is _NO_SSE:
            raise
        return payload


def _sse_data_events(text: str) -> list[str]:
    """Return the data payload of each dispatched SSE event, in order.

    Follows the EventSource line handling: a line is split on its first colon
    into a field name and value, one leading space is stripped from the value,
    ``data`` fields within an event join with newlines, a line beginning with a
    colon is a keep-alive comment, and a blank line dispatches the accumulated
    event. Only ``data`` is collected; the event type, id and retry fields do not
    carry the JSON body. Lines are split on CRLF, CR or LF, the three SSE line
    terminators, and nothing else.
    """
    events: list[str] = []
    data_lines: list[str] = []
    have_data = False
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            if have_data:
                events.append("\n".join(data_lines))
            data_lines = []
            have_data = False
            continue
        if line.startswith(":"):
            continue
        field, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
            have_data = True
    if have_data:
        events.append("\n".join(data_lines))
    return events


def _sse_payload(text: str) -> Any:
    """Lift the JSON-RPC reply out of an SSE stream, or signal it is not SSE.

    Returns ``_NO_SSE`` when the text has no ``data:`` frame, so a genuinely
    malformed JSON file still surfaces its own parse error rather than a
    confusing one about event streams. A stream that does carry frames but no
    JSON, or that carries more than one JSON-RPC response, is a loud error: a
    gate must never quietly pick one reply and skip a poisoned sibling. Server
    notifications (no ``result``/``error``) are ignored so a keep-alive or a
    progress event beside the real reply does not read as ambiguity.
    """
    data_events = _sse_data_events(text)
    if not data_events:
        return _NO_SSE
    scannable: list[Any] = []
    for chunk in data_events:
        try:
            message = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict | list):
            scannable.append(message)
    if not scannable:
        raise ValueError(
            "input is an SSE (text/event-stream) response but no data: frame "
            "held a JSON message to scan"
        )
    responses = [
        m for m in scannable if isinstance(m, dict) and ("result" in m or "error" in m)
    ]
    chosen = responses or scannable
    if len(chosen) > 1:
        raise ValueError(
            "the SSE stream carried more than one JSON-RPC response; save the "
            "single tools/list, prompts/list or resources/list reply and scan that"
        )
    return chosen[0]


# How to name a JSON value in an error message.
_JSON_TYPES = {
    dict: "an object",
    list: "a list",
    str: "a string",
    bool: "a boolean",
    int: "a number",
    float: "a number",
}


def _typename(value: Any) -> str:
    if value is None:
        return "null"
    return _JSON_TYPES.get(type(value), "an unsupported value")


def _entities(value: Any, label: str) -> list[dict[str, Any]]:
    """Coerce one manifest listing into the entity objects to scan.

    A listing rune cannot read is an error, never an empty scan. Skipping a
    key whose shape surprised us is the worst outcome a scanner has: the
    poisoned prompt is in the file, rune says CLEAN, and the gate is the thing
    that told you it was safe. So every entry a manifest presents gets scanned
    or the run exits 2 naming the key.

    A bare object stands in for a one-element list, matching the single-tool
    shape already accepted at the top level, and covers the saved-response
    shape too: scanning walks every nested string, so a listing wrapped in one
    more layer of object is still read rather than dropped. null means the key
    is absent, which is safe because null carries no metadata to miss.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        raise ValueError(
            f"{label} must be a list or an object, got {_typename(value)}"
        )
    for i, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                f"{label}[{i}] must be an object, got {_typename(item)}"
            )
    return value


def _listing_groups(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Extract the entity lists a single manifest object names directly.

    Handles the "tools"/"prompts"/"resources" keys and the bare single-tool
    shape. Returns an empty mapping when the object names no listing of its own,
    leaving it to the caller to try unwrapping a JSON-RPC "result" envelope.
    """
    present = [key for key in _MANIFEST_KEYS if key in data]
    if present:
        return {
            _MANIFEST_KEYS[key]: _entities(data[key], f'"{key}"')
            for key in present
        }
    if any(k in data for k in ("name", "description", "inputSchema")):
        return {"tool": [data]}
    return {}


def _envelope_groups(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Collect every listing an object carries, directly or under "result".

    An MCP "tools/list" reply is a JSON-RPC envelope: the real listing sits
    under "result", beside "jsonrpc" and "id". This merges the object's own
    listings with those inside a "result" envelope, recursing so a
    doubly-wrapped "result".result" is still reached. The union is taken per
    kind rather than letting either side suppress the other: a spec-compliant
    client reads "result", so a clean top-level decoy beside a poisoned "result"
    must not hide the poison. Top-level lists are copied before extending so a
    merge never mutates the caller's data in place.

    This never raises on the "no listing anywhere" case; that verdict belongs to
    the single caller, which can then point the error at the whole file. A
    "result" object that names no listing of its own contributes nothing and so
    cannot discard a valid top-level listing. A malformed listing (a "tools"
    that is not a list) still raises through _entities, because that is a shape
    rune must not silently skip.

    Server metadata ("instructions"/"serverInfo") is deliberately not unwrapped
    here: it is read only from the object handed to _normalize, so a raw
    JSON-RPC initialize reply with those fields hidden under "result" is still a
    named error rather than a silent miss.
    """
    groups = _listing_groups(data)
    inner = data.get("result")
    if isinstance(inner, dict):
        groups = {kind: list(entities) for kind, entities in groups.items()}
        for kind, entities in _envelope_groups(inner).items():
            groups.setdefault(kind, []).extend(entities)
    return groups


def _server_entity(data: dict[str, Any]) -> dict[str, Any] | None:
    """Pull an MCP server's own model-facing metadata out of an initialize result.

    Scopes to exactly the two fields a client reads, ``instructions`` (a string
    the spec says MAY be added to the system prompt) and ``serverInfo`` (the
    display name and title). Every other key in the response is left alone, so a
    benign ``protocolVersion`` or a ``nextCursor`` on a listing is never mistaken
    for server metadata. Widening this to "any key that is not a listing" is what
    turns an honest response into a false finding, so the set stays closed.

    A field that is present but the wrong type is an error naming the key, never
    a skip. Dropping it would scan whatever else the file holds and print CLEAN
    over metadata rune never read, the same silent miss _entities refuses for a
    malformed listing. null is the one exception: it carries nothing to miss, so
    it reads as absent.

    Returns None when no field carries content, so neither a plain tools listing
    nor an empty ``instructions`` string sprouts a phantom server entity. The
    live path in client.py skips empty instructions for the same reason.
    """
    entity: dict[str, Any] = {}
    for key, expected in _SERVER_KEYS.items():
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, expected):
            raise ValueError(
                f'"{key}" must be {_JSON_TYPES[expected]}, got {_typename(value)}'
            )
        if value:
            # "" and {} hold no text to scan, so an entity built from them would
            # be a row about nothing.
            entity[key] = value
    return entity or None


def _normalize(data: Any) -> dict[str, list[dict[str, Any]]]:
    """Turn a manifest into entity lists keyed by kind.

    Accepts a bare tools array, a single tool object, or an object carrying any
    of "tools", "prompts" and "resources" (an exported MCP listing may hold more
    than one), plus an initialize response whose own "instructions" and
    "serverInfo" are scanned as a "server" entity beside any listings present.
    The kind keys let one file describe a whole server's surface. A raw
    JSON-RPC response is accepted too, for listings: the listing under "result"
    is unwrapped, so a captured "tools/list" reply scans without hand-editing.
    """
    if isinstance(data, list):
        # A bare array has no key to name, so errors point at the file itself.
        return {"tool": _entities(data, "manifest")}

    if isinstance(data, dict):
        groups = _envelope_groups(data)
        server = _server_entity(data)
        if server is not None:
            groups["server"] = [server]
        if groups:
            return groups
        if "result" in data or "jsonrpc" in data:
            # A saved raw JSON-RPC message hides the payload one level down under
            # "result". Refusing loudly beats scanning the envelope's own keys
            # and reporting a confident CLEAN on a file whose payload was skipped.
            raise ValueError(
                'this looks like a raw JSON-RPC message; scan the "result" '
                "payload (the tools/list or initialize response body), not the "
                "whole envelope"
            )
        raise ValueError(
            'manifest object has nothing to scan: no "tools", "prompts" or '
            '"resources" listing, and no server "instructions"/"serverInfo" text'
        )

    raise ValueError(
        'manifest must be a list of tools or an object with a "tools", '
        '"prompts" or "resources" listing or server "instructions"'
    )


# Hosts where an unencrypted request never leaves the machine, so sending a
# credential over plain http to one of them is not exposing it on a network.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _parse_headers(values: list[str]) -> dict[str, str]:
    """Turn "Name: value" strings into a header dict.

    Splits on the first colon only, so a value that is itself a URL survives.
    A malformed entry raises without quoting the input: the thing most likely
    to be in a --header is a token, and it must not reach a terminal or a CI
    log just because it was typed wrong.
    """
    headers: dict[str, str] = {}
    for raw in values:
        name, sep, value = raw.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not name:
            raise ValueError('bad --header, expected "Name: value"')
        headers[name] = value
    return headers


def _check_http_url(url: str) -> None:
    """Reject a URL rune cannot fetch, before any credential is attached."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme in ("http", "https"):
        if not parts.hostname:
            raise ValueError(f"--http URL has no host: {url!r}")
        return
    if parts.netloc:
        # A real URL naming a transport rune cannot audit, e.g. ftp://host/x.
        raise ValueError(f"--http only speaks http and https, got {parts.scheme!r}")
    # No authority to speak to. Covers a bare "example.com/mcp", a bare path,
    # and "file:///etc/passwd", which urlsplit reads as a scheme with no host.
    raise ValueError(f"--http needs an http:// or https:// URL, got {url!r}")


def _cleartext_warning(url: str, headers: dict[str, str]) -> str | None:
    """Warn when credentials would cross a network unencrypted.

    Not fatal: an internal plain-http deployment is a real thing and the URL is
    the user's own explicit choice. Silence would not be, so it is said out loud.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if not headers or parts.scheme != "http":
        return None
    if (parts.hostname or "").lower() in _LOOPBACK_HOSTS:
        return None
    return (
        f"rune: warning: sending {len(headers)} header(s) unencrypted over http "
        f"to {parts.hostname}; use https if the endpoint offers it"
    )


def _sarif_uri(url: str) -> str:
    """The --http URL with anything secret stripped, for the SARIF artifact URI.

    A SARIF log is uploaded and kept, so a token that rode in the query string
    or in userinfo must not be written into it alongside the findings.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def _want_color(args: argparse.Namespace, out: TextIO) -> bool:
    if args.no_color or args.json or args.sarif or os.environ.get("NO_COLOR"):
        return False
    return hasattr(out, "isatty") and out.isatty()


def main(
    argv: list[str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    inp: TextIO | None = None,
) -> int:
    import sys

    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    inp = inp if inp is not None else sys.stdin
    parser = _build_parser()
    args = parser.parse_args(argv)

    manifest = args.manifest_flag or args.manifest
    sources = [bool(manifest), bool(args.stdio), bool(args.http)]
    if sum(sources) != 1:
        print(
            "rune: give exactly one of a manifest path, --stdio CMD, or --http URL",
            file=err,
        )
        return _EXIT_ERROR

    if args.header and not args.http:
        print("rune: --header only applies to --http", file=err)
        return _EXIT_ERROR

    headers: dict[str, str] = {}
    if args.http:
        try:
            _check_http_url(args.http)
            headers = _parse_headers(args.header)
        except ValueError as exc:
            print(f"rune: {exc}", file=err)
            return _EXIT_ERROR
        warning = _cleartext_warning(args.http, headers)
        if warning:
            print(warning, file=err)

    if args.baseline and args.write_baseline:
        print("rune: use --baseline or --write-baseline, not both", file=err)
        return _EXIT_ERROR

    if args.json and args.sarif:
        print("rune: use --json or --sarif, not both", file=err)
        return _EXIT_ERROR

    try:
        if args.stdio:
            from .client import LiveScanError, fetch_metadata

            try:
                groups = fetch_metadata(args.stdio[0], list(args.stdio[1:]))
            except LiveScanError as exc:
                print(f"rune: live scan failed: {exc}", file=err)
                return _EXIT_ERROR
        elif args.http:
            from .client import LiveScanError, fetch_metadata_http

            try:
                groups = fetch_metadata_http(args.http, headers=headers)
            except LiveScanError as exc:
                print(f"rune: live scan failed: {exc}", file=err)
                return _EXIT_ERROR
        else:
            groups = _load_manifest(manifest, inp)
    except FileNotFoundError:
        print(f"rune: no such file: {manifest}", file=err)
        return _EXIT_ERROR
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"rune: cannot read manifest: {exc}", file=err)
        return _EXIT_ERROR

    results = scan_targets(groups)

    if args.write_baseline:
        from .baseline import build_baseline

        document = build_baseline(results)
        try:
            with open(args.write_baseline, "w", encoding="utf-8") as fh:
                json.dump(document, fh, indent=2, ensure_ascii=True)
                fh.write("\n")
        except OSError as exc:
            print(f"rune: cannot write baseline: {exc}", file=err)
            return _EXIT_ERROR
        count = len(document["findings"])
        print(
            f"rune: wrote baseline with {count} finding(s) to {args.write_baseline}",
            file=err,
        )
        return _EXIT_CLEAN

    baselined = 0
    if args.baseline:
        from .baseline import BaselineError, apply_baseline, load_fingerprints

        try:
            accepted = load_fingerprints(args.baseline)
        except FileNotFoundError:
            print(f"rune: no such baseline: {args.baseline}", file=err)
            return _EXIT_ERROR
        except (BaselineError, OSError) as exc:
            print(f"rune: cannot read baseline: {exc}", file=err)
            return _EXIT_ERROR
        baselined = apply_baseline(results, accepted)

    if args.sarif:
        # A stdio or piped scan has no file on disk to point an alert at, so the
        # artifact URI is only set when a real manifest path was read, or when
        # --http gave a genuine URI to name (credentials stripped out of it).
        if args.http:
            source_uri = _sarif_uri(args.http)
        else:
            source_uri = manifest if manifest and manifest != _STDIN_ARG else None
        print(render_sarif(results, uri=source_uri, version=_VERSION), file=out)
    elif args.json:
        print(render_json(results, baselined=baselined), file=out)
    else:
        print(render_text(results, color=_want_color(args, out), baselined=baselined), file=out)

    threshold = Severity.from_label(args.fail_on)
    hit = any(f.severity >= threshold for r in results for f in r.findings)
    return _EXIT_FINDING if hit else _EXIT_CLEAN
