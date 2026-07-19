"""Command-line entry point for rune."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, TextIO

from .models import Severity
from .report import render_json, render_text
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
        "--no-color", action="store_true", help="disable ANSI color in text output"
    )
    parser.add_argument("--version", action="version", version=f"rune {_VERSION}")
    return parser


# The manifest keys that carry each kind of listing.
_MANIFEST_KEYS = {"tools": "tool", "prompts": "prompt", "resources": "resource"}


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
        data = json.loads(text)
    else:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    return _normalize(data)


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
    """
    groups = _listing_groups(data)
    inner = data.get("result")
    if isinstance(inner, dict):
        groups = {kind: list(entities) for kind, entities in groups.items()}
        for kind, entities in _envelope_groups(inner).items():
            groups.setdefault(kind, []).extend(entities)
    return groups


def _normalize(data: Any) -> dict[str, list[dict[str, Any]]]:
    """Turn a manifest into entity lists keyed by kind.

    Accepts a bare tools array, a single tool object, or an object carrying any
    of "tools", "prompts" and "resources" (an exported MCP listing may hold more
    than one). The kind keys let one file describe a whole server's surface. A
    raw JSON-RPC response is accepted too: the listing under "result" is
    unwrapped, so a captured "tools/list" reply scans without hand-editing.
    """
    if isinstance(data, list):
        # A bare array has no key to name, so errors point at the file itself.
        return {"tool": _entities(data, "manifest")}

    if isinstance(data, dict):
        groups = _envelope_groups(data)
        if groups:
            return groups
        raise ValueError('manifest object has no "tools", "prompts" or "resources" list')

    raise ValueError(
        'manifest must be a list of tools or an object with a '
        '"tools", "prompts" or "resources" list'
    )


def _want_color(args: argparse.Namespace, out: TextIO) -> bool:
    if args.no_color or args.json or os.environ.get("NO_COLOR"):
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
    if bool(manifest) == bool(args.stdio):
        print("rune: give exactly one of a manifest path or --stdio CMD", file=err)
        return _EXIT_ERROR

    if args.baseline and args.write_baseline:
        print("rune: use --baseline or --write-baseline, not both", file=err)
        return _EXIT_ERROR

    try:
        if args.stdio:
            from .client import LiveScanError, fetch_metadata

            try:
                groups = fetch_metadata(args.stdio[0], list(args.stdio[1:]))
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

    if args.json:
        print(render_json(results, baselined=baselined), file=out)
    else:
        print(render_text(results, color=_want_color(args, out), baselined=baselined), file=out)

    threshold = Severity.from_label(args.fail_on)
    hit = any(f.severity >= threshold for r in results for f in r.findings)
    return _EXIT_FINDING if hit else _EXIT_CLEAN
