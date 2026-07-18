"""Command-line entry point for rune."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, TextIO

from .models import Severity
from .report import render_json, render_text
from .scan import scan_tools

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
        "{\"tools\": [...]} object)",
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
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI color in text output"
    )
    parser.add_argument("--version", action="version", version=f"rune {_VERSION}")
    return parser


def _load_manifest(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return _normalize(data)


def _normalize(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        tools = data.get("tools")
        if isinstance(tools, list):
            data = tools
        elif any(k in data for k in ("name", "description", "inputSchema")):
            data = [data]
        else:
            raise ValueError('manifest object has no "tools" list')
    if not isinstance(data, list):
        raise ValueError("manifest must be a list of tools or a {\"tools\": [...]} object")
    tools = [t for t in data if isinstance(t, dict)]
    if not tools and data:
        raise ValueError("manifest contains no tool objects")
    return tools


def _want_color(args: argparse.Namespace, out: TextIO) -> bool:
    if args.no_color or args.json or os.environ.get("NO_COLOR"):
        return False
    return hasattr(out, "isatty") and out.isatty()


def main(
    argv: list[str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    import sys

    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    parser = _build_parser()
    args = parser.parse_args(argv)

    manifest = args.manifest_flag or args.manifest
    if bool(manifest) == bool(args.stdio):
        print("rune: give exactly one of a manifest path or --stdio CMD", file=err)
        return _EXIT_ERROR

    try:
        if args.stdio:
            from .client import LiveScanError, fetch_tools

            try:
                tools = fetch_tools(args.stdio[0], list(args.stdio[1:]))
            except LiveScanError as exc:
                print(f"rune: live scan failed: {exc}", file=err)
                return _EXIT_ERROR
        else:
            tools = _load_manifest(manifest)
    except FileNotFoundError:
        print(f"rune: no such file: {manifest}", file=err)
        return _EXIT_ERROR
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"rune: cannot read manifest: {exc}", file=err)
        return _EXIT_ERROR

    results = scan_tools(tools)

    if args.json:
        print(render_json(results), file=out)
    else:
        print(render_text(results, color=_want_color(args, out)), file=out)

    threshold = Severity.from_label(args.fail_on)
    hit = any(f.severity >= threshold for r in results for f in r.findings)
    return _EXIT_FINDING if hit else _EXIT_CLEAN
