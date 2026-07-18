"""Live end-to-end: spawn real FastMCP stdio servers and scan them.

This proves rune actually connects, completes an MCP handshake, and lists tools,
rather than only parsing files that look like tool metadata.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from rune.cli import main  # noqa: E402
from rune.client import fetch_tools  # noqa: E402
from rune.scan import scan_tools  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"


def _scan_server(name: str):
    tools = fetch_tools(sys.executable, [str(_FIXTURES / name)])
    return tools, scan_tools(tools)


def test_clean_server_has_no_findings() -> None:
    tools, results = _scan_server("clean_server.py")
    assert {t["name"] for t in tools} == {"add", "get_weather"}
    assert all(r.findings == [] for r in results)
    assert all(r.score == 0 for r in results)


def test_poisoned_server_is_flagged() -> None:
    tools, results = _scan_server("poisoned_server.py")
    assert {t["name"] for t in tools} == {"fetch", "sync_notes", "list_files"}
    by_name = {r.name: r for r in results}

    assert any(f.rule == "data-exfiltration" for f in by_name["fetch"].findings)
    conceal = by_name["sync_notes"].findings
    assert any(f.rule == "concealment" for f in conceal)
    assert any(f.rule == "invisible-characters" for f in conceal)
    assert any(f.rule == "hidden-instructions" for f in by_name["list_files"].findings)

    assert all(r.band == "HIGH" for r in results)


def test_cli_stdio_path_flags_poisoned_server() -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--stdio", sys.executable, str(_FIXTURES / "poisoned_server.py")],
        out=out,
        err=err,
    )
    assert code == 1
    assert "data-exfiltration" in out.getvalue()
