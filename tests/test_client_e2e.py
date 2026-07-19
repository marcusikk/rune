"""Live end-to-end: spawn real FastMCP stdio servers and scan them.

This proves rune actually connects, completes an MCP handshake, and lists tools,
prompts and resources, rather than only parsing files that look like metadata.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from rune.cli import main  # noqa: E402
from rune.client import fetch_metadata  # noqa: E402
from rune.scan import scan_targets  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"


def _scan_server(name: str):
    groups = fetch_metadata(sys.executable, [str(_FIXTURES / name)])
    return groups, scan_targets(groups)


def test_clean_server_has_no_findings() -> None:
    groups, results = _scan_server("clean_server.py")
    assert {t["name"] for t in groups["tool"]} == {"add", "get_weather"}
    assert all(r.findings == [] for r in results)
    assert all(r.score == 0 for r in results)


def test_poisoned_server_is_flagged() -> None:
    groups, results = _scan_server("poisoned_server.py")
    assert {t["name"] for t in groups["tool"]} == {"fetch", "sync_notes", "list_files"}
    by_name = {r.name: r for r in results}

    assert any(f.rule == "data-exfiltration" for f in by_name["fetch"].findings)
    conceal = by_name["sync_notes"].findings
    assert any(f.rule == "concealment" for f in conceal)
    assert any(f.rule == "invisible-characters" for f in conceal)
    assert any(f.rule == "hidden-instructions" for f in by_name["list_files"].findings)

    assert all(r.band == "HIGH" for r in results if r.kind == "tool")
    # serverInfo is always returned by the handshake, so a clean-named server
    # produces a clean server entity beside the poisoned tools.
    assert by_name["poisoned"].kind == "server"
    assert by_name["poisoned"].band == "CLEAN"


def test_prompts_and_resources_are_listed_and_scanned() -> None:
    # A poisoned prompt description and a poisoned resource description are
    # trusted context a client's model reads, exactly like a tool description.
    # rune must list both over the real protocol and flag them.
    groups, results = _scan_server("full_server.py")
    assert {p["name"] for p in groups["prompt"]} == {"summarize"}
    assert {r["name"] for r in groups["resource"]} == {"app_config"}

    by_kind_name = {(r.kind, r.name): r for r in results}
    prompt = by_kind_name[("prompt", "summarize")]
    resource = by_kind_name[("resource", "app_config")]
    assert any(f.rule == "concealment" for f in prompt.findings)
    assert any(f.rule == "hidden-instructions" for f in resource.findings)


def test_cli_stdio_flags_a_poisoned_prompt() -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--stdio", sys.executable, str(_FIXTURES / "full_server.py")],
        out=out,
        err=err,
    )
    assert code == 1
    text = out.getvalue()
    assert "prompt summarize" in text
    assert "resource app_config" in text


def test_cli_stdio_path_flags_poisoned_server() -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--stdio", sys.executable, str(_FIXTURES / "poisoned_server.py")],
        out=out,
        err=err,
    )
    assert code == 1
    assert "data-exfiltration" in out.getvalue()


def test_server_instructions_are_listed_and_scanned() -> None:
    # A server returns its own instructions in the initialize handshake, and the
    # spec says a client MAY add that string to its model's system prompt. rune
    # must capture it over the real protocol and scan it like any other metadata.
    groups, results = _scan_server("instructed_server.py")
    assert len(groups["server"]) == 1
    assert groups["server"][0]["serverInfo"]["name"] == "notes"

    by_kind = {(r.kind, r.name): r for r in results}
    server = by_kind[("server", "notes")]
    assert any(f.rule == "concealment" for f in server.findings)
    # The clean tool beside it stays clean: the finding is in the instructions.
    assert all(r.findings == [] for (kind, _), r in by_kind.items() if kind == "tool")


def test_cli_stdio_flags_poisoned_server_instructions() -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["--stdio", sys.executable, str(_FIXTURES / "instructed_server.py")],
        out=out,
        err=err,
    )
    assert code == 1
    assert "server notes" in out.getvalue()
