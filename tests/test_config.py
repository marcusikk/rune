"""Reading an MCP client config and reporting a scan that covered several servers.

Everything here runs without the mcp SDK: the parser never connects, and the
orchestration tests use entries that fail before a transport is opened. The live
proof that a config entry actually starts and gets scanned is in
test_config_e2e.py.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from rune.baseline import BaselineEntry, build_baseline, fingerprint
from rune.cli import _redact, main
from rune.config import ConfigError, load_config, parse_config, select
from rune.models import Finding, Severity, SourceStatus, ToolResult
from rune.report import (
    render_config_text,
    render_source_notice,
    render_stale_notice,
    to_json,
    to_sarif,
)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out=out, err=err, inp=io.StringIO(""))
    return code, out.getvalue(), err.getvalue()


def _write(tmp_path: Path, data: object, name: str = "mcp.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _finding(rule: str = "concealment", match: str = "hide this") -> Finding:
    return Finding(
        rule=rule,
        severity=Severity.HIGH,
        path="description",
        offset=0,
        match=match,
        excerpt=match,
        message="directive to hide activity from the user",
    )


# --- parsing -----------------------------------------------------------------


def test_claude_desktop_shape_is_read() -> None:
    specs = parse_config(
        {
            "mcpServers": {
                "notes": {"command": "npx", "args": ["-y", "notes"], "env": {"K": "v"}},
            }
        }
    )
    assert [s.name for s in specs] == ["notes"]
    assert specs[0].transport == "stdio"
    assert specs[0].command == "npx"
    assert specs[0].args == ("-y", "notes")
    assert specs[0].env == {"K": "v"}
    assert specs[0].error is None


def test_vscode_servers_key_is_read() -> None:
    specs = parse_config({"servers": {"api": {"type": "http", "url": "https://x.test/mcp"}}})
    assert specs[0].transport == "http"
    assert specs[0].url == "https://x.test/mcp"


def test_both_maps_are_read_and_file_order_is_kept() -> None:
    specs = parse_config(
        {"mcpServers": {"a": {"command": "a"}}, "servers": {"b": {"command": "b"}}}
    )
    assert [s.name for s in specs] == ["a", "b"]


def test_a_name_under_both_maps_is_refused() -> None:
    # The two definitions can differ, and silently picking one would scan a
    # server the reader is not looking at.
    with pytest.raises(ConfigError, match="defined under both"):
        parse_config({"mcpServers": {"a": {"command": "x"}}, "servers": {"a": {"command": "y"}}})


def test_transport_is_guessed_from_the_url_when_not_declared() -> None:
    specs = parse_config(
        {
            "mcpServers": {
                "modern": {"url": "https://x.test/mcp"},
                "legacy": {"url": "https://x.test/sse"},
                "trailing": {"url": "https://x.test/sse/"},
            }
        }
    )
    assert [s.transport for s in specs] == ["http", "sse", "sse"]


@pytest.mark.parametrize(
    "declared,expected",
    [("stdio", "stdio"), ("http", "http"), ("streamable-http", "http"), ("SSE", "sse")],
)
def test_declared_type_wins_over_the_guess(declared: str, expected: str) -> None:
    entry = {"type": declared}
    entry["command" if expected == "stdio" else "url"] = (
        "x" if expected == "stdio" else "https://x.test/sse"
    )
    assert parse_config({"mcpServers": {"s": entry}})[0].transport == expected


def test_headers_and_cwd_are_carried() -> None:
    specs = parse_config(
        {
            "mcpServers": {
                "api": {"url": "https://x.test/mcp", "headers": {"Authorization": "Bearer t"}},
                "local": {"command": "x", "cwd": "/srv"},
            }
        }
    )
    assert specs[0].headers == {"Authorization": "Bearer t"}
    assert specs[1].cwd == "/srv"


def test_disabled_entry_is_kept_and_marked() -> None:
    # Kept rather than dropped: a report that never mentions a server cannot be
    # told apart from a report of a config that never had it.
    specs = parse_config({"mcpServers": {"old": {"command": "x", "disabled": True}}})
    assert specs[0].disabled is True
    assert specs[0].transport == "stdio"


@pytest.mark.parametrize(
    "entry,reason",
    [
        ({}, "needs a"),
        ({"comand": "typo"}, "needs a"),
        ({"command": "x", "url": "https://x.test/mcp"}, "both"),
        ({"command": ""}, "non-empty"),
        ({"command": 7}, "non-empty"),
        ({"command": "x", "args": "not-a-list"}, "args"),
        ({"command": "x", "args": [1]}, "args"),
        ({"command": "x", "env": {"PORT": 8080}}, "env"),
        ({"command": "x", "cwd": 3}, "cwd"),
        ({"type": "carrier-pigeon", "command": "x"}, "unknown transport"),
        ({"type": 3, "command": "x"}, '"type"'),
        ({"type": "http"}, 'needs a "url"'),
        ({"type": "stdio", "url": "https://x.test/mcp"}, 'needs a "command"'),
        ({"url": ""}, "non-empty"),
        ({"url": "https://x.test/mcp", "headers": {"A": 1}}, "headers"),
        ("not-an-object", "must be an object"),
    ],
)
def test_a_bad_entry_records_its_own_error(entry: object, reason: str) -> None:
    specs = parse_config({"mcpServers": {"bad": entry}})
    assert specs[0].error is not None
    assert reason in specs[0].error


def test_one_bad_entry_does_not_sink_the_others() -> None:
    # The whole point: an entry nobody has fixed must not stop the five servers
    # beside it from ever being audited.
    specs = parse_config(
        {"mcpServers": {"bad": {}, "good": {"command": "x"}, "worse": {"command": 1}}}
    )
    assert [s.name for s in specs] == ["bad", "good", "worse"]
    assert [s.error is None for s in specs] == [False, True, False]


@pytest.mark.parametrize(
    "data,reason",
    [
        ([], "must be a JSON object"),
        ({"tools": []}, 'no "mcpServers" or "servers" map'),
        ({"mcpServers": []}, "must be an object mapping"),
    ],
)
def test_a_file_with_no_server_list_raises(data: object, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        parse_config(data)


def test_jsonc_gets_a_hint(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text('{\n  // vscode allows this\n  "servers": {}\n}', encoding="utf-8")
    with pytest.raises(ConfigError, match="JSONC"):
        load_config(str(path))


def test_plain_bad_json_gets_no_jsonc_hint(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text("{oops", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(str(path))
    assert "JSONC" not in str(exc.value)


def test_select_narrows_and_keeps_config_order() -> None:
    specs = parse_config(
        {"mcpServers": {"a": {"command": "a"}, "b": {"command": "b"}, "c": {"command": "c"}}}
    )
    assert [s.name for s in select(specs, ["c", "a"])] == ["a", "c"]
    assert [s.name for s in select(specs, [])] == ["a", "b", "c"]


def test_select_refuses_an_unknown_name() -> None:
    # A typo that scanned nothing and reported CLEAN would be the worst outcome.
    specs = parse_config({"mcpServers": {"a": {"command": "a"}}})
    with pytest.raises(ConfigError, match="no server named 'nope'"):
        select(specs, ["nope"])


# --- identity ----------------------------------------------------------------


def test_a_source_qualifies_a_fingerprint_but_absence_changes_nothing() -> None:
    # Every baseline on disk was written without a source, so the digest for one
    # must not move; two servers in one config must not share one.
    f = _finding()
    assert fingerprint("search", f) == fingerprint("search", f, source=None)
    assert fingerprint("search", f, source="a") != fingerprint("search", f)
    assert fingerprint("search", f, source="a") != fingerprint("search", f, source="b")


def test_an_approval_for_one_server_does_not_cover_its_namesake(tmp_path: Path) -> None:
    from rune.baseline import apply_baseline

    a = ToolResult(name="search", findings=[_finding()], source="alpha")
    b = ToolResult(name="search", findings=[_finding()], source="beta")
    accepted = {e["fingerprint"] for e in build_baseline([a])["findings"]}
    assert apply_baseline([a, b], accepted) == 1
    assert a.findings == []
    assert len(b.findings) == 1


def test_a_config_baseline_records_and_names_its_source() -> None:
    document = build_baseline([ToolResult("search", [_finding()], source="alpha")])
    assert document["findings"][0]["source"] == "alpha"
    entry = BaselineEntry(fingerprint="f" * 8, kind="tool", target="search", source="alpha")
    assert "alpha" in render_stale_notice([entry])


def test_a_single_server_baseline_keeps_its_exact_keys() -> None:
    entry = build_baseline([ToolResult("search", [_finding()])])["findings"][0]
    assert "source" not in entry
    assert set(entry) == {"kind", "target", "rule", "path", "fingerprint", "excerpt"}


def test_sarif_separates_two_servers_with_the_same_tool() -> None:
    log = to_sarif(
        [
            ToolResult("search", [_finding()], source="alpha"),
            ToolResult("search", [_finding()], source="beta"),
        ]
    )
    results = log["runs"][0]["results"]
    assert {r["properties"]["source"] for r in results} == {"alpha", "beta"}
    assert results[0]["partialFingerprints"] != results[1]["partialFingerprints"]
    assert results[0]["message"]["text"].startswith("alpha / tool search:")


def test_sarif_for_one_server_is_untouched() -> None:
    result = to_sarif([ToolResult("search", [_finding()])])["runs"][0]["results"][0]
    assert "source" not in result["properties"]
    assert result["message"]["text"].startswith("tool search:")


# --- rendering ---------------------------------------------------------------


def _sources() -> list[SourceStatus]:
    return [
        SourceStatus("alpha", "stdio", "scanned"),
        SourceStatus("empty", "http", "scanned"),
        SourceStatus("gone", "stdio", "failed", "server would not start"),
        SourceStatus("old", "stdio", "disabled"),
    ]


def test_every_requested_server_gets_a_section() -> None:
    text = render_config_text(
        [ToolResult("search", [_finding()], source="alpha")], _sources(), "mcp.json"
    )
    for name in ("alpha", "empty", "gone", "old"):
        assert f"=== {name} (" in text
    assert "no tools, prompts, resources or server metadata listed" in text
    assert "not scanned: server would not start" in text
    assert "not scanned: disabled in the config" in text


def test_the_roll_call_and_the_findings_summary_are_separate_lines() -> None:
    # The per-kind clause already counts "server" entities. Folding the config's
    # own count into the same sentence reads as a verdict on those entities.
    text = render_config_text(
        [ToolResult("notes", [], kind="server", source="alpha")], _sources(), "mcp.json"
    )
    roll, summary = text.splitlines()[-2:]
    assert roll == "2 of 4 server(s) in mcp.json scanned, 1 failed, 1 disabled."
    assert summary == "1 server(s) scanned, 0 flagged, 0 finding(s)."


def test_a_clean_roll_call_names_no_categories() -> None:
    text = render_config_text([], [SourceStatus("a", "stdio", "scanned")], "mcp.json")
    assert text.splitlines()[-2] == "1 of 1 server(s) in mcp.json scanned."


def test_a_config_name_cannot_forge_a_line_of_the_report() -> None:
    # The same rule the entity names follow: a name out of a file is data, and
    # the report is rune's own prose.
    forged = "ok\n=== admin (stdio) ===\ntool evil  risk 0/100  [CLEAN]"
    sources = [SourceStatus(forged, "stdio", "failed", "nope\nrune: all clear")]
    text = render_config_text([], sources, "mcp.json")
    notice = render_source_notice(sources)
    for rendered in (text, notice):
        assert "\\n" in rendered
        assert "\n=== admin" not in rendered
        assert "\nrune: all clear" not in rendered


def test_the_notice_names_every_server_that_was_not_scanned() -> None:
    notice = render_source_notice(_sources())
    assert notice.startswith("rune: 2 of 4 server(s) were not scanned:")
    assert "gone: server would not start" in notice
    assert "old: disabled in the config" in notice
    assert "alpha" not in notice


def test_json_carries_the_roll_call_and_the_source_of_each_entity() -> None:
    payload = to_json(
        [ToolResult("search", [_finding()], source="alpha")], sources=_sources()
    )
    assert payload["tools"][0]["source"] == "alpha"
    assert [s["status"] for s in payload["sources"]] == [
        "scanned",
        "scanned",
        "failed",
        "disabled",
    ]
    assert payload["sources"][2]["error"] == "server would not start"
    assert payload["summary"]["sources"] == 4
    assert payload["summary"]["sourcesScanned"] == 2


def test_json_for_one_server_keeps_its_shape() -> None:
    payload = to_json([ToolResult("search", [_finding()])])
    assert payload["sources"] == []
    assert "source" not in payload["tools"][0]


# --- redaction ---------------------------------------------------------------


def test_config_values_are_taken_back_out_of_a_message() -> None:
    message = "spawn failed with env {'TOKEN': 'sk-live-abcdefghij'}"
    assert _redact(message, ["sk-live-abcdefghij"]) == (
        "spawn failed with env {'TOKEN': '<redacted>'}"
    )


def test_redaction_prefers_the_longest_value() -> None:
    # A short value inside a longer one must not leave the longer one half-blanked.
    assert _redact("aaaaaaaaaabbbb", ["aaaaaaaaaabbbb", "aaaaaaaaaa"]) == "<redacted>"


def test_short_values_are_left_alone() -> None:
    # Blanking "2" would shred an unrelated message and protect nothing.
    assert _redact("[Errno 2] no such file", ["2", "true"]) == "[Errno 2] no such file"


# --- CLI wiring --------------------------------------------------------------


def test_config_is_one_source_among_the_others(tmp_path: Path) -> None:
    config = _write(tmp_path, {"mcpServers": {"a": {"command": "x"}}})
    manifest = _write(tmp_path, [{"name": "add"}], name="tools.json")
    code, _, err = _run([manifest, "--config", config])
    assert code == 2
    assert "exactly one" in err


def test_server_without_config_is_refused(tmp_path: Path) -> None:
    manifest = _write(tmp_path, [{"name": "add"}], name="tools.json")
    code, _, err = _run([manifest, "--server", "a"])
    assert code == 2
    assert "--server only applies to --config" in err


def test_header_with_config_is_refused(tmp_path: Path) -> None:
    # A config carries each server's own headers, so one on the command line has
    # no server to belong to, and applying it to all of them would send one
    # server's credential to another.
    config = _write(tmp_path, {"mcpServers": {"a": {"url": "https://x.test/mcp"}}})
    code, _, err = _run(["--config", config, "--header", "A: b"])
    assert code == 2
    assert "--header only applies" in err


def test_missing_config_file_is_named(tmp_path: Path) -> None:
    code, _, err = _run(["--config", str(tmp_path / "nope.json")])
    assert code == 2
    assert "no such config" in err


def test_unreadable_config_exits_two(tmp_path: Path) -> None:
    config = _write(tmp_path, {"tools": []})
    code, _, err = _run(["--config", config])
    assert code == 2
    assert "cannot read config" in err


def test_an_empty_config_is_not_a_clean_scan(tmp_path: Path) -> None:
    config = _write(tmp_path, {"mcpServers": {}})
    code, out, err = _run(["--config", config])
    assert code == 2
    assert "declares no MCP servers" in err
    assert out == ""


def test_unknown_server_name_exits_two(tmp_path: Path) -> None:
    config = _write(tmp_path, {"mcpServers": {"a": {"command": "x"}}})
    code, _, err = _run(["--config", config, "--server", "nope"])
    assert code == 2
    assert "no server named 'nope'" in err


@pytest.mark.parametrize("flag", ["--baseline", "--pin", "--write-baseline", "--write-pin"])
def test_a_baseline_or_pin_needs_one_server(tmp_path: Path, flag: str) -> None:
    # Both files are statements about one server's metadata, keyed on the entity
    # names inside it. Across several there is nothing for either to describe.
    config = _write(
        tmp_path, {"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}}}
    )
    code, _, err = _run(["--config", config, flag, str(tmp_path / "f.json")])
    assert code == 2
    assert f"{flag} covers one server" in err
    assert "--server NAME" in err


@pytest.mark.parametrize("flag", ["--pin", "--write-pin"])
def test_a_pin_is_refused_when_the_one_server_never_answered(
    tmp_path: Path, flag: str
) -> None:
    # A pin written from a scan that read nothing records an absence as a fact,
    # and one judged against it reports every pinned entity as removed.
    config = _write(tmp_path, {"mcpServers": {"a": {"command": "definitely-not-real-xyz"}}})
    target = tmp_path / "f.json"
    code, _, err = _run(["--config", config, flag, str(target)])
    assert code == 2
    assert "needs metadata from the server" in err
    assert not target.exists()


def test_a_disabled_only_config_scans_nothing_and_stays_clean(tmp_path: Path) -> None:
    # Disabled is the user's own choice and the server is not wired into an
    # agent either, so not scanning it is the correct scan, not a failure.
    config = _write(tmp_path, {"mcpServers": {"old": {"command": "x", "disabled": True}}})
    code, out, err = _run(["--config", config])
    assert code == 0
    assert "not scanned: disabled in the config" in out
    assert "old: disabled in the config" in err


def test_an_unreachable_server_exits_two_and_is_named(tmp_path: Path) -> None:
    config = _write(
        tmp_path,
        {
            "mcpServers": {
                "bad": {"command": "definitely-not-real-xyz"},
                "worse": {"nothing": "here"},
            }
        },
    )
    code, out, err = _run(["--config", config])
    assert code == 2
    assert "0 of 2 server(s)" in out
    assert "rune: 2 of 2 server(s) were not scanned:" in err


def test_an_unreachable_server_is_reported_in_json(tmp_path: Path) -> None:
    config = _write(tmp_path, {"mcpServers": {"bad": {"command": "definitely-not-real-xyz"}}})
    code, out, _ = _run(["--config", config, "--json"])
    assert code == 2
    payload = json.loads(out)
    assert payload["sources"][0]["status"] == "failed"
    assert payload["sources"][0]["error"]
    assert payload["summary"]["sourcesScanned"] == 0


def test_a_url_rune_cannot_fetch_fails_that_entry_alone(tmp_path: Path) -> None:
    # Rejected before a socket is opened, and recorded against the one entry, so
    # the servers beside it are still audited.
    config = _write(
        tmp_path,
        {
            "mcpServers": {
                "wrong": {"url": "ftp://x.test/mcp"},
                "old": {"command": "x", "disabled": True},
            }
        },
    )
    code, out, _ = _run(["--config", config])
    assert code == 2
    assert "only speaks http and https" in out
    assert "1 failed, 1 disabled" in out


@pytest.mark.parametrize(
    "url",
    [
        "https://tok3nvalue@",  # userinfo, no host
        "tok3nvalue@x.test/mcp",  # no scheme, so no authority to strip
        "file:///mcp?k=tok3nvalue",  # scheme, no host, token in the query
    ],
)
def test_a_credential_in_a_url_is_never_echoed_back(tmp_path: Path, url: str) -> None:
    # A config is exactly where a URL with a token embedded in it lives, and an
    # error message is read off a terminal or out of a CI log.
    config = _write(tmp_path, {"mcpServers": {"api": {"type": "http", "url": url}}})
    code, out, err = _run(["--config", config, "--sarif"])
    assert code == 2
    assert "tok3nvalue" not in out
    assert "tok3nvalue" not in err


def test_sarif_anchors_a_config_scan_to_the_config_file(tmp_path: Path) -> None:
    config = _write(tmp_path, {"mcpServers": {"bad": {"command": "definitely-not-real-xyz"}}})
    code, out, _ = _run(["--config", config, "--sarif"])
    assert code == 2
    assert json.loads(out)["runs"][0]["results"] == []


def test_sarif_says_the_run_was_partial_when_a_server_failed() -> None:
    # An empty results array tells the platform to clear the alerts it raised
    # before. Right for a server that was scanned and came back clean, and the
    # wrong answer entirely for one that would not start.
    run = to_sarif([], sources=_sources())["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    messages = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    assert any("gone" in m and "server would not start" in m for m in messages)
    assert any("old" in m and "disabled in the config" in m for m in messages)
    assert not any("alpha" in m for m in messages)


def test_sarif_stays_successful_when_only_a_disabled_server_was_skipped() -> None:
    sources = [SourceStatus("a", "stdio", "scanned"), SourceStatus("old", "stdio", "disabled")]
    invocation = to_sarif([], sources=sources)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert len(invocation["toolExecutionNotifications"]) == 1


def test_sarif_for_one_server_carries_no_invocation() -> None:
    assert "invocations" not in to_sarif([ToolResult("a")])["runs"][0]
