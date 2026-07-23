"""Live end-to-end: scan a whole MCP client config of real FastMCP servers.

The parsing tests prove rune reads a config file. These prove it audits one:
every entry is started for real, handshaken with, and listed, in one command,
and the servers that will not start are named instead of quietly missing from
the report.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from rune.cli import main  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"

# A command that does not exist, so the entry fails at spawn for a real reason
# rather than a simulated one.
_MISSING = "rune-definitely-not-a-real-binary-xyz"


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out=out, err=err, inp=io.StringIO(""))
    return code, out.getvalue(), err.getvalue()


def _entry(fixture: str, **extra: object) -> dict[str, object]:
    return {"command": sys.executable, "args": [str(_FIXTURES / fixture)], **extra}


def _config(tmp_path: Path, servers: dict[str, object], name: str = "mcp.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return str(path)


def test_one_command_scans_every_server_in_the_config(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {
            "weather": _entry("clean_server.py"),
            "notes": _entry("poisoned_server.py"),
            "docs": _entry("full_server.py"),
        },
    )
    code, out, _ = _run(["--config", config])

    assert code == 1
    for name in ("weather", "notes", "docs"):
        assert f"=== {name} (stdio) ===" in out
    # Each finding sits under the server it came from, not in one flat pile.
    weather, notes = out.split("=== notes (stdio) ===")[0], out.split("=== notes (stdio) ===")[1]
    assert "data-exfiltration" not in weather
    assert "data-exfiltration" in notes
    assert "3 of 3 server(s) in " in out


def test_a_clean_config_exits_zero(tmp_path: Path) -> None:
    config = _config(tmp_path, {"weather": _entry("clean_server.py")})
    code, out, _ = _run(["--config", config])
    assert code == 0
    assert "1 of 1 server(s) in " in out
    assert "0 flagged" in out


def test_a_server_that_will_not_start_does_not_cancel_the_audit(tmp_path: Path) -> None:
    # The reason this matters: one broken entry nobody has fixed must not keep
    # every other server in the config from ever being looked at.
    config = _config(
        tmp_path, {"broken": {"command": _MISSING}, "notes": _entry("poisoned_server.py")}
    )
    code, out, err = _run(["--config", config])

    assert code == 2
    assert "data-exfiltration" in out
    assert "1 of 2 server(s) in " in out
    assert "1 failed" in out
    assert "broken: " in err


def test_server_narrows_the_scan_to_one_entry(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {"weather": _entry("clean_server.py"), "notes": _entry("poisoned_server.py")},
    )
    code, out, _ = _run(["--config", config, "--server", "weather"])
    assert code == 0
    assert "=== notes" not in out
    assert "1 of 1 server(s) in " in out


def test_a_server_shadowing_another_server_s_tool_name_is_caught(tmp_path: Path) -> None:
    # The whole point of scanning a config rather than an entry out of it, proved
    # over real handshakes: shadow_server.py trips no rule read on its own, and
    # is only a problem beside the server whose tool name it claims. Scanned
    # alone it is clean, which is the control here.
    both = _config(
        tmp_path,
        {"weather": _entry("clean_server.py"), "helper": _entry("shadow_server.py")},
        name="both.json",
    )
    code, out, _ = _run(["--config", both])
    assert code == 1
    assert out.count("name-collision") == 2
    assert "server 'helper' also exposes a tool with this name" in out
    assert "server 'weather' also exposes a tool with this name" in out

    # Control: the same server on its own has nothing to collide with, and the
    # honest server beside a poisoned one that shares no name is not a collision.
    assert _run(["--config", both, "--server", "helper"])[0] == 0
    other = _config(
        tmp_path,
        {"weather": _entry("clean_server.py"), "notes": _entry("poisoned_server.py")},
        name="other.json",
    )
    _, out, _ = _run(["--config", other])
    assert "name-collision" not in out


def test_json_names_the_server_each_finding_came_from(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        {"weather": _entry("clean_server.py"), "notes": _entry("poisoned_server.py")},
    )
    code, out, _ = _run(["--config", config, "--json"])
    assert code == 1
    payload = json.loads(out)
    assert {s["name"]: s["status"] for s in payload["sources"]} == {
        "weather": "scanned",
        "notes": "scanned",
    }
    flagged = {t["source"] for t in payload["tools"] if t["findings"]}
    assert flagged == {"notes"}


def test_env_and_cwd_from_the_config_reach_the_server(tmp_path: Path) -> None:
    # A config entry's env and cwd are what a server needs to start at all, so
    # scanning a config means honouring the whole entry, not just its command
    # line. env_server.py builds its tool description out of the environment
    # variable and working directory it was actually given, and --pin digests
    # every string it listed, so a pin taken with one launch context and checked
    # against another is drift if and only if that context reached the process.
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    pin = tmp_path / "context.pin.json"

    def config(marker: str, cwd: Path, name: str) -> str:
        entry = _entry("env_server.py", env={"RUNE_MARKER": marker}, cwd=str(cwd))
        return _config(tmp_path, {"context": entry}, name=name)

    base = config("carried", first, "base.json")
    assert _run(["--config", base, "--write-pin", str(pin)])[0] == 0
    # Control: the same launch context twice is not drift, so a difference below
    # can only have come from the field that changed.
    assert _run(["--config", base, "--pin", str(pin)])[0] == 0

    changed_env = config("different", first, "env.json")
    code, _, err = _run(["--config", changed_env, "--pin", str(pin)])
    assert code == 1
    assert "no longer match the pin" in err

    changed_cwd = config("carried", second, "cwd.json")
    assert _run(["--config", changed_cwd, "--pin", str(pin)])[0] == 1


def test_a_placeholder_in_the_config_reaches_the_server_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A committed config does not hold the token, it holds ${GITHUB_TOKEN}, and
    # a VS Code entry points at ${workspaceFolder}. The proof that rune resolves
    # them is not that the file parses, it is that the process starts with the
    # values in it: env_server.py builds its tool description out of the
    # environment variable and working directory it was actually given, so a pin
    # taken from literal values matches a scan driven by placeholders only if
    # both resolved to exactly those values.
    pin = tmp_path / "context.pin.json"
    literal = _config(
        tmp_path,
        {"context": _entry("env_server.py", env={"RUNE_MARKER": "carried"}, cwd=str(tmp_path))},
        name="literal.json",
    )
    assert _run(["--config", literal, "--write-pin", str(pin)])[0] == 0

    placeholders = _config(
        tmp_path,
        {
            "context": _entry(
                "env_server.py",
                env={"RUNE_MARKER": "${RUNE_E2E_MARKER}"},
                cwd="${workspaceFolder}",
            )
        },
        name="placeholders.json",
    )
    monkeypatch.setenv("RUNE_E2E_MARKER", "carried")
    code, out, _ = _run(["--config", placeholders, "--pin", str(pin)])
    assert code == 0
    assert "1 of 1 server(s) in " in out

    # Control: the pin is sensitive to that marker, so the run above passing was
    # the resolved value arriving and not the pin ignoring it.
    monkeypatch.setenv("RUNE_E2E_MARKER", "different")
    code, _, err = _run(["--config", placeholders, "--pin", str(pin)])
    assert code == 1
    assert "no longer match the pin" in err


def test_an_unresolvable_placeholder_costs_one_entry_not_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The variable nobody exported is one entry's problem, named on stderr, and
    # the servers beside it are audited as usual.
    monkeypatch.delenv("RUNE_E2E_MISSING", raising=False)
    config = _config(
        tmp_path,
        {
            "notes": _entry("poisoned_server.py", env={"TOKEN": "${RUNE_E2E_MISSING}"}),
            "weather": _entry("clean_server.py"),
        },
    )
    code, out, err = _run(["--config", config])

    assert code == 2
    assert "=== notes (unreadable) ===" in out
    assert "${RUNE_E2E_MISSING}" in out
    assert "not set in this environment" in err
    assert "tool get_weather" in out
    assert "1 of 2 server(s) in " in out


def test_a_pin_gates_one_server_picked_out_of_a_config(tmp_path: Path) -> None:
    # The rug pull, gated straight from the config the client already has: pin
    # the server as reviewed, then catch it serving different words later.
    pin = tmp_path / "notes.pin.json"
    config = _config(
        tmp_path,
        {
            "weather": _entry("clean_server.py"),
            "notes": {
                "command": sys.executable,
                "args": [str(_FIXTURES / "rug_pull_server.py")],
            },
        },
    )
    code, _, _ = _run(["--config", config, "--server", "notes", "--write-pin", str(pin)])
    assert code == 0
    assert pin.exists()

    code, _, _ = _run(["--config", config, "--server", "notes", "--pin", str(pin)])
    assert code == 0

    pulled = _config(
        tmp_path,
        {
            "notes": {
                "command": sys.executable,
                "args": [str(_FIXTURES / "rug_pull_server.py"), "--pulled"],
            }
        },
    )
    code, _, err = _run(["--config", pulled, "--server", "notes", "--pin", str(pin)])
    assert code == 1
    assert "no longer match the pin" in err


def test_one_pin_gates_every_server_in_the_config(tmp_path: Path) -> None:
    # The rug pull at the scale people actually run: several servers wired into
    # one client, one of them serving different words a month later, caught by
    # one file and one command over real handshakes.
    pin = tmp_path / "mcp.pin.json"
    # weather and forecast run the same binary, so the two entries list byte for
    # byte the same tools. They are still two servers, and the pin has to hold
    # them as two, not fold them into one.
    honest = _config(
        tmp_path,
        {
            "weather": _entry("clean_server.py"),
            "forecast": _entry("clean_server.py"),
            "notes": _entry("rug_pull_server.py"),
        },
        name="honest.json",
    )
    code, _, err = _run(["--config", honest, "--write-pin", str(pin)])
    assert code == 0
    assert "wrote pin for " in err
    recorded = json.loads(pin.read_text(encoding="utf-8"))["entities"]
    assert {e["source"] for e in recorded} == {"weather", "forecast", "notes"}

    # Control: the same three servers again is not drift, so the difference below
    # can only have come from the description that changed. The run exits 1 all
    # the same, because two entries running one binary means two definitions of
    # every tool name in it, which is a name-collision finding on each; asserting
    # on the drift line rather than the code is what keeps the two apart.
    code, out, err = _run(["--config", honest, "--pin", str(pin)])
    assert code == 1
    assert "no longer match the pin" not in err
    assert "name-collision" in out
    assert "'forecast' also exposes a tool with this name" in out

    pulled = _config(
        tmp_path,
        {
            "weather": _entry("clean_server.py"),
            "forecast": _entry("clean_server.py"),
            "notes": _entry(
                "rug_pull_server.py",
                args=[str(_FIXTURES / "rug_pull_server.py"), "--pulled"],
            ),
        },
        name="pulled.json",
    )
    code, _, err = _run(["--config", pulled, "--pin", str(pin)])
    assert code == 1
    # The swapped description fires no rule, so the pin is the only thing that
    # can see it, and it names which of the three servers moved.
    assert "rune: 1 pinned entity(s) no longer match the pin:" in err
    assert "notes: tool sync_notes  changed: description" in err


def test_a_baseline_written_from_a_config_suppresses_that_server(tmp_path: Path) -> None:
    baseline = tmp_path / "notes.baseline.json"
    config = _config(tmp_path, {"notes": _entry("poisoned_server.py")})

    code, _, _ = _run(["--config", config, "--server", "notes", "--write-baseline", str(baseline)])
    assert code == 0

    code, out, _ = _run(["--config", config, "--server", "notes", "--baseline", str(baseline)])
    assert code == 0
    assert "0 flagged" in out
    assert json.loads(baseline.read_text(encoding="utf-8"))["findings"][0]["source"] == "notes"


def test_a_server_slower_than_its_budget_is_reported_and_can_be_given_longer(
    tmp_path: Path,
) -> None:
    # The execution-based proof that --timeout is the number rune actually
    # waits: one real server, stalled for two seconds, scanned twice. The first
    # run cannot reach the handshake inside its budget and says so; the second
    # gives it the time it needs and completes. Before the flag there was only
    # the first outcome, with nothing a user could type to reach the second.
    config = _config(
        tmp_path, {"slow": _entry("slow_server.py", env={"RUNE_TEST_DELAY": "2"})}
    )

    code, out, _ = _run(["--config", config, "--timeout", "0.5"])
    assert code == 2
    assert "not scanned: server did not respond within 0.5s (see --timeout)" in out

    code, out, _ = _run(["--config", config, "--timeout", "60"])
    assert code == 0
    assert "tool ping" in out
    assert "1 of 1 server(s) in " in out
