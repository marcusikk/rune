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
    # can only have come from the description that changed.
    assert _run(["--config", honest, "--pin", str(pin)])[0] == 0

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
