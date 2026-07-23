"""--timeout: the budget one server gets to answer, and what rune refuses.

The default suits a server that is already on disk. The one that is not, the
`npx -y ...` or `docker run` entry that fetches itself the first time anybody
scans it, needs longer, and before this flag existed there was no way to give it
any: the scan reported "server did not respond" and, under --config, took the
whole audit to exit 2 with it.

These run offline. The transport functions are replaced so the budget can be
watched arriving at each of them; the live proof that the number changes what
actually happens is in test_config_e2e.py.
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from rune.cli import _timeout_seconds, main
from rune.client import DEFAULT_TIMEOUT, _budget, _timed_out


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out=out, err=err, inp=io.StringIO(""))
    return code, out.getvalue(), err.getvalue()


def _manifest(tmp_path: Path) -> str:
    path = tmp_path / "tools.json"
    path.write_text(json.dumps([{"name": "add", "description": "Add two numbers."}]))
    return str(path)


def _config(tmp_path: Path, servers: dict[str, object]) -> str:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return str(path)


# --- the message -------------------------------------------------------------


@pytest.mark.parametrize(
    ("seconds", "rendered"),
    [(20.0, "20s"), (1.0, "1s"), (0.5, "0.5s"), (2.25, "2.25s"), (90.0, "90s")],
)
def test_a_budget_is_rendered_without_lying_about_its_size(
    seconds: float, rendered: str
) -> None:
    # A fractional budget used to print as "0s", which reads as a rune bug
    # rather than as the number the user typed.
    assert _budget(seconds) == rendered


def test_the_timeout_message_names_the_flag_that_raises_it() -> None:
    message = str(_timed_out(20.0))
    assert "did not respond within 20s" in message
    assert "--timeout" in message


# --- what the flag refuses ---------------------------------------------------


@pytest.mark.parametrize("value", ["0", "-1", "-0.5"])
def test_a_budget_that_expires_before_the_handshake_is_refused(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", value, "--stdio", "true"])
    assert exc.value.code == 2
    assert "is not a positive number of seconds" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["abc", "", "10s", "1,5"])
def test_a_budget_that_is_not_a_number_is_refused(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", value, "--stdio", "true"])
    assert exc.value.code == 2
    assert "is not a number of seconds" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["inf", "-inf", "nan", "-nan", "Infinity", "NaN"])
def test_no_spelling_of_a_deadline_that_never_arrives_gets_through(value: str) -> None:
    # Checked on the parser itself as well as through the CLI below, because
    # argparse reads "-inf" as an option name and never reaches this function,
    # which would leave the negative spellings untested at the CLI level.
    with pytest.raises(argparse.ArgumentTypeError):
        _timeout_seconds(value)


@pytest.mark.parametrize("value", ["inf", "nan", "Infinity", "NaN"])
def test_a_deadline_that_never_arrives_is_refused(
    value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # float() accepts all of these, and asyncio builds a deadline out of the
    # number it is handed. Neither inf nor nan ever compares as elapsed, so a
    # scanner told to bound itself would instead wait for good in CI. The
    # refusal says that rather than calling inf "not positive", which is false.
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", value, "--stdio", "true"])
    assert exc.value.code == 2
    assert "is not a length of time rune can wait" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["45", "0.5", "1e3", "  30  "])
def test_a_usable_budget_is_accepted(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []
    monkeypatch.setattr(
        "rune.client.fetch_metadata",
        lambda command, args, **kw: seen.append(kw["timeout"]) or _EMPTY,
    )
    code, _, _ = _run(["--timeout", value, "--stdio", "true"])
    assert code == 0
    assert seen == [float(value)]


def test_timeout_is_refused_where_there_is_no_server_to_wait_for(tmp_path: Path) -> None:
    # A manifest is a file on disk. Accepting a budget for reading one takes a
    # flag that changes nothing and reports success for it.
    code, _, err = _run([_manifest(tmp_path), "--timeout", "45"])
    assert code == 2
    assert "--timeout only applies to --stdio, --http, --sse or --config" in err


# --- where the budget arrives ------------------------------------------------

_EMPTY: dict[str, list[dict[str, object]]] = {
    "tool": [],
    "prompt": [],
    "resource": [],
    "server": [],
}


@pytest.mark.parametrize(
    ("argv", "target"),
    [
        (["--stdio", "true"], "rune.client.fetch_metadata"),
        (["--http", "https://example.test/mcp"], "rune.client.fetch_metadata_http"),
        (["--sse", "https://example.test/sse"], "rune.client.fetch_metadata_sse"),
    ],
)
def test_every_transport_is_given_the_budget_that_was_asked_for(
    argv: list[str], target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[float] = []
    monkeypatch.setattr(
        target, lambda *a, **kw: seen.append(kw["timeout"]) or _EMPTY
    )
    code, _, _ = _run(["--timeout", "45", *argv])
    assert code == 0
    assert seen == [45.0]


@pytest.mark.parametrize(
    ("argv", "target"),
    [
        (["--stdio", "true"], "rune.client.fetch_metadata"),
        (["--http", "https://example.test/mcp"], "rune.client.fetch_metadata_http"),
        (["--sse", "https://example.test/sse"], "rune.client.fetch_metadata_sse"),
    ],
)
def test_every_transport_keeps_the_default_when_no_budget_is_asked_for(
    argv: list[str], target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[float] = []
    monkeypatch.setattr(
        target, lambda *a, **kw: seen.append(kw["timeout"]) or _EMPTY
    )
    code, _, _ = _run(argv)
    assert code == 0
    assert seen == [DEFAULT_TIMEOUT]


def test_each_server_in_a_config_gets_the_whole_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Per server, not shared: a config is scanned one entry at a time, and a
    # single clock across the run would make an entry's result depend on how
    # many entries happened to sit above it in the file.
    seen: list[tuple[str, float]] = []

    def fetch(spec, err, timeout):  # noqa: ANN001 - stands in for _fetch_spec
        seen.append((spec.name, timeout))
        return _EMPTY

    monkeypatch.setattr("rune.cli._fetch_spec", fetch)
    config = _config(
        tmp_path,
        {"a": {"command": "x"}, "b": {"command": "y"}, "c": {"url": "https://c.test/mcp"}},
    )
    code, _, _ = _run(["--config", config, "--timeout", "45"])
    assert code == 0
    assert seen == [("a", 45.0), ("b", 45.0), ("c", 45.0)]


@pytest.mark.parametrize(
    ("entry", "target"),
    [
        ({"command": "x"}, "rune.client.fetch_metadata"),
        ({"url": "https://a.test/mcp"}, "rune.client.fetch_metadata_http"),
        ({"url": "https://a.test/sse"}, "rune.client.fetch_metadata_sse"),
    ],
)
def test_a_config_entry_carries_the_budget_over_its_own_transport(
    entry: dict[str, object],
    target: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _fetch_spec picks a transport per entry, so each branch has to hand the
    # budget on. The live proof for the stdio branch is in test_config_e2e.py;
    # the remote branches have no local server to stall, so they are watched
    # here instead of being left as the one path nothing covers.
    seen: list[float] = []
    monkeypatch.setattr(target, lambda *a, **kw: seen.append(kw["timeout"]) or _EMPTY)
    code, _, _ = _run(["--config", _config(tmp_path, {"a": entry}), "--timeout", "45"])
    assert code == 0
    assert seen == [45.0]


def test_a_config_run_keeps_the_default_when_no_budget_is_asked_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[float] = []

    def fetch(spec, err, timeout):  # noqa: ANN001 - stands in for _fetch_spec
        seen.append(timeout)
        return _EMPTY

    monkeypatch.setattr("rune.cli._fetch_spec", fetch)
    code, _, _ = _run(["--config", _config(tmp_path, {"a": {"command": "x"}})])
    assert code == 0
    assert seen == [DEFAULT_TIMEOUT]


def test_a_server_that_runs_out_of_budget_does_not_cancel_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A slow entry is reported under its own heading like any other failure, and
    # the servers beside it are still scanned.
    from rune.client import LiveScanError

    def fetch(spec, err, timeout):  # noqa: ANN001 - stands in for _fetch_spec
        if spec.name == "slow":
            raise LiveScanError(str(_timed_out(timeout)))
        return _EMPTY

    monkeypatch.setattr("rune.cli._fetch_spec", fetch)
    config = _config(tmp_path, {"slow": {"command": "x"}, "quick": {"command": "y"}})
    code, out, _ = _run(["--config", config, "--timeout", "0.5"])
    assert code == 2
    assert "not scanned: server did not respond within 0.5s (see --timeout)" in out
    assert "=== quick (stdio) ===" in out
    assert "1 of 2 server(s) in " in out
