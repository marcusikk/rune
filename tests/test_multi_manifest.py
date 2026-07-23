"""Several captured manifests scanned together in one run.

rune could always scan one saved listing. But the shadowing a client cannot see,
a server claiming the name of a tool the user already trusts, spans two servers,
and offline that means two captured `tools/list` replies in two files. `--config`
finds it across a live setup; this is the same check for the captured listings a
CI job commits instead of opening every server over the network.

The source a finding carries is the file it came from, so the report, the JSON,
SARIF and a pin all say which listing each result describes. A single manifest is
untouched: it carries no source, exactly as every scan and every pin written
before this did.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from rune.cli import main


def _run(argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    inp = io.StringIO(stdin if stdin is not None else "")
    code = main(argv, out=out, err=err, inp=inp)
    return code, out.getvalue(), err.getvalue()


def _write(tmp_path: Path, name: str, data: object) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _tool(name: str, description: str = "Does a thing.") -> dict[str, object]:
    return {"name": name, "description": description}


def test_shared_tool_name_across_two_manifests_collides(tmp_path: Path) -> None:
    trusted = _write(tmp_path, "trusted.json", {"tools": [_tool("deploy")]})
    added = _write(tmp_path, "added.json", {"tools": [_tool("deploy"), _tool("weather")]})

    code, out, _ = _run(["--manifest", trusted, "--manifest", added])

    assert code == 1
    assert out.count("name-collision") == 2
    # Each side names the other file as the server also answering to the name, so
    # a reader can see which listing shadows which.
    assert added in out
    assert trusted in out
    # weather is unique, so it does not collide.
    assert "weather" in out and out.count("name-collision") == 2


def test_source_leads_each_entity_in_the_flat_report(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("beta")]})

    code, out, _ = _run(["--manifest", a, "--manifest", b])

    assert code == 0
    assert f"{a} / tool alpha" in out
    assert f"{b} / tool beta" in out


def test_distinct_names_do_not_collide(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("beta")]})

    code, out, _ = _run(["--manifest", a, "--manifest", b])

    assert code == 0
    assert "name-collision" not in out
    assert "0 flagged" in out


def test_tool_and_prompt_sharing_a_name_do_not_collide(tmp_path: Path) -> None:
    # A tool is routed by name and a prompt is routed by name, but not by the same
    # name: a client calls one and fetches the other, so a tool "x" in one file
    # and a prompt "x" in another are not two definitions of one call target.
    a = _write(tmp_path, "a.json", {"tools": [_tool("notes")]})
    b = _write(tmp_path, "b.json", {"prompts": [{"name": "notes"}]})

    code, out, _ = _run(["--manifest", a, "--manifest", b])

    assert code == 0
    assert "name-collision" not in out


def test_positional_and_flag_manifests_combine(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("shared")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("shared")]})

    code, out, _ = _run([a, "--manifest", b])

    assert code == 1
    assert out.count("name-collision") == 2


def test_json_carries_the_source_per_result(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("shared")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("shared")]})

    code, out, _ = _run(["--manifest", a, "--manifest", b, "--json"])

    assert code == 1
    doc = json.loads(out)
    sources = sorted(t["source"] for t in doc["tools"])
    assert sources == sorted([a, b])
    assert all(f["rule"] == "name-collision" for t in doc["tools"] for f in t["findings"])


def test_sarif_anchors_each_result_to_its_source(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("shared")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("shared")]})

    code, out, _ = _run(["--manifest", a, "--manifest", b, "--sarif"])

    assert code == 1
    doc = json.loads(out)
    results = doc["runs"][0]["results"]
    assert sorted({r["properties"]["source"] for r in results}) == sorted([a, b])
    # No single file to point at, so no manifest-wide physicalLocation is claimed;
    # the source property carries the provenance instead.
    assert all(
        "physicalLocation" not in loc for r in results for loc in r["locations"]
    )


def test_single_manifest_carries_no_source(tmp_path: Path) -> None:
    only = _write(tmp_path, "only.json", {"tools": [_tool("deploy")]})

    code, out, _ = _run(["--manifest", only, "--json"])

    assert code == 0
    doc = json.loads(out)
    # A one-file scan is unchanged: no source, so every pin and baseline written
    # before this keeps comparing without one.
    assert all("source" not in t for t in doc["tools"])
    text_code, text_out, _ = _run(["--manifest", only])
    assert " / tool deploy" not in text_out


def test_pin_matches_when_every_manifest_is_unchanged(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("beta")]})
    pin = str(tmp_path / "pin.json")

    code, _, _ = _run(["--manifest", a, "--manifest", b, "--write-pin", pin])
    assert code == 0
    code, _, _ = _run(["--manifest", a, "--manifest", b, "--pin", pin])
    assert code == 0


def test_pin_reports_drift_under_the_source_that_changed(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    b = _write(tmp_path, "b.json", {"tools": [_tool("beta", "Second tool.")]})
    pin = str(tmp_path / "pin.json")
    _run(["--manifest", a, "--manifest", b, "--write-pin", pin])

    _write(tmp_path, "b.json", {"tools": [_tool("beta", "Second tool, reworded.")]})
    code, _, err = _run(["--manifest", a, "--manifest", b, "--pin", pin])

    assert code == 1
    assert b in err
    assert a not in err.split("no longer match")[-1]


def test_stdin_cannot_join_several_manifests(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})

    code, _, err = _run(["--manifest", a, "--manifest", "-"], stdin="{}")

    assert code == 2
    assert "stdin" in err


def test_the_same_manifest_twice_is_refused(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})

    code, _, err = _run(["--manifest", a, "--manifest", a])

    assert code == 2
    assert "more than once" in err


def test_one_missing_file_names_that_file(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    missing = str(tmp_path / "gone.json")

    code, _, err = _run(["--manifest", a, "--manifest", missing])

    assert code == 2
    assert missing in err
    assert a not in err


def test_one_malformed_file_names_that_file(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.json", {"tools": [_tool("alpha")]})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    code, _, err = _run(["--manifest", a, "--manifest", str(bad)])

    assert code == 2
    assert str(bad) in err
