# AGENTS.md

Notes for automated agents working in this repo.

## What rune is

A scanner that reads MCP metadata (name, description, JSON schema) for tools,
prompts, and resources, and flags hidden instructions: data exfiltration,
injection, concealment, invisible characters, and fake instruction markup. It
lists only: it never calls a tool, renders a prompt, or reads a resource body.

## Layout

- `rune/rules.py` - the detection rules. The heart of the tool. `scan_text`
  runs every rule over one string and returns `(rule, severity, offset, length,
  message)` hits.
- `rune/scan.py` - walks an entity dict (tool, prompt, or resource), tags each
  hit with its JSON path, and rolls findings into a 0-100 score and a band.
  `scan_targets` groups the kinds; each result carries its `kind`.
- `rune/pin.py` - digests every string `scan.walk_strings` yields and diffs a
  scan against a recorded pin. Detection by change, not by pattern, so it is the
  one part of rune that is not a rule and emits no finding.
- `rune/report.py` - text and JSON rendering.
- `rune/client.py` - live stdio scan via the MCP SDK (lazy import).
- `rune/cli.py` - `main(argv, out, err)`, driven in-process by the tests.

## Invariants (do not break)

- `rune/` imports no third-party package at module load. `mcp` is imported
  lazily inside `client.py` only.
- No `subprocess` and no `assert` in the package; tests drive the CLI in-process
  via `StringIO`, so `bandit -r .` reports no issues.
- Detection regexes are bounded to avoid catastrophic backtracking.
- Server text reaches a line of rune's prose only through `render_visible`:
  entity names and JSON paths as much as excerpts. Data surfaces (`--json`,
  SARIF's structured fields, the baseline and pin files) keep the exact text
  instead, so a consumer sees what the server sent. See
  `tests/test_report_safety.py`.
- The `data-exfiltration` rule keys on the secret being the grammatical object
  of an outbound verb, never on word order. See `tests/test_precision.py`.

## Checks

```
pytest && ruff check . && bandit -r .
```
