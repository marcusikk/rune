# AGENTS.md

Notes for automated agents working in this repo.

## What rune is

A scanner that reads MCP tool metadata (name, description, JSON schema) and
flags hidden instructions: data exfiltration, injection, concealment, invisible
characters, and fake instruction markup. It never calls a tool.

## Layout

- `rune/rules.py` - the detection rules. The heart of the tool. `scan_text`
  runs every rule over one string and returns `(rule, severity, offset, length,
  message)` hits.
- `rune/scan.py` - walks a tool dict, tags each hit with its JSON path, and
  rolls findings into a 0-100 score and a band.
- `rune/report.py` - text and JSON rendering.
- `rune/client.py` - live stdio scan via the MCP SDK (lazy import).
- `rune/cli.py` - `main(argv, out, err)`, driven in-process by the tests.

## Invariants (do not break)

- `rune/` imports no third-party package at module load. `mcp` is imported
  lazily inside `client.py` only.
- No `subprocess` and no `assert` in the package; tests drive the CLI in-process
  via `StringIO`, so `bandit -r .` reports no issues.
- Detection regexes are bounded to avoid catastrophic backtracking.
- The `data-exfiltration` rule keys on the secret being the grammatical object
  of an outbound verb, never on word order. See `tests/test_precision.py`.

## Checks

```
pytest && ruff check . && bandit -r .
```
