# AGENTS.md

Notes for automated agents working in this repo.

## What rune is

A scanner that reads MCP metadata (name, description, JSON schema) for tools,
prompts, and resources, and flags hidden instructions: data exfiltration,
injection, concealment, invisible characters, fake instruction markup, and one
tool name claimed by two servers. It
lists only: it never calls a tool, renders a prompt, or reads a resource body.

## Layout

- `rune/rules.py` - the detection rules. The heart of the tool. `scan_text`
  runs every rule over one string and returns `(rule, severity, offset, length,
  message)` hits.
- `rune/scan.py` - walks an entity dict (tool, prompt, or resource), tags each
  hit with its JSON path, and rolls findings into a 0-100 score and a band.
  `scan_targets` groups the kinds; each result carries its `kind`.
  `flag_name_collisions` is the one finding that reads no text: it runs once over
  the whole scan, after every server has been listed, and flags entities that
  share the name a client routes calls by. Its rule id lives in
  `rules.STRUCTURAL_RULE_IDS`, so a consumer keying a table off rune's rules
  (the SARIF driver) covers `ALL_RULE_IDS`, not just `RULE_IDS`.
- `rune/pin.py` - digests every string `scan.walk_strings` yields and diffs a
  scan against a recorded pin. Detection by change, not by pattern, so it is the
  one part of rune that is not a rule and emits no finding.
- `rune/config.py` - parses an MCP client config (`mcpServers`/`servers`) into
  `ServerSpec`s. Never connects; a bad entry records its own `error` instead of
  raising, so one broken entry cannot cancel the audit of the rest. The file is
  read as JSONC: `strip_jsonc` blanks comments and trailing commas in place, so
  every offset survives and json's line and column still point into the file on
  disk. Config files only; a manifest stays strict JSON. `_Variables.expand`
  then fills in the `${...}` placeholders the client would fill in, one pass so
  a resolved value is never resolved again.
- `rune/report.py` - text, JSON and SARIF rendering.
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
- A credential rune was handed is never printed: header values, config `env`
  values, and a URL's userinfo and query string are kept out of every error
  message and every artifact. See `tests/test_config.py`.
- A finding's identity is `(source, kind, entity name, rule, JSON path, matched
  text)`. `source` is set only on a `--config` scan and left out of the digest
  otherwise, so every baseline written before it keeps working.
- A pinned entity's identity is `(source, kind, entity name)` plus the JSON path
  of each string. `source` is written only on a `--config` scan, and a pin that
  names no server is adopted by the single server a run scanned, so every pin
  written before it keeps working and `_FORMAT_VERSION` stays 1.
- A config placeholder rune cannot resolve is that entry's own error, never an
  empty string: a guess would start a server the client does not start and
  report the scan of it as the audit of the real one. See `tests/test_config.py`.
- Every live scan is bounded. `--timeout` is one server's own budget, never a
  clock shared across a `--config` run, and a value that is zero, negative or
  non-finite is refused at parse time: asyncio builds a deadline out of the
  number, and `inf`/`nan` never arrive, so accepting either would turn a scanner
  told to bound itself into one that hangs. See `tests/test_timeout.py`.
- `--pin` and `--baseline` compare only the servers a run actually scanned. A
  server left out is named as unchecked, never reported as removed or stale:
  "rune did not look" is not "it is gone".

## Checks

```
pytest && ruff check . && bandit -r .
```
