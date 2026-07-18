# Contributing to rune

Thanks for helping. rune is small on purpose, so the bar for changes is that they
stay precise and stay tested.

## Setup

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a PR

```
pytest          # all tests, including the live FastMCP end-to-end scan
ruff check .
bandit -r .
```

All three must be clean.

## Adding or changing a detection rule

The whole value of rune is that it does not cry wolf. If you touch a rule:

- Add **true-positive** tests (a real attack it must catch) and **true-negative**
  tests (honest text it must not flag). A rule without both is not done.
- For anything in the `data-exfiltration` family, add benign cases in
  `tests/test_precision.py`. The benign set must contain strings that satisfy
  *all* preconditions of the rule, so "zero false positives" actually exercises
  it. `test_benign_set_actually_exercises_the_rule` enforces this.
- Keep regexes bounded (no unbounded `+`/`*` before a required token) so a
  hostile description cannot cause catastrophic backtracking.
  `test_no_catastrophic_backtracking` guards this.

## Style

- The `rune/` package stays dependency-free and importable without the MCP SDK;
  live scanning imports `mcp` lazily.
- No `subprocess` and no `assert` in the package, so `bandit -r .` stays clean.
- No em dashes.
