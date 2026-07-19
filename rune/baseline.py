"""Suppress findings a human has already reviewed, so a CI gate stays useful.

rune is meant to sit in front of an agent as a gate: a non-zero exit blocks the
build. A pattern-based scanner will occasionally flag text a maintainer has read
and judged safe, and a gate that cannot record that judgement gets its threshold
lowered until it protects nothing. A baseline is the escape valve. You review the
current findings once, write them to a file, and future scans stop failing on
exactly those. Anything new still fails.

The identity of a finding is (kind, entity name, rule, JSON path, matched text).
The offset is deliberately excluded, so editing text elsewhere in a description
does not un-baseline an accepted finding. So is the rendered excerpt, which is a
context window around the match and moves whenever nearby text changes. The
matched text itself IS included, so changing the flagged text does re-open a
finding: an attacker cannot inherit a maintainer's approval by swapping the
payload under a fingerprint that was accepted for different words.

The kind (tool, prompt, resource or server) is folded in so a poisoned prompt
named like an accepted tool does not inherit the tool's approval. It is folded in
for every non-tool kind, never for tools, so every baseline written before rune
scanned prompts, resources and server metadata keeps suppressing its tool
findings byte for byte and does not need to be regenerated. That is why
_FORMAT_VERSION stays 1: no existing file is invalidated.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .models import Finding, ToolResult

# Bump when the fingerprint inputs change in a way that invalidates old files.
# Adding prompts and resources did NOT: a tool fingerprint is unchanged, so a
# file written under this version keeps working. See the module docstring.
_FORMAT_VERSION = 1


class BaselineError(ValueError):
    """Raised when a baseline file cannot be parsed."""


def fingerprint(name: str, finding: Finding, *, kind: str = "tool") -> str:
    """A stable id for one finding, independent of where it sits in the string.

    Built from the entity name, the rule, the JSON path, and the matched text.
    Offset and the surrounding excerpt are left out on purpose: a finding should
    keep its identity when unrelated edits shift it or change its context, and
    lose it only when the flagged text itself changes.

    ``kind`` is prepended for every non-tool kind so a prompt, resource or
    server finding lives in a separate namespace from a same-named tool. It is
    left out for tools, which keeps a tool fingerprint identical to the ones
    every existing baseline was written with.
    """
    parts = (name, finding.rule, finding.path, finding.match)
    if kind != "tool":
        parts = (kind, *parts)
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def build_baseline(results: list[ToolResult]) -> dict[str, Any]:
    """Serialize every current finding into a reviewable baseline document."""
    entries = [
        {
            "kind": r.kind,
            "target": r.name,
            "rule": f.rule,
            "path": f.path,
            "fingerprint": fingerprint(r.name, f, kind=r.kind),
            "excerpt": f.excerpt,
        }
        for r in results
        for f in r.findings
    ]
    # Sort so the file is stable across runs and diffs cleanly in version control.
    entries.sort(
        key=lambda e: (e["kind"], e["target"], e["rule"], e["path"], e["fingerprint"])
    )
    return {"version": _FORMAT_VERSION, "findings": entries}


def load_fingerprints(path: str) -> set[str]:
    """Read a baseline file and return the set of accepted fingerprints."""
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise BaselineError(f"not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise BaselineError("baseline must be a JSON object")
    version = data.get("version")
    if version != _FORMAT_VERSION:
        raise BaselineError(
            f"unsupported baseline version {version!r}, expected {_FORMAT_VERSION}"
        )
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise BaselineError('baseline "findings" must be a list')

    accepted: set[str] = set()
    for entry in findings:
        if not isinstance(entry, dict):
            raise BaselineError("each baseline entry must be an object")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or not fp:
            raise BaselineError("a baseline entry is missing its fingerprint")
        accepted.add(fp)
    return accepted


def apply_baseline(results: list[ToolResult], accepted: set[str]) -> int:
    """Drop accepted findings from results in place; return how many were dropped.

    A tool whose findings are all accepted keeps its place in the list but scores
    clean, which is the honest reading: there is nothing new to look at.
    """
    suppressed = 0
    for r in results:
        kept: list[Finding] = []
        for f in r.findings:
            if fingerprint(r.name, f, kind=r.kind) in accepted:
                suppressed += 1
            else:
                kept.append(f)
        r.findings = kept
    return suppressed
