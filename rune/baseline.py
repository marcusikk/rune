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

An entry that matches nothing in a scan is reported as stale rather than left
silent. A baseline entry is a standing approval that lives in the repo, and one
whose finding is gone is an approval nobody is reviewing any more: if that exact
text ever comes back, a server rolls back, a vendor restores a description, a
removed tool is re-added, rune suppresses it again without a human ever looking.
Reporting stale entries is what lets a maintainer prune them, and it makes a
baseline diff readable, since a live approval and a fossil look identical on disk.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .models import Finding, ToolResult

# Bump when the fingerprint inputs change in a way that invalidates old files.
# Adding prompts and resources did NOT: a tool fingerprint is unchanged, so a
# file written under this version keeps working. See the module docstring.
_FORMAT_VERSION = 1


class BaselineError(ValueError):
    """Raised when a baseline file cannot be parsed."""


def fingerprint(
    name: str, finding: Finding, *, kind: str = "tool", source: str | None = None
) -> str:
    """A stable id for one finding, independent of where it sits in the string.

    Built from the entity name, the rule, the JSON path, and the matched text.
    Offset and the surrounding excerpt are left out on purpose: a finding should
    keep its identity when unrelated edits shift it or change its context, and
    lose it only when the flagged text itself changes.

    ``kind`` is prepended for every non-tool kind so a prompt, resource or
    server finding lives in a separate namespace from a same-named tool. It is
    left out for tools, which keeps a tool fingerprint identical to the ones
    every existing baseline was written with.

    Encoded with surrogatepass for the reason ``pin.digest`` is: the name, path
    and matched text are the server's, and a manifest may legally carry an
    unpaired surrogate that a plain encode() refuses. That manifest scans and
    reports fine, so a strict encode here would leave --write-baseline and
    --sarif, which fingerprints every result, raising on input the rest of rune
    handles. surrogatepass changes no digest of text that already encoded, so
    every baseline on disk stays valid and _FORMAT_VERSION does not move.

    ``source`` is the config's name for the server the result came from, set only
    on a ``--config`` scan. It is folded in when present for the reason ``kind``
    is: two servers in one config can each expose a tool named ``search``, and an
    approval given to one of them must not silently cover the other. It is left
    out entirely when absent, which is every scan of a single server, so no
    fingerprint any existing baseline recorded moves and _FORMAT_VERSION stays 1.
    """
    parts = (name, finding.rule, finding.path, finding.match)
    if kind != "tool":
        parts = (kind, *parts)
    if source is not None:
        parts = (source, *parts)
    joined = "\x00".join(parts)
    return hashlib.sha256(joined.encode("utf-8", "surrogatepass")).hexdigest()


def _entry(r: ToolResult, f: Finding) -> dict[str, Any]:
    entry = {
        "kind": r.kind,
        "target": r.name,
        "rule": f.rule,
        "path": f.path,
        "fingerprint": fingerprint(r.name, f, kind=r.kind, source=r.source),
        "excerpt": f.excerpt,
    }
    # Written only on a --config scan, so a baseline from any other run keeps the
    # exact keys it has always had and re-writing one produces no diff.
    if r.source is not None:
        entry["source"] = r.source
    return entry


def build_baseline(results: list[ToolResult]) -> dict[str, Any]:
    """Serialize every current finding into a reviewable baseline document."""
    entries = [_entry(r, f) for r in results for f in r.findings]
    # Sort so the file is stable across runs and diffs cleanly in version control.
    entries.sort(
        key=lambda e: (
            e.get("source", ""),
            e["kind"],
            e["target"],
            e["rule"],
            e["path"],
            e["fingerprint"],
        )
    )
    return {"version": _FORMAT_VERSION, "findings": entries}


@dataclass(frozen=True)
class BaselineEntry:
    """One recorded approval, as read back off disk.

    Only ``fingerprint`` is load-bearing; it alone decides what gets suppressed.
    The rest is what the file wrote down about the finding at approval time, kept
    so a stale entry can be named in a way a human can act on. Those fields are
    optional on purpose: the loader has never required them, and tightening that
    now would reject baselines already committed by existing users.
    """

    fingerprint: str
    kind: str = ""
    target: str = ""
    rule: str = ""
    path: str = ""
    source: str = ""

    @property
    def label(self) -> str:
        """A human-readable name for this entry, degrading to its fingerprint.

        A file written by ``--write-baseline`` always carries the descriptive
        fields, so this reads as "tool fetch  data-exfiltration  description". A
        hand-written entry may carry only a fingerprint, and naming it by its id
        is still more use than dropping it from the report.
        """
        if not (self.kind or self.target or self.rule):
            return f"fingerprint {self.fingerprint[:12]}"
        located = f"{self.kind} {self.target}  {self.rule}".strip()
        if self.path:
            located = f"{located}  {self.path}"
        # A --config baseline can hold two entries that differ only by which
        # server they came from, so an entry that recorded one names it.
        return f"{self.source}: {located}" if self.source else located

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "target": self.target,
            "rule": self.rule,
            "path": self.path,
            "source": self.source,
            "fingerprint": self.fingerprint,
        }


def _text(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def load_baseline(path: str) -> list[BaselineEntry]:
    """Read a baseline file into its entries, in file order.

    Validation is exactly what it has always been: the document shape, the
    version, and a non-empty fingerprint on every entry. The descriptive fields
    are read opportunistically, never required.
    """
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

    entries: list[BaselineEntry] = []
    for entry in findings:
        if not isinstance(entry, dict):
            raise BaselineError("each baseline entry must be an object")
        fp = entry.get("fingerprint")
        if not isinstance(fp, str) or not fp:
            raise BaselineError("a baseline entry is missing its fingerprint")
        entries.append(
            BaselineEntry(
                fingerprint=fp,
                kind=_text(entry, "kind"),
                target=_text(entry, "target"),
                rule=_text(entry, "rule"),
                path=_text(entry, "path"),
                source=_text(entry, "source"),
            )
        )
    return entries


def current_fingerprints(results: list[ToolResult]) -> set[str]:
    """Every finding this scan produced, by fingerprint.

    Call this BEFORE apply_baseline. That function deletes exactly the findings
    the baseline matched, so taking the set afterwards would make every accepted
    entry look like it matched nothing, which is the precise opposite of stale.
    """
    return {
        fingerprint(r.name, f, kind=r.kind, source=r.source)
        for r in results
        for f in r.findings
    }


def stale_entries(
    entries: list[BaselineEntry], present: set[str]
) -> list[BaselineEntry]:
    """The recorded approvals no current finding claimed, in file order.

    Deduplicated by fingerprint, so a file that lists the same approval twice is
    reported once. ``present`` must come from current_fingerprints on results
    that have not been filtered yet.
    """
    stale: list[BaselineEntry] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.fingerprint in present or entry.fingerprint in seen:
            continue
        seen.add(entry.fingerprint)
        stale.append(entry)
    return stale


def apply_baseline(results: list[ToolResult], accepted: set[str]) -> int:
    """Drop accepted findings from results in place; return how many were dropped.

    A tool whose findings are all accepted keeps its place in the list but scores
    clean, which is the honest reading: there is nothing new to look at.
    """
    suppressed = 0
    for r in results:
        kept: list[Finding] = []
        for f in r.findings:
            if fingerprint(r.name, f, kind=r.kind, source=r.source) in accepted:
                suppressed += 1
            else:
                kept.append(f)
        r.findings = kept
    return suppressed
