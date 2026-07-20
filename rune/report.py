"""Render scan results as text, JSON, or SARIF."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .baseline import BaselineEntry, fingerprint
from .models import Finding, ToolResult
from .scan import render_visible

_COLORS = {
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "CLEAN": "\033[32m",
}
_RESET = "\033[0m"


def _paint(band: str, text: str, color: bool) -> str:
    if not color:
        return text
    return f"{_COLORS.get(band, '')}{text}{_RESET}"


def _scanned_clause(results: list[ToolResult]) -> str:
    """A per-kind count of what was scanned, e.g. "3 tool(s), 1 prompt(s)".

    Only kinds that are present are named, so a tools-only scan reads exactly as
    it always has and a mixed scan spells out the extra surface it covered.
    """
    counts = {kind: 0 for kind in ("tool", "prompt", "resource", "server")}
    for r in results:
        counts[r.kind] = counts.get(r.kind, 0) + 1
    parts = [f"{n} {kind}(s)" for kind, n in counts.items() if n]
    if not parts:
        parts = ["0 tool(s)"]
    return ", ".join(parts) + " scanned"


def render_text(results: list[ToolResult], *, color: bool = False, baselined: int = 0) -> str:
    lines: list[str] = []
    total_findings = sum(len(r.findings) for r in results)

    for r in results:
        header = f"{r.kind} {r.name}  risk {r.score}/100  [{r.band}]"
        lines.append(_paint(r.band, header, color))
        for f in r.findings:
            tag = f"[{f.severity.label.upper()}]"
            location = f"{f.path} (offset {f.offset})" if f.path else f"offset {f.offset}"
            lines.append(f"  {tag} {f.rule}  {location}")
            lines.append(f"      {f.message}")
            lines.append(f"      > {f.excerpt}")
        lines.append("")

    flagged = sum(1 for r in results if r.findings)
    summary = (
        f"{_scanned_clause(results)}, {flagged} flagged, "
        f"{total_findings} finding(s)."
    )
    if baselined:
        summary += f" {baselined} baselined."
    lines.append(summary)
    return "\n".join(lines)


def render_stale_notice(stale: Sequence[BaselineEntry]) -> str:
    """Name the baseline entries this scan did not match, and how to act on them.

    This goes to stderr in every output mode rather than into the report body. It
    is a statement about the baseline file, not about the scanned server, so it
    must not land in the middle of piped --json or --sarif, and it must still be
    visible in those modes, which a line in the text report would not be.

    The wording claims only what rune actually knows. An entry can match nothing
    because the finding was fixed, and it can match nothing because this scan
    covered less than the one the baseline was written from. rune cannot tell
    those apart, so it reports the fact and leaves the judgement to the reader.
    """
    lines = [
        f"rune: {len(stale)} baseline entry(s) matched nothing in this scan:"
    ]
    lines.extend(f"  {entry.label}" for entry in stale)
    lines.append(
        "rune: prune them by re-running with --write-baseline, or ignore this if "
        "this scan covered less than the baseline was written from"
    )
    return "\n".join(lines)


def _entity_json(r: ToolResult) -> dict[str, Any]:
    return {
        "name": r.name,
        "score": r.score,
        "band": r.band,
        "findings": [
            {
                "rule": f.rule,
                "severity": f.severity.label,
                "path": f.path,
                "offset": f.offset,
                "message": f.message,
                "excerpt": f.excerpt,
            }
            for f in r.findings
        ],
    }


def to_json(
    results: list[ToolResult],
    *,
    baselined: int = 0,
    stale: Sequence[BaselineEntry] = (),
) -> dict[str, Any]:
    # Grouped by kind so the "tools" array keeps its existing shape and prompts
    # and resources appear alongside it rather than mixed in.
    grouped = {kind: [] for kind in ("tool", "prompt", "resource", "server")}
    for r in results:
        grouped.setdefault(r.kind, []).append(_entity_json(r))
    return {
        "tools": grouped["tool"],
        "prompts": grouped["prompt"],
        "resources": grouped["resource"],
        "servers": grouped["server"],
        # The stale entries in machine-readable form, so a team can prune a
        # baseline from a script rather than reading them off stderr. Each one
        # carries the same fields the baseline file recorded, so an entry here
        # can be matched straight back to the line it came from.
        "staleBaseline": [entry.as_dict() for entry in stale],
        "summary": {
            "tools": len(grouped["tool"]),
            "prompts": len(grouped["prompt"]),
            "resources": len(grouped["resource"]),
            "servers": len(grouped["server"]),
            "flagged": sum(1 for r in results if r.findings),
            "findings": sum(len(r.findings) for r in results),
            "baselined": baselined,
            "staleBaseline": len(stale),
        },
    }


def render_json(
    results: list[ToolResult],
    *,
    baselined: int = 0,
    stale: Sequence[BaselineEntry] = (),
) -> str:
    return json.dumps(
        to_json(results, baselined=baselined, stale=stale), indent=2, ensure_ascii=True
    )


# --- SARIF 2.1.0 -------------------------------------------------------------
#
# SARIF is the format GitHub and GitLab code scanning ingest, so emitting it
# lets rune's findings show up in the platform's security UI beside everything
# else, instead of only as an exit code. This is a second machine format next to
# --json, never a replacement: the --json shape is rune's own and unchanged.
#
# The one thing worth pointing out: SARIF has a first-class partialFingerprints
# field whose whole job is to give a result a stable identity so the platform can
# track it across runs and not re-alert on one a human already triaged. rune
# already computes exactly that id for its baseline, so the two line up with no
# new machinery - the SARIF fingerprint IS the baseline fingerprint.

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/marcusikk/rune"

# SARIF result levels, keyed by rune severity label. SARIF has no "high"; the
# convention is error/warning/note, which maps cleanly onto high/medium/low.
_SARIF_LEVELS = {"high": "error", "medium": "warning", "low": "note"}

# The rules rune can emit, in a fixed order so ruleIndex is stable across runs.
# Each entry is (id, one-line description, default level). The per-result level
# still comes from the finding's own severity; this is only the rule's default.
_SARIF_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "data-exfiltration",
        "A secret is named as the object of an outbound verb sent to an "
        "external destination.",
        "error",
    ),
    (
        "hidden-instructions",
        "Text aimed at the reading model, such as an instruction to ignore its "
        "prior context or change role.",
        "error",
    ),
    (
        "concealment",
        "A directive to hide the tool's activity from the user.",
        "error",
    ),
    (
        "invisible-characters",
        "Zero-width, bidirectional, or tag characters used to smuggle text past "
        "a human reviewer.",
        "warning",
    ),
    (
        "injection-markup",
        "Markup a model may read as an instruction boundary, such as <system> "
        "or [INST].",
        "warning",
    ),
    (
        "sensitive-file-access",
        "A directive to read a well-known credential or secret file, such as an "
        "SSH private key or cloud credentials.",
        "error",
    ),
)

_RULE_INDEX = {rule_id: i for i, (rule_id, _, _) in enumerate(_SARIF_RULES)}


def _sarif_driver(version: str) -> dict[str, Any]:
    return {
        "name": "rune",
        "informationUri": _INFORMATION_URI,
        "version": version,
        "rules": [
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": text},
                "defaultConfiguration": {"level": level},
                "helpUri": _INFORMATION_URI,
            }
            for rule_id, text, level in _SARIF_RULES
        ],
    }


def _sarif_result(r: ToolResult, f: Finding, uri: str | None) -> dict[str, Any]:
    location: dict[str, Any] = {
        # The JSON path (e.g. inputSchema.properties.path.description) is where
        # the poison sits inside the entity. rune does not track a source line in
        # the manifest file, so the path goes in as a logical location, which is
        # how SARIF names a spot in structured data that has no line of its own.
        "logicalLocations": [{"fullyQualifiedName": f.path or r.name, "kind": "member"}],
    }
    if uri is not None:
        location["physicalLocation"] = {"artifactLocation": {"uri": uri}}

    result: dict[str, Any] = {
        "ruleId": f.rule,
        "level": _SARIF_LEVELS.get(f.severity.label, "warning"),
        # The alert body names the exact substring the rule objected to, not
        # f.excerpt: the excerpt widens the match with up to 40 characters of
        # surrounding context on each side, so using it here would present
        # benign neighbouring prose to a triager as the flagged text. Escaped,
        # because an invisible-characters match is by definition unprintable.
        "message": {
            "text": f"{r.kind} {r.name}: {f.message}. Flagged text: {render_visible(f.match)}"
        },
        "locations": [location],
        # Baseline and SARIF agree on identity, so a result carries the same id
        # here that --baseline would suppress it by.
        "partialFingerprints": {"runeFingerprint/v1": fingerprint(r.name, f, kind=r.kind)},
        "properties": {"kind": r.kind, "target": r.name, "score": r.score, "band": r.band},
    }
    if f.rule in _RULE_INDEX:
        result["ruleIndex"] = _RULE_INDEX[f.rule]
    return result


def to_sarif(
    results: list[ToolResult], *, uri: str | None = None, version: str = "0.1.0"
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from scan results.

    ``uri`` is the manifest file the results came from, used as the artifact
    location. It is left off for a live (``--stdio``) or piped (stdin) scan,
    which have no file on disk; those results carry only their JSON-path logical
    location. A fully clean scan produces an empty ``results`` array, which is a
    valid log and tells the platform to clear any alerts it had cleared before.
    """
    sarif_results = [
        _sarif_result(r, f, uri) for r in results for f in r.findings
    ]
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": _sarif_driver(version)}, "results": sarif_results}],
    }


def render_sarif(
    results: list[ToolResult], *, uri: str | None = None, version: str = "0.1.0"
) -> str:
    return json.dumps(to_sarif(results, uri=uri, version=version), indent=2, ensure_ascii=True)
