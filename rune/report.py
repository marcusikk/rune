"""Render scan results as text, JSON, or SARIF."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from .baseline import BaselineEntry, fingerprint
from .models import Finding, SourceStatus, ToolResult
from .pin import Drift
from .scan import render_visible

_COLORS = {
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "CLEAN": "\033[32m",
}
_RESET = "\033[0m"

# Bands from least to most severe, so a section heading can take the colour of
# the worst entity under it.
_BANDS = ("CLEAN", "LOW", "MEDIUM", "HIGH")


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


def _entity_lines(r: ToolResult, color: bool, *, show_source: bool = False) -> list[str]:
    """The block of report lines for one scanned entity.

    The entity name and the JSON path are the server's text, not rune's: the
    name is whatever the manifest called the tool, and the path is built from
    the manifest's own object keys. Both are escaped for the same reason the
    excerpt always has been. A name holding a newline would otherwise write
    whole lines of this report itself, and a report that reads as rune's
    verdict is exactly what an attacker wants to author. Escaping is the
    identity on every name and path that does not contain one, so an ordinary
    report is unchanged.

    ``show_source`` prefixes the source when several listings share one flat
    report, so a reader can tell which of them a finding came from. A --config
    scan leaves it off because its section headings already name each server;
    a single-source scan has no source to show.
    """
    where = f"{render_visible(r.source)} / " if show_source and r.source is not None else ""
    header = f"{where}{r.kind} {render_visible(r.name)}  risk {r.score}/100  [{r.band}]"
    lines = [_paint(r.band, header, color)]
    for f in r.findings:
        tag = f"[{f.severity.label.upper()}]"
        path = render_visible(f.path)
        location = f"{path} (offset {f.offset})" if path else f"offset {f.offset}"
        lines.append(f"  {tag} {f.rule}  {location}")
        lines.append(f"      {f.message}")
        lines.append(f"      > {f.excerpt}")
    lines.append("")
    return lines


def _summary(results: list[ToolResult], baselined: int) -> str:
    flagged = sum(1 for r in results if r.findings)
    total_findings = sum(len(r.findings) for r in results)
    summary = (
        f"{_scanned_clause(results)}, {flagged} flagged, "
        f"{total_findings} finding(s)."
    )
    if baselined:
        summary += f" {baselined} baselined."
    return summary


def _roll_call(sources: Sequence[SourceStatus], config: str) -> str:
    """How many of the config's servers this run actually opened.

    Its own line, above the findings summary and naming the config file, because
    the per-kind clause below it already counts ``server`` entities: the
    handshake metadata of one server. Two counts of two different things sharing
    a word in one sentence is how a reader comes away thinking three of five
    servers were poisoned when three of five were never opened.
    """
    scanned = sum(1 for s in sources if s.ok)
    line = f"{scanned} of {len(sources)} server(s) in {config} scanned"
    counts = [
        (sum(1 for s in sources if s.status == "failed"), "failed"),
        (sum(1 for s in sources if s.status == "disabled"), "disabled"),
    ]
    extra = ", ".join(f"{n} {label}" for n, label in counts if n)
    return f"{line}, {extra}." if extra else f"{line}."


def render_text(results: list[ToolResult], *, color: bool = False, baselined: int = 0) -> str:
    """Render the human report for a scan of one server, or of several captured
    listings that each name their source."""
    # Several captured manifests are reported flat, not in config-style sections,
    # so a finding names its source inline. A single scan has no source set and
    # reads exactly as it always has.
    show_source = any(r.source is not None for r in results)
    lines: list[str] = []
    for r in results:
        lines.extend(_entity_lines(r, color, show_source=show_source))
    lines.append(_summary(results, baselined))
    return "\n".join(lines)


def render_config_text(
    results: list[ToolResult],
    sources: Sequence[SourceStatus],
    config: str,
    *,
    color: bool = False,
    baselined: int = 0,
) -> str:
    """Render the human report for a scan that covered several servers.

    Sections follow the order the config listed the servers in, which is the
    order its reader already knows, and every requested server gets a section
    whether or not it produced anything. A server that failed to start, one the
    config had switched off, and one that listed no metadata at all each say so
    under their own heading. The alternative, printing only the servers that
    returned results, would let a server drop out of an audit without the report
    ever mentioning it.

    A config's name for a server is text out of a file, so it is escaped in the
    heading exactly as an entity name is in the line below it.
    """
    by_source: dict[str, list[ToolResult]] = {}
    for r in results:
        by_source.setdefault(r.source or "", []).append(r)

    lines: list[str] = []
    for status in sources:
        section = by_source.get(status.name, [])
        band = max((r.band for r in section), key=_BANDS.index, default="CLEAN")
        lines.append(
            _paint(band, f"=== {render_visible(status.name)} ({status.transport}) ===", color)
        )
        if status.status == "disabled":
            lines.extend(["  not scanned: disabled in the config", ""])
            continue
        if status.status == "failed":
            lines.extend([f"  not scanned: {render_visible(status.error or '')}", ""])
            continue
        if not section:
            lines.extend(["  no tools, prompts, resources or server metadata listed", ""])
            continue
        for r in section:
            lines.extend(_entity_lines(r, color))

    lines.append(_roll_call(sources, config))
    lines.append(_summary(results, baselined))
    return "\n".join(lines)


def render_source_notice(sources: Sequence[SourceStatus]) -> str:
    """Name the servers a multi-server run did not scan, and why.

    On stderr in every output mode, for the reason the stale-baseline and drift
    notices are: it is a statement about the run rather than a finding about a
    server, so it must not land inside piped --json or --sarif, and it must still
    be seen there. The exit code says the audit was incomplete; this says which
    servers made it so.
    """
    skipped = [s for s in sources if not s.ok]
    lines = [f"rune: {len(skipped)} of {len(sources)} server(s) were not scanned:"]
    for s in skipped:
        why = "disabled in the config" if s.status == "disabled" else (s.error or "")
        lines.append(f"  {render_visible(s.name)}: {render_visible(why)}")
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

    A label is the entity name a past scan recorded, so it is still the server's
    text however long it has sat in the repo, and it is escaped like the drift
    notice's.
    """
    lines = [
        f"rune: {len(stale)} baseline entry(s) matched nothing in this scan:"
    ]
    lines.extend(f"  {render_visible(entry.label)}" for entry in stale)
    lines.append(
        "rune: prune them by re-running with --write-baseline, or ignore this if "
        "this scan covered less than the baseline was written from"
    )
    return "\n".join(lines)


def render_drift_notice(drifts: Sequence[Drift]) -> str:
    """Name the metadata that no longer matches the pin, and how to act on it.

    On stderr in every output mode, for the same reason the stale notice is: it
    is a statement about a file on disk next to the scan, not a finding about the
    scanned server, so it must not land inside piped --json or --sarif, and it
    must still be visible there.

    Entity names and JSON paths come from the server, so they are escaped the
    same way a finding's excerpt is. A tool named with an embedded newline must
    not be able to forge a line of rune's own output.
    """
    lines = [f"rune: {len(drifts)} pinned entity(s) no longer match the pin:"]
    lines.extend(f"  {render_visible(d.label)}" for d in drifts)
    lines.append(
        "rune: read the change before accepting it; re-run with --write-pin to "
        "pin the metadata as it is now"
    )
    return "\n".join(lines)


def render_unchecked_notice(names: Sequence[str]) -> str:
    """Name the pinned servers this run did not scan, so a partial gate says so.

    A pin over a whole config is a gate, and a gate that silently checks four of
    six servers is the failure the roll call exists to prevent. rune cannot tell
    why a server was left out, whether it was narrowed away with --server,
    switched off in the config, or taken out of the file since the pin was
    written, so it reports the fact and leaves the reading to whoever ran it.

    On stderr in every output mode, for the reason the drift notice is.
    """
    lines = [f"rune: the pin also covers {len(names)} server(s) this run did not scan:"]
    lines.extend(f"  {render_visible(name)}" for name in names)
    lines.append(
        "rune: their pinned metadata was not checked; scan them to check it, or "
        "re-run with --write-pin to drop them"
    )
    return "\n".join(lines)


def _entity_json(r: ToolResult) -> dict[str, Any]:
    entity: dict[str, Any] = {
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
    # Present only on a --config scan, so the shape a single-server scan emits
    # is exactly what it has always been.
    if r.source is not None:
        entity["source"] = r.source
    return entity


def to_json(
    results: list[ToolResult],
    *,
    baselined: int = 0,
    stale: Sequence[BaselineEntry] = (),
    drifts: Sequence[Drift] = (),
    unchecked: Sequence[str] = (),
    sources: Sequence[SourceStatus] = (),
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
        # The pin differences in machine-readable form, so a pipeline can tell a
        # changed description from a tool that was added without parsing stderr.
        "pinDrift": [drift.as_dict() for drift in drifts],
        # The servers the pin covers that this run did not scan, so a consumer
        # can see that a clean pinDrift was a partial check. Not derivable from
        # "sources" below: a server dropped from the config since the pin was
        # written appears here and nowhere else.
        "pinUnchecked": list(unchecked),
        # Every server a --config run was asked to cover, scanned or not, in
        # config order. A consumer that only counted the entities below would
        # read a server that failed to start as a server with nothing to report.
        # Empty for a scan of a single server, which has no roll call to give.
        "sources": [status.as_dict() for status in sources],
        "summary": {
            "tools": len(grouped["tool"]),
            "prompts": len(grouped["prompt"]),
            "resources": len(grouped["resource"]),
            "servers": len(grouped["server"]),
            "flagged": sum(1 for r in results if r.findings),
            "findings": sum(len(r.findings) for r in results),
            "baselined": baselined,
            "staleBaseline": len(stale),
            "pinDrift": len(drifts),
            "pinUnchecked": len(unchecked),
            "sources": len(sources),
            "sourcesScanned": sum(1 for status in sources if status.ok),
        },
    }


def render_json(
    results: list[ToolResult],
    *,
    baselined: int = 0,
    stale: Sequence[BaselineEntry] = (),
    drifts: Sequence[Drift] = (),
    unchecked: Sequence[str] = (),
    sources: Sequence[SourceStatus] = (),
) -> str:
    return json.dumps(
        to_json(
            results,
            baselined=baselined,
            stale=stale,
            drifts=drifts,
            unchecked=unchecked,
            sources=sources,
        ),
        indent=2,
        ensure_ascii=True,
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
        "A secret, or the model's own system prompt, is named as the object of "
        "an outbound verb sent to an external destination.",
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
        "confusable-characters",
        "A Cyrillic or Greek look-alike character mixed into a Latin word, used "
        "to spoof a name or slip text past a reviewer and the other rules.",
        "error",
    ),
    (
        "compatibility-characters",
        "Text styled in a Unicode compatibility variant of ASCII (fullwidth, "
        "mathematical, or circled letters) that normalizes to a payload another "
        "rule catches, used to slip it past the ASCII rules.",
        "error",
    ),
    (
        "base64-payload",
        "A base64-encoded run that decodes to a payload another rule catches, "
        "used to hide it from the ASCII rules while a model decodes and acts on "
        "it.",
        "error",
    ),
    (
        "hex-payload",
        "A hex-encoded run that decodes to a payload another rule catches, used "
        "to hide it from the ASCII rules while a model decodes and acts on it.",
        "error",
    ),
    (
        "injection-markup",
        "Markup a model may read as an instruction boundary, such as <system>, "
        "[INST], Llama's <<SYS>>, a Gemma turn marker, or a model special token "
        "in the <|...|> frame.",
        "warning",
    ),
    (
        "name-collision",
        "Two entities answer to one name a client routes calls by, so which "
        "definition a call reaches is up to the client. A server that claims "
        "the name of a tool already in the config shadows it.",
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

    # On a --config scan the server's name leads the alert text, because the
    # same tool name can come from two servers in one log and a triager has to
    # be able to tell which one this is. Escaped, like every other piece of
    # scanned text that lands in a sentence a human reads.
    where = f"{render_visible(r.source)} / " if r.source is not None else ""
    result: dict[str, Any] = {
        "ruleId": f.rule,
        "level": _SARIF_LEVELS.get(f.severity.label, "warning"),
        # The alert body names the exact substring the rule objected to, not
        # f.excerpt: the excerpt widens the match with up to 40 characters of
        # surrounding context on each side, so using it here would present
        # benign neighbouring prose to a triager as the flagged text. Escaped,
        # because an invisible-characters match is by definition unprintable.
        # The name is escaped for the same reason: this is a sentence a triager
        # reads, so server text in it is quoted, never spelled out. The
        # structured fields below keep the exact name, because those are the
        # finding's data and a tool matching on them must see what was sent.
        "message": {
            "text": (
                f"{where}{r.kind} {render_visible(r.name)}: {f.message}. "
                f"Flagged text: {render_visible(f.match)}"
            )
        },
        "locations": [location],
        # Baseline and SARIF agree on identity, so a result carries the same id
        # here that --baseline would suppress it by. That includes the source on
        # a --config scan: without it two servers exposing an identically named
        # tool with the same finding would collapse into one alert upstream.
        "partialFingerprints": {
            "runeFingerprint/v1": fingerprint(r.name, f, kind=r.kind, source=r.source)
        },
        "properties": {"kind": r.kind, "target": r.name, "score": r.score, "band": r.band},
    }
    if r.source is not None:
        result["properties"]["source"] = r.source
    if f.rule in _RULE_INDEX:
        result["ruleIndex"] = _RULE_INDEX[f.rule]
    return result


def _sarif_invocation(sources: Sequence[SourceStatus]) -> dict[str, Any]:
    """Record which servers a config run could not open, in SARIF's own terms.

    An empty results array tells the platform to clear the alerts it raised
    before. That is right for a server rune scanned and found clean, and exactly
    wrong for one that would not start: without this, a server that quietly stops
    starting would have its old alerts cleared as if it had been re-audited.
    ``executionSuccessful`` is what says the run was partial, and the
    notifications name which servers made it so.
    """
    notifications = [
        {
            "level": "error" if s.status == "failed" else "note",
            "message": {
                "text": (
                    f"server {render_visible(s.name)} was not scanned: "
                    + (
                        "disabled in the config"
                        if s.status == "disabled"
                        else render_visible(s.error or "unknown reason")
                    )
                )
            },
        }
        for s in sources
        if not s.ok
    ]
    return {
        "executionSuccessful": not any(s.status == "failed" for s in sources),
        "toolExecutionNotifications": notifications,
    }


def to_sarif(
    results: list[ToolResult],
    *,
    uri: str | None = None,
    version: str = "0.1.0",
    sources: Sequence[SourceStatus] = (),
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from scan results.

    ``uri`` is the manifest file the results came from, used as the artifact
    location. It is left off for a live (``--stdio``) or piped (stdin) scan,
    which have no file on disk; those results carry only their JSON-path logical
    location. A fully clean scan produces an empty ``results`` array, which is a
    valid log and tells the platform to clear any alerts it had cleared before.

    ``sources`` is the per-server roll call of a ``--config`` run, which becomes
    an ``invocations`` entry. It is left off entirely for a single-server scan,
    so that log is byte for byte what it has always been.
    """
    sarif_results = [
        _sarif_result(r, f, uri) for r in results for f in r.findings
    ]
    run: dict[str, Any] = {
        "tool": {"driver": _sarif_driver(version)},
        "results": sarif_results,
    }
    if sources:
        run["invocations"] = [_sarif_invocation(sources)]
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def render_sarif(
    results: list[ToolResult],
    *,
    uri: str | None = None,
    version: str = "0.1.0",
    sources: Sequence[SourceStatus] = (),
) -> str:
    return json.dumps(
        to_sarif(results, uri=uri, version=version, sources=sources),
        indent=2,
        ensure_ascii=True,
    )
