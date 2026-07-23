"""Walk a tool's metadata, run the rules, and roll findings into a score."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from .models import Finding, Severity, ToolResult
from .rules import NAME_COLLISION, scan_text

# How many characters of context to show around a hit.
_EXCERPT_RADIUS = 40


def render_visible(text: str) -> str:
    """Make hidden characters visible so flagged text is readable and safe.

    Shared with the reporters: any surface that prints a snippet of scanned
    metadata has to escape it, or the invisible characters rune exists to find
    pass straight through the report unseen.

    Two properties every caller relies on. The result carries no character that
    can end or forge a line of rune's own output, and it carries no character a
    UTF-8 stream refuses to encode. Together they are what lets a reporter
    interpolate server-controlled text into a line of prose at all.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch in "\t":
            out.append(" ")
        elif ch == "\n":
            out.append("\\n")
        elif cp in (0x2028, 0x2029):
            # Unicode's own line and paragraph separators. A terminal ignores
            # them, but str.splitlines() and plenty of viewers break a line on
            # one, so leaving them raw would hand a name a second way to write
            # a line of this report. No rule flags them either, since they are
            # legitimate text elsewhere.
            out.append(f"<U+{cp:04X}>")
        elif 0xD800 <= cp <= 0xDFFF:
            # Not a hidden character but an unencodable one. JSON may escape an
            # unpaired surrogate, and Python's parser hands it back as a code
            # point no UTF-8 stream will take, so printing it raw raises on a
            # scan that had otherwise succeeded. The server picks whether that
            # happens, which makes it a way to silence a report rather than a
            # quirk. Escaped, it prints and stays distinct from every other
            # code point.
            out.append(f"<U+{cp:04X}>")
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F or cp in (
            0x200B,
            0x200C,
            0x200D,
            0x2060,
            0xFEFF,
            0x00AD,
            0x061C,
        ) or 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069 or 0xE0000 <= cp <= 0xE007F:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)


def _excerpt(text: str, offset: int, length: int) -> str:
    start = max(0, offset - _EXCERPT_RADIUS)
    end = min(len(text), offset + length + _EXCERPT_RADIUS)
    snippet = render_visible(text[start:end])
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_path, string) for every string leaf under value.

    This is the definition of the surface rune reads: every string here is a
    string a model can be shown. Public because the pin records exactly this
    set, and a pin built from a second, hand-written walk would drift from what
    the scanner actually looks at.
    """
    if isinstance(value, str):
        yield (path, value)
    elif isinstance(value, dict):
        for key, sub in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from walk_strings(sub, child)
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            yield from walk_strings(sub, f"{path}[{i}]")


# The order kinds are reported in: tools, then prompts, resources, and last the
# server's own metadata.
KINDS = ("tool", "prompt", "resource", "server")


def entity_label(entity: dict[str, Any], kind: str, index: int) -> str:
    """The name this entity is reported under. Shared with the pin, which keys
    its entries on the same label the report prints."""
    # The server's name and title live nested under serverInfo, not at the top
    # level, so read the label from there rather than duplicating it as a
    # top-level string (which would then be scanned twice).
    if kind == "server":
        info = entity.get("serverInfo")
        if isinstance(info, dict):
            for key in ("name", "title"):
                value = info.get(key)
                if isinstance(value, str) and value.strip():
                    return value
        return f"<{kind} #{index}>"
    # A resource has no name of its own in older servers, so fall back to the
    # URI it is addressed by, then the URI template, before a positional label.
    for key in ("name", "uri", "uriTemplate", "title"):
        value = entity.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return f"<{kind} #{index}>"


# The kinds an MCP client routes by name: a tool is called by name, a prompt is
# fetched by name. A resource is addressed by its URI and may legitimately carry
# the same display name as another, and the server's own metadata is not a call
# target at all, so neither is compared.
_ROUTED_KINDS = ("tool", "prompt")


def route_name(entity: dict[str, Any], kind: str) -> str | None:
    """The name a client would route a call to this entity by, or None.

    Deliberately not ``entity_label``: that falls back to a title, a URI, or a
    positional ``<tool #0>`` so every result has something to print, and two
    entities that both fell back are not two definitions of one call target.
    Only a declared, non-blank ``name`` on a routed kind is one.
    """
    if kind not in _ROUTED_KINDS:
        return None
    name = entity.get("name")
    if isinstance(name, str) and name.strip():
        return name
    return None


def _finding_order(f: Finding) -> tuple[int, str, int]:
    return (-f.severity.rank, f.path, f.offset)


def _other_servers_clause(kind: str, names: Sequence[str]) -> str:
    """Name the other servers holding this name, escaped like every other piece
    of scanned text that lands in a sentence a human reads."""
    quoted = ", ".join(f"'{render_visible(n)}'" for n in names)
    if len(names) == 1:
        return f"server {quoted} also exposes a {kind} with this name"
    return f"servers {quoted} also expose a {kind} with this name"


def _collision_message(kind: str, same_listing: bool, others: Sequence[str]) -> str:
    clauses = []
    if same_listing:
        clauses.append(f"a second {kind} in the same listing carries this name")
    if others:
        clauses.append(_other_servers_clause(kind, others))
    if not clauses:
        # Only reachable if one scan mixes results that name their server with
        # results that do not. Nothing in rune produces that today, but a
        # sentence that opens with a comma is not a thing to leave a future
        # caller able to print.
        clauses.append(f"another {kind} in this scan carries this name")
    return (
        "; ".join(clauses)
        + f", so which definition a call to this {kind} reaches is up to the client"
    )


def flag_name_collisions(results: list[ToolResult]) -> int:
    """Flag every entity that shares its routed name with another, in place.

    A client calls a tool by name. Two definitions answering to one name means
    the client picks, by load order or by whichever listing it read last, and the
    caller cannot tell which one it got. That is a shadowing attack when a server
    added to a config claims the name of a tool the user already trusts, and it
    is an ambiguity worth knowing about even when nobody meant anything by it,
    which is why the finding is medium and not high: rune can see the collision,
    never the intent behind it.

    It has to run over the whole scan at once, after every server has been
    listed, because the interesting pair spans two servers in one config and
    neither listing is anomalous on its own.

    Returns the number of findings added, and re-sorts what it touched so the
    report keeps the order it documents.
    """
    groups: dict[tuple[str, str], list[ToolResult]] = {}
    for r in results:
        if r.route_name is not None:
            groups.setdefault((r.kind, r.route_name), []).append(r)

    added = 0
    for (kind, name), group in groups.items():
        if len(group) < 2:
            continue
        # Worked out once per group, not once per member: a listing that repeats
        # one name a thousand times would otherwise be quadratic, and the size of
        # that listing is the server's choice.
        counts: dict[str | None, int] = {}
        for o in group:
            counts[o.source] = counts.get(o.source, 0) + 1
        named = sorted(s for s in counts if s is not None)
        for r in group:
            others = [s for s in named if s != r.source]
            same_listing = counts[r.source] > 1
            r.findings.append(
                Finding(
                    rule=NAME_COLLISION,
                    severity=Severity.MEDIUM,
                    # The name string is where the collision sits, and it is the
                    # path a text rule firing on the same characters reports, so
                    # the two stay comparable in a baseline and in SARIF.
                    path="name",
                    offset=0,
                    match=name,
                    excerpt=_excerpt(name, 0, len(name)),
                    message=_collision_message(kind, same_listing, others),
                )
            )
            r.findings.sort(key=_finding_order)
            added += 1
    if not added:
        return 0

    # A collision changes a score, so the "riskiest entity leads its kind" order
    # scan_targets established has to be re-established. Sorting each contiguous
    # (source, kind) run rather than the whole list keeps every entity under the
    # server and kind it was reported beneath.
    start = 0
    for i in range(1, len(results) + 1):
        end = i == len(results)
        if end or (results[i].source, results[i].kind) != (
            results[start].source,
            results[start].kind,
        ):
            results[start:i] = sorted(
                results[start:i], key=lambda item: (-item.score, item.name)
            )
            start = i
    return added


def scan_entity(entity: dict[str, Any], kind: str = "tool", index: int = 0) -> ToolResult:
    """Scan one tool, prompt or resource definition into a result."""
    result = ToolResult(
        name=entity_label(entity, kind, index),
        kind=kind,
        route_name=route_name(entity, kind),
    )
    for path, text in walk_strings(entity):
        for rule, severity, offset, length, message in scan_text(text):
            result.findings.append(
                Finding(
                    rule=rule,
                    severity=severity,
                    path=path,
                    offset=offset,
                    match=text[offset:offset + length],
                    excerpt=_excerpt(text, offset, length),
                    message=message,
                )
            )
    result.findings.sort(key=_finding_order)
    return result


def scan_tool(tool: dict[str, Any], index: int = 0) -> ToolResult:
    """Scan one tool definition and return its findings and score."""
    return scan_entity(tool, "tool", index)


def scan_tools(tools: list[dict[str, Any]]) -> list[ToolResult]:
    """Scan a list of tools, highest risk first."""
    return scan_targets({"tool": tools})


def scan_targets(
    groups: dict[str, list[dict[str, Any]]], *, source: str | None = None
) -> list[ToolResult]:
    """Scan every entity across the kinds, grouped by kind, highest risk first.

    Kinds are reported tools-then-prompts-then-resources, and within a kind the
    riskiest entity leads. Grouping keeps the kind labels clustered instead of
    interleaving a low-scoring prompt between two tools.

    ``source`` is the name of the server these groups were listed from, set only
    when one run covers several servers. It is stamped on every result here, at
    the one place a scan is turned into results, so no caller can produce a
    result that has lost track of which server it describes.
    """
    results: list[ToolResult] = []
    for kind in KINDS:
        group = [
            scan_entity(entity, kind, i)
            for i, entity in enumerate(groups.get(kind, []))
        ]
        group.sort(key=lambda r: (-r.score, r.name))
        results.extend(group)
    if source is not None:
        for result in results:
            result.source = source
    return results
