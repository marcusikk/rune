"""Walk a tool's metadata, run the rules, and roll findings into a score."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .models import Finding, ToolResult
from .rules import scan_text

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


def scan_entity(entity: dict[str, Any], kind: str = "tool", index: int = 0) -> ToolResult:
    """Scan one tool, prompt or resource definition into a result."""
    result = ToolResult(name=entity_label(entity, kind, index), kind=kind)
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
    result.findings.sort(key=lambda f: (-f.severity.rank, f.path, f.offset))
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
