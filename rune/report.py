"""Render scan results as text or JSON."""

from __future__ import annotations

import json
from typing import Any

from .models import ToolResult

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
    counts = {kind: 0 for kind in ("tool", "prompt", "resource")}
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


def to_json(results: list[ToolResult], *, baselined: int = 0) -> dict[str, Any]:
    # Grouped by kind so the "tools" array keeps its existing shape and prompts
    # and resources appear alongside it rather than mixed in.
    grouped = {kind: [] for kind in ("tool", "prompt", "resource")}
    for r in results:
        grouped.setdefault(r.kind, []).append(_entity_json(r))
    return {
        "tools": grouped["tool"],
        "prompts": grouped["prompt"],
        "resources": grouped["resource"],
        "summary": {
            "tools": len(grouped["tool"]),
            "prompts": len(grouped["prompt"]),
            "resources": len(grouped["resource"]),
            "flagged": sum(1 for r in results if r.findings),
            "findings": sum(len(r.findings) for r in results),
            "baselined": baselined,
        },
    }


def render_json(results: list[ToolResult], *, baselined: int = 0) -> str:
    return json.dumps(to_json(results, baselined=baselined), indent=2, ensure_ascii=True)
