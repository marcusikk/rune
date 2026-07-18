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


def render_text(results: list[ToolResult], *, color: bool = False) -> str:
    lines: list[str] = []
    total_findings = sum(len(r.findings) for r in results)

    for r in results:
        header = f"{r.name}  risk {r.score}/100  [{r.band}]"
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
        f"{len(results)} tool(s) scanned, {flagged} flagged, "
        f"{total_findings} finding(s)."
    )
    lines.append(summary)
    return "\n".join(lines)


def to_json(results: list[ToolResult]) -> dict[str, Any]:
    return {
        "tools": [
            {
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
            for r in results
        ],
        "summary": {
            "tools": len(results),
            "flagged": sum(1 for r in results if r.findings),
            "findings": sum(len(r.findings) for r in results),
        },
    }


def render_json(results: list[ToolResult]) -> str:
    return json.dumps(to_json(results), indent=2, ensure_ascii=True)
