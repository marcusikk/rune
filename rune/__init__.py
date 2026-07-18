"""rune: scan MCP tool metadata for hidden instructions before you connect."""

from __future__ import annotations

from .models import Finding, Severity, ToolResult
from .scan import scan_tool, scan_tools

__all__ = ["Finding", "Severity", "ToolResult", "scan_tool", "scan_tools"]
__version__ = "0.1.0"
