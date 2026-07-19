"""Data structures shared across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Finding severity, ordered so it can be compared and summed."""

    LOW = ("low", 5)
    MEDIUM = ("medium", 15)
    HIGH = ("high", 40)

    def __init__(self, label: str, points: int) -> None:
        self.label = label
        self.points = points

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.label]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    @classmethod
    def from_label(cls, label: str) -> Severity:
        for member in cls:
            if member.label == label:
                return member
        raise ValueError(f"unknown severity: {label}")


# Score thresholds for the per-tool risk band.
_HIGH_BAND = 40
_MEDIUM_BAND = 15


@dataclass(frozen=True)
class Finding:
    """A single hit: which rule, where, and the offending text.

    ``match`` is the exact substring the rule flagged. ``excerpt`` is that same
    text widened with surrounding context and rendered for display, so it moves
    whenever nearby text changes. Identity keys on ``match``, never on
    ``excerpt`` or ``offset``.
    """

    rule: str
    severity: Severity
    path: str
    offset: int
    match: str
    excerpt: str
    message: str


@dataclass
class ToolResult:
    """All findings for one scanned entity plus its rolled-up score.

    An MCP server exposes model-facing metadata as ``tool``, ``prompt`` and
    ``resource`` listings, plus its own ``server`` metadata (the initialize
    ``instructions`` and ``serverInfo``). ``kind`` records which one this result
    came from so mixed output stays legible and a prompt named like a tool keeps
    a distinct baseline identity.
    """

    name: str
    findings: list[Finding] = field(default_factory=list)
    kind: str = "tool"

    @property
    def score(self) -> int:
        return min(100, sum(f.severity.points for f in self.findings))

    @property
    def band(self) -> str:
        score = self.score
        if score >= _HIGH_BAND:
            return "HIGH"
        if score >= _MEDIUM_BAND:
            return "MEDIUM"
        if score >= 1:
            return "LOW"
        return "CLEAN"
