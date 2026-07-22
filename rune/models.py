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


@dataclass(frozen=True)
class SourceStatus:
    """What became of one server a multi-server run was asked to cover.

    A run over a whole config has to report the servers it could not open as
    loudly as the ones it could. A server that failed to start contributes no
    results, so without this it would simply be absent from the report, and an
    audit that quietly covered four of five servers is the exact failure a gate
    exists to prevent.

    ``status`` is one of ``scanned``, ``failed`` or ``disabled``. ``error`` is set
    only for ``failed`` and holds the reason, with anything read out of the config
    stripped back out of it.
    """

    name: str
    transport: str
    status: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "scanned"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "transport": self.transport,
            "status": self.status,
            "error": self.error,
        }


@dataclass
class ToolResult:
    """All findings for one scanned entity plus its rolled-up score.

    An MCP server exposes model-facing metadata as ``tool``, ``prompt`` and
    ``resource`` listings, plus its own ``server`` metadata (the initialize
    ``instructions`` and ``serverInfo``). ``kind`` records which one this result
    came from so mixed output stays legible and a prompt named like a tool keeps
    a distinct baseline identity.

    ``source`` names the server this result came from when one run scanned
    several, which is what ``--config`` does. It is ``None`` for every
    single-server scan, so a manifest, ``--stdio``, ``--http`` and ``--sse`` run
    reports and fingerprints exactly as it always has. When it is set it is part
    of the finding's identity: two servers in one config can each expose a tool
    named ``search``, and their findings are not the same finding.
    """

    name: str
    findings: list[Finding] = field(default_factory=list)
    kind: str = "tool"
    source: str | None = None

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
