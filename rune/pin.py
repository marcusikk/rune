"""Record what a server's metadata said, so a later change to it cannot pass unseen.

rune reads text and matches patterns in it. That answers "does this metadata
carry a trick I know?", and the README is blunt about the limit: a clean scan
means no known trick was found, not that the server is safe. A poisoned
description written in words no rule matches reads CLEAN, today and every day
after.

The pin answers the other half, the half patterns cannot: "is this still the
text I reviewed?" You scan a server once, read what its tools say, and write a
pin. From then on rune fails when any of that text changes, whether or not a
rule fires on the new wording. That closes the rug pull, the attack this tool
would otherwise be blind to by construction: a server ships honest metadata
while it is being evaluated, gets approved and wired into an agent, then swaps
in an instruction later, when nobody is reading tool descriptions any more. The
swapped text does not have to be clumsy enough for a regex to catch. It only has
to be different, and different is exactly what a pin sees.

What is recorded is a SHA-256 per string, never the string. A pin is committed to
a repository and read in review, and a file that quoted every description back
would be a second copy of the manifest to keep in step, and would paste an
attacker's payload into a diff a human is skimming. Digests keep the file small,
keep the poisoned text out of it, and still detect a one-character edit.

Identity is (kind, name) plus the JSON path of each string, the same coordinates
the scanner and the report already use. So a renamed tool reads as one entity
gone and one arrived, which is what it is: the description a human approved is no
longer the one under that name. Reordering the listing changes nothing, since
nothing here is positional except the fallback label of an entity that has no
name of its own.

A ``--config`` run scans every server the client is wired to, so identity gains
the config's name for the server an entity came from. One pin then covers the
whole setup, which is the only version of this that gates anything: a rug pull
is not a thing you check on the one server you remembered to pin separately. The
name is recorded only when there is one, so a pin taken of a single server is
the same file it has always been. Comparison is scoped to the servers a run
actually scanned, so narrowing with --server reports drift on that server rather
than reporting the rest of the config as removed.

A pin is not a baseline. A baseline records findings a human read and accepted,
and it suppresses. A pin records the text a human read, and it fails. A
baselined finding whose text is then edited is a pin drift, on purpose: approval
covers the words that were approved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from .scan import KINDS, entity_label, render_visible, walk_strings

# Bump when the digest inputs change in a way that invalidates existing files.
# Recording the server a --config run read an entity from did NOT: the key is
# absent from every pin written before it, and one of those is read against the
# single server it describes exactly as it always was. See scope_pin.
_FORMAT_VERSION = 1

# How many changed field paths a single drift line names before it summarises
# the rest. A rewritten tool can differ in dozens of places, and a line that
# lists all of them stops being readable at exactly the moment it matters.
_MAX_LISTED_PATHS = 3


class PinError(ValueError):
    """Raised when a pin file cannot be parsed."""


@dataclass(frozen=True)
class PinnedEntity:
    """One entity's metadata as a map of JSON path to digest of the text there.

    ``source`` is the config's name for the server the entity was listed by, set
    only on a ``--config`` run. It is ``None`` for a scan of a single server,
    which has no name to record, and the key is then left out of the file
    entirely: a pin written by any earlier build is still read, and re-writing
    one produces no diff.
    """

    kind: str
    name: str
    fields: dict[str, str]
    source: str | None = None

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"kind": self.kind, "name": self.name}
        if self.source is not None:
            entry["source"] = self.source
        entry["fields"] = dict(self.fields)
        return entry


def digest(text: str) -> str:
    """The recorded digest of one string leaf.

    Just the text. The JSON path it was found at is the key this is stored
    under, and comparison is per path, so hashing the path in as well would
    change no outcome anywhere.

    Encoded with surrogatepass because the text is the server's, not ours. JSON
    allows the escape \\ud800, Python's parser hands that back as a lone
    surrogate, and a plain encode() raises on one. Such a manifest scans fine
    and exits 0 today, so a strict encode here would turn working input into a
    traceback and leave that server the one server nobody can pin, which an
    attacker picks deliberately. surrogatepass gives a surrogate the three bytes
    no valid character encodes to, so distinct strings keep distinct digests, and
    text that already encoded encodes to the same bytes as before: pins written
    by an earlier build stay valid, and no format bump is owed.
    """
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _entity_fields(entity: dict[str, Any]) -> dict[str, str]:
    """One digest per string leaf, filed under the JSON path it was found at.

    A JSON path is a display label, and two different leaves can render the same
    one: a key spelled "a.b" sits at the same path as key "b" nested under key
    "a". The scanner only ever prints that label, but here it is a dictionary
    key, and letting the second leaf land on the first would hide a change to
    one of them behind the other's digest. So a repeat gets its own slot,
    suffixed with its occurrence. That keeps one slot per leaf no matter how the
    paths are spelled, which is the property detection rests on; the label being
    a little uglier in a case no honest server produces is the cheap half.
    """
    fields: dict[str, str] = {}
    for path, text in walk_strings(entity):
        key, seen = path, 0
        while key in fields:
            seen += 1
            key = f"{path}~{seen}"
        fields[key] = digest(text)
    return fields


def pin_entities(
    groups: dict[str, list[dict[str, Any]]], *, source: str | None = None
) -> list[PinnedEntity]:
    """Digest every scannable string in every entity, in report order.

    ``source`` stamps the config's name for the server that listed them, and is
    left unset for a scan of a single server.
    """
    entities: list[PinnedEntity] = []
    for kind in KINDS:
        for index, entity in enumerate(groups.get(kind, [])):
            entities.append(
                PinnedEntity(
                    kind=kind,
                    name=entity_label(entity, kind, index),
                    fields=_entity_fields(entity),
                    source=source,
                )
            )
    return entities


def build_pin(entities: Sequence[PinnedEntity]) -> dict[str, Any]:
    """Serialize pinned entities into a pin document."""
    # Sorted so the file is stable across runs and diffs cleanly in version
    # control. Python's sort is stable, so entities sharing a source, a kind and
    # a name keep the order they were listed in, which is the order they are
    # compared in later. Server first, so one config's pin reads and diffs
    # server by server rather than interleaving them.
    ordered = sorted(entities, key=lambda e: (e.source or "", _kind_order(e.kind), e.name))
    return {
        "version": _FORMAT_VERSION,
        "entities": [e.as_dict() for e in ordered],
    }


def _kind_order(kind: str) -> tuple[int, str]:
    """Sort key putting the known kinds in report order and any other kind last.

    A pin file is read back from disk, so it can name a kind this build does not
    know. That is not a reason to refuse it or to crash sorting it.
    """
    return (KINDS.index(kind), "") if kind in KINDS else (len(KINDS), kind)


def _fields(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise PinError('a pin entry\'s "fields" must be an object')
    out: dict[str, str] = {}
    for path, dg in value.items():
        if not isinstance(path, str) or not isinstance(dg, str) or not dg:
            raise PinError("a pin entry has a field with no digest")
        out[path] = dg
    return out


def load_pin(path: str) -> list[PinnedEntity]:
    """Read a pin file into its entities, in file order."""
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise PinError(f"not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PinError("pin must be a JSON object")
    version = data.get("version")
    if version != _FORMAT_VERSION:
        raise PinError(
            f"unsupported pin version {version!r}, expected {_FORMAT_VERSION}"
        )
    entities = data.get("entities")
    if not isinstance(entities, list):
        raise PinError('pin "entities" must be a list')

    loaded: list[PinnedEntity] = []
    for entry in entities:
        if not isinstance(entry, dict):
            raise PinError("each pin entry must be an object")
        kind, name = entry.get("kind"), entry.get("name")
        if not isinstance(kind, str) or not isinstance(name, str):
            raise PinError('a pin entry is missing its "kind" or "name"')
        source = entry.get("source")
        if source is not None and not isinstance(source, str):
            raise PinError('a pin entry\'s "source" must be a string')
        loaded.append(
            PinnedEntity(
                kind=kind,
                name=name,
                fields=_fields(entry.get("fields")),
                source=source,
            )
        )
    return loaded


@dataclass(frozen=True)
class Drift:
    """One way the current metadata differs from the pin."""

    kind: str
    name: str
    change: str  # "changed", "added" or "removed"
    # The JSON paths that differ, on a "changed" drift only, and never empty
    # there: an entity that differs nowhere is not reported at all.
    paths: tuple[str, ...] = ()
    # Which server this entity belongs to, on a --config run only.
    source: str | None = None

    @property
    def label(self) -> str:
        where = f"{self.kind} {self.name}"
        # A whole-config pin can hold two entities that differ only by which
        # server declared them, so a drift on one names it. Left off entirely
        # for a single-server scan, which reads as it always has.
        if self.source is not None:
            where = f"{self.source}: {where}"
        if self.change != "changed":
            return f"{where}  {self.change} since the pin"
        listed = ", ".join(self.paths[:_MAX_LISTED_PATHS])
        extra = len(self.paths) - _MAX_LISTED_PATHS
        if extra > 0:
            listed += f" and {extra} more field(s)"
        return f"{where}  changed: {listed}"

    def as_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {"kind": self.kind, "name": self.name}
        if self.source is not None:
            entry["source"] = self.source
        entry["change"] = self.change
        entry["paths"] = list(self.paths)
        return entry


_Key = tuple[str | None, str, str]


def _grouped(entities: Sequence[PinnedEntity]) -> dict[_Key, list[PinnedEntity]]:
    """Bucket entities by (source, kind, name), keeping listing order in a bucket.

    MCP names are meant to be unique per kind, but a manifest is a file and can
    hold two tools called the same thing. Bucketing rather than keying by name
    means the second one is compared and reported instead of silently replacing
    the first, which is the shape an attacker would use to hide one.

    The server is part of the key because two servers in one config can each
    declare a tool called ``search``, and the text approved for one is not an
    approval of the other's.
    """
    buckets: dict[_Key, list[PinnedEntity]] = {}
    for entity in entities:
        buckets.setdefault((entity.source, entity.kind, entity.name), []).append(entity)
    return buckets


def _display(source: str | None) -> str:
    """How a server name is written in a message about the pin file itself.

    The name is returned exactly as the pin recorded it: the unchecked list is
    a data surface (--json carries it as pinUnchecked), so it keeps the text the
    server was configured under. A message built for a human has to escape it
    with render_visible instead, because a PinError's text is printed as a line
    of rune's own prose and a newline in a name would let the pin file write
    lines of the report.
    """
    return "(no server recorded)" if source is None else source


def scope_pin(
    pinned: Sequence[PinnedEntity], scanned: Sequence[str] | None
) -> tuple[list[PinnedEntity], list[str]]:
    """Line a pin up with the servers this run actually scanned.

    Returns the entities to compare and the names of the pinned servers this run
    did not cover. Those are left out of the comparison rather than reported as
    removed: a run narrowed with --server, a server the config switched off, and
    a server that has been taken out of the config entirely all mean rune did not
    look, and "I did not look" is not "it is gone". The caller names them, so a
    partial check is never mistaken for a whole one.

    A pin that names no server at all is one written from a scan of a single
    server, by this build or any earlier one. It is adopted by the one server a
    run scanned, which is the comparison it was written for and keeps every pin
    on disk working. Judged against several servers there is nothing to adopt it,
    so the run is refused rather than being told every entity was removed.
    """
    if not pinned:
        return [], []

    sources = {e.source for e in pinned}
    if scanned is None:
        # A scan of one unnamed server: a manifest, --stdio, --http or --sse.
        # Names in the pin cannot discriminate anything here, so they are dropped
        # and the comparison is the one it has always been, unless the file
        # describes more than one server, which this run cannot be.
        if len(sources) > 1:
            named = ", ".join(sorted(render_visible(_display(s)) for s in sources))
            raise PinError(
                f"this pin covers {len(sources)} servers ({named}); "
                "judge it with --config, adding --server NAME to pick one out of it"
            )
        return [replace(e, source=None) for e in pinned], []

    covered = set(scanned)
    if sources == {None}:
        if len(covered) != 1:
            raise PinError(
                "this pin was written from a scan of a single server and does not "
                "name one; add --server NAME to say which server in the config it "
                "describes, or re-run with --write-pin to pin them all"
            )
        return [replace(e, source=next(iter(covered))) for e in pinned], []

    comparable = [e for e in pinned if e.source in covered]
    unchecked = sorted(_display(s) for s in sources if s not in covered)
    if not comparable:
        # Escaped here rather than in unchecked itself: the message is prose,
        # the returned list is data and keeps the exact names.
        raise PinError(
            "this pin names no server this run scanned; it covers "
            + ", ".join(render_visible(n) for n in unchecked)
        )
    return comparable, unchecked


def _changed_paths(old: dict[str, str], new: dict[str, str]) -> tuple[str, ...]:
    return tuple(sorted(p for p in old.keys() | new.keys() if old.get(p) != new.get(p)))


def pin_drift(
    pinned: Sequence[PinnedEntity], current: Sequence[PinnedEntity]
) -> list[Drift]:
    """Every difference between a pin and the current scan, in report order.

    Removal counts. A pin is a statement that the server is the one that was
    reviewed, and a tool that disappeared is not the same server, even though a
    missing tool cannot poison anything by itself. Reporting it is also what
    makes the vanish-and-return trick visible, where a tool is pulled from a
    listing while it is being audited and put back afterwards.

    Pass ``pinned`` through :func:`scope_pin` first on a run that covers a
    config, so a server this run did not scan is not read as a server whose
    every entity was removed.
    """
    old, new = _grouped(pinned), _grouped(current)
    drifts: list[Drift] = []
    keys = sorted(
        old.keys() | new.keys(), key=lambda k: (k[0] or "", _kind_order(k[1]), k[2])
    )
    for key in keys:
        source, kind, name = key
        befores, afters = old.get(key, []), new.get(key, [])
        for i in range(max(len(befores), len(afters))):
            if i >= len(afters):
                drifts.append(Drift(kind, name, "removed", source=source))
            elif i >= len(befores):
                drifts.append(Drift(kind, name, "added", source=source))
            else:
                paths = _changed_paths(befores[i].fields, afters[i].fields)
                if paths:
                    drifts.append(Drift(kind, name, "changed", paths, source=source))
    return drifts
