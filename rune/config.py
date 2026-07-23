"""Read an MCP client's config file and turn its entries into scan targets.

Nobody wires up one MCP server. A working agent setup is a config file with half
a dozen entries in it, and until now auditing that meant reading the file,
copying each command and its arguments out by hand, and running rune once per
server. The step people actually skip is the copying, so the servers that never
got scanned were the ones nobody could be bothered to transcribe. This module
reads the file rune's users already have and hands the CLI the list.

The shape is the same across the clients that matter: a top-level object mapping
a name to a definition, under ``mcpServers`` (Claude Desktop, Claude Code,
Cursor, Windsurf) or ``servers`` (VS Code). A definition is either local, with a
``command`` plus optional ``args``/``env``/``cwd``, or remote, with a ``url``
plus optional ``headers``.

The file is read as JSONC. VS Code documents and writes ``mcp.json`` with
comments in it, and a config carrying a note above an entry is a working config
for the client that reads it, so refusing to audit it was rune's problem rather
than the reader's.

Parsing is deliberately split from connecting. This module never opens a socket
or starts a process; it validates the file and reports what it found. That is
what lets the whole config be checked before the first server is launched, and
it is what makes the parser testable without the mcp SDK installed.

One entry's problem is that entry's problem. A definition rune cannot read is
recorded on its own :class:`ServerSpec` as an ``error`` rather than raised, so a
single mistyped entry cannot cancel the audit of the five servers beside it.
Only a file-level problem, one that leaves no list of servers to work from at
all, raises :class:`ConfigError`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .scan import render_visible

# The two spellings of the server map, in the order they are read. A file may
# legally carry only one; a name defined under both is refused rather than
# silently resolved, since the two definitions can differ.
_SERVER_MAPS = ("mcpServers", "servers")

# Transport names a config may declare, mapped onto the three rune speaks.
# "streamable-http" and its variants are the spec's own name for what rune calls
# http, and clients write it every way punctuation allows.
_TRANSPORTS = {
    "stdio": "stdio",
    "local": "stdio",
    "http": "http",
    "streamable-http": "http",
    "streamable_http": "http",
    "streamablehttp": "http",
    "sse": "sse",
}


class ConfigError(ValueError):
    """Raised when a config file has no list of servers rune can work from."""


def _quoted(text: str) -> str:
    """Name a config-supplied string inside a message rune prints.

    The names and values here come out of a file, so they are quoted the way an
    entity name is in the report: escaped, never interpolated raw. A server named
    with an embedded newline must not be able to write a line of rune's output.
    """
    return f"'{render_visible(text)}'"


@dataclass(frozen=True)
class ServerSpec:
    """One server entry, either ready to scan or carrying the reason it is not.

    Exactly one of three states. ``error`` set means the definition could not be
    read and the entry is reported as a failure without anything being launched.
    ``disabled`` means the config itself switched it off. Otherwise ``transport``
    says which of the three connectors to use and the matching fields are filled.
    """

    name: str
    transport: str = ""
    command: str = ""
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    disabled: bool = False
    error: str | None = None

    @property
    def label(self) -> str:
        """How this entry is named in the report, transport-first.

        An entry whose definition rune could not read has no transport to name,
        so it says that instead of guessing one.
        """
        return "unreadable" if self.error is not None else self.transport


def _string_list(value: Any, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f'"{what}" must be a list of strings')
    return tuple(value)


def _string_map(value: Any, what: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        # A number where a string belongs is the common typo ("PORT": 8080).
        # Refusing beats coercing: the value is fed to a process rune is about to
        # start, and guessing what the author meant is not rune's call.
        raise ValueError(f'"{what}" must be an object mapping strings to strings')
    return dict(value)


def _transport_from_url(url: str) -> str:
    """Guess the transport of a remote entry that did not declare one.

    Only the two-endpoint SSE transport has a conventional path, so a URL ending
    in /sse is read as SSE and everything else as Streamable HTTP, which is what
    a current server speaks. A config that means otherwise says so with "type".
    """
    from urllib.parse import urlsplit

    path = urlsplit(url).path.rstrip("/")
    return "sse" if path.endswith("/sse") else "http"


def _parse_entry(name: str, entry: Any) -> ServerSpec:
    """Read one server definition, recording its own problem rather than raising."""
    try:
        return _read_entry(name, entry)
    except ValueError as exc:
        return ServerSpec(name=name, error=str(exc))


def _read_entry(name: str, entry: Any) -> ServerSpec:
    if not isinstance(entry, dict):
        raise ValueError("definition must be an object")

    disabled = entry.get("disabled") is True
    declared = entry.get("type", entry.get("transport"))
    transport: str | None = None
    if declared is not None:
        if not isinstance(declared, str):
            raise ValueError('"type" must be a string')
        transport = _TRANSPORTS.get(declared.strip().lower())
        if transport is None:
            raise ValueError(
                f"unknown transport {_quoted(declared)}; rune speaks stdio, http and sse"
            )

    has_command = entry.get("command") is not None
    has_url = entry.get("url") is not None
    if has_command and has_url:
        raise ValueError(
            'has both a "command" and a "url"; a server is either local or remote'
        )
    if transport is None:
        if has_command:
            transport = "stdio"
        elif has_url:
            transport = _transport_from_url(str(entry["url"]))
        else:
            raise ValueError('needs a "command" (stdio) or a "url" (http or sse)')

    if transport == "stdio":
        if not has_command:
            raise ValueError('type "stdio" needs a "command"')
        command = entry["command"]
        if not isinstance(command, str) or not command.strip():
            raise ValueError('"command" must be a non-empty string')
        cwd = entry.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError('"cwd" must be a string')
        return ServerSpec(
            name=name,
            transport="stdio",
            command=command,
            args=_string_list(entry.get("args"), "args"),
            env=_string_map(entry.get("env"), "env"),
            cwd=cwd,
            disabled=disabled,
        )

    if not has_url:
        raise ValueError(f'type "{transport}" needs a "url"')
    url = entry["url"]
    if not isinstance(url, str) or not url.strip():
        raise ValueError('"url" must be a non-empty string')
    return ServerSpec(
        name=name,
        transport=transport,
        url=url,
        headers=_string_map(entry.get("headers"), "headers"),
        disabled=disabled,
    )


def parse_config(data: Any) -> list[ServerSpec]:
    """Turn a parsed config document into its server entries, in file order.

    File order is kept so the report reads in the order the config is written,
    which is the order the reader already knows.
    """
    if not isinstance(data, dict):
        raise ConfigError(
            'config must be a JSON object with an "mcpServers" or "servers" map'
        )

    specs: list[ServerSpec] = []
    seen: dict[str, str] = {}
    found_map = False
    for key in _SERVER_MAPS:
        block = data.get(key)
        if block is None:
            continue
        if not isinstance(block, dict):
            raise ConfigError(
                f'"{key}" must be an object mapping a server name to its definition'
            )
        found_map = True
        for name, entry in block.items():
            if name in seen:
                raise ConfigError(
                    f"server {_quoted(name)} is defined under both "
                    f'"{seen[name]}" and "{key}"'
                )
            seen[name] = key
            specs.append(_parse_entry(name, entry))

    if not found_map:
        raise ConfigError(
            'config has no "mcpServers" or "servers" map; point --config at an '
            "MCP client config file, not at a tools manifest"
        )
    return specs


# --- JSONC ------------------------------------------------------------------
#
# Two scans, each jumping between the characters that can change what the reader
# is looking at, so a large file stays linear. Both are quote-aware, which is the
# whole difficulty: the "//" in a URL and the comma in a description are not
# syntax, and a reader that treats them as syntax corrupts a valid config.

# The only characters that can open a comment or a string.
_COMMENT_OR_STRING = re.compile(r'["/]')
# Inside a string, the only two that matter: the closing quote and the backslash
# that stops the next character from being one.
_STRING_END = re.compile(r'["\\]')
# The four characters JSON counts as whitespace. Anything else is a token, and
# every token is significant to where a trailing comma sits.
_SIGNIFICANT = re.compile(r"[^ \t\n\r]")


def _end_of_string(text: str, quote: int) -> int:
    """Index just past the string literal opening at *quote*.

    An unterminated string runs to the end of the file. Returning that leaves
    everything after it untouched, so json reports the unterminated string at its
    real position instead of rune mangling the rest of the file first.
    """
    i = quote + 1
    while True:
        m = _STRING_END.search(text, i)
        if m is None:
            return len(text)
        if m.group() == '"':
            return m.end()
        i = m.end() + 1  # a backslash escapes whatever follows it, quote included


def _blank(chars: list[str], start: int, end: int) -> None:
    """Overwrite a span with spaces, keeping its line breaks.

    Every offset in the file survives, so a syntax error further down is still
    reported at the line and column it occupies in the file the reader has open.
    """
    for i in range(start, end):
        if chars[i] not in "\r\n":
            chars[i] = " "


def _strip_comments(text: str) -> str:
    chars = list(text)
    i = 0
    while (m := _COMMENT_OR_STRING.search(text, i)) is not None:
        at = m.start()
        if text[at] == '"':
            i = _end_of_string(text, at)
            continue
        after = text[at + 1 : at + 2]
        if after == "/":
            end = text.find("\n", at)
            end = len(text) if end == -1 else end
            _blank(chars, at, end)
            i = end
        elif after == "*":
            close = text.find("*/", at + 2)
            if close == -1:
                # Blanking to the end of the file would report the error as a
                # truncated config, which sends the reader looking at the wrong
                # end of it. Name the comment that never closed instead.
                line = text.count("\n", 0, at) + 1
                raise ConfigError(f"unterminated block comment opened on line {line}")
            _blank(chars, at, close + 2)
            i = close + 2
        else:
            # A lone slash opens nothing and is not valid JSON either. Leaving it
            # in place keeps json's error pointed at the character that caused it.
            i = at + 1
    return "".join(chars)


def _strip_trailing_commas(text: str) -> str:
    """Drop each comma that closes a list or an object, on comment-free text.

    Only a comma that follows a value is dropped. A comma with nothing in front
    of it is not a trailing comma but a missing element, so ``{,}`` and ``[1,,]``
    stay the errors they are rather than being quietly read as something else.
    """
    chars = list(text)
    previous = ""  # the significant character before the one being read
    comma = -1  # a comma waiting to find out what follows it
    i = 0
    while (m := _SIGNIFICANT.search(text, i)) is not None:
        at = m.start()
        char = text[at]
        if char == '"':
            previous, comma, i = '"', -1, _end_of_string(text, at)
            continue
        if char == ",":
            comma = at if previous not in ("", "{", "[", ",") else -1
        elif char in "}]" and comma != -1:
            chars[comma] = " "
            comma = -1
        else:
            comma = -1
        previous = char
        i = at + 1
    return "".join(chars)


def strip_jsonc(text: str) -> str:
    """Read JSONC as the JSON underneath it, character offsets intact.

    Comments become spaces and a trailing comma becomes a space, so the result is
    the same length as the file and every line break is where it was. Text that
    is already plain JSON comes back unchanged.
    """
    return _strip_trailing_commas(_strip_comments(text))


def load_config(path: str) -> list[ServerSpec]:
    """Read a config file from disk into its server entries."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = strip_jsonc(text)
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"not valid JSON: {exc} (comments and trailing commas are read, so "
            "this is something else)"
        ) from exc
    return parse_config(data)


def select(specs: list[ServerSpec], names: list[str]) -> list[ServerSpec]:
    """Narrow the entries to the named ones, keeping config order.

    A name that matches nothing raises. Scanning fewer servers than were asked
    for and still reporting on them is the failure mode worth avoiding here: a
    typo in a --server would otherwise read as a clean audit of a server that was
    never opened.
    """
    if not names:
        return list(specs)
    known = {spec.name for spec in specs}
    missing = [n for n in names if n not in known]
    if missing:
        raise ConfigError(
            "no server named " + ", ".join(_quoted(n) for n in missing) + " in the config"
        )
    wanted = set(names)
    return [spec for spec in specs if spec.name in wanted]
