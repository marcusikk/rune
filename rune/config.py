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

Placeholders are resolved for the same reason. A committed config does not hold
the token its server needs, it holds ``${GITHUB_TOKEN}``, and a VS Code entry
points at ``${workspaceFolder}`` rather than at an absolute path. Passing those
through as written starts a different server from the one the client starts, or
no server at all, so rune fills them in from its own environment and from where
the config file sits. A placeholder only the client can answer, or a variable
nothing has set, is that entry's own error: never a guess, and never an empty
string standing in for a value that mattered.

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
import os
import re
from collections.abc import Mapping
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


# --- variables --------------------------------------------------------------
#
# A config does not hold the values it needs, it holds placeholders the client
# fills in: an API key out of the environment, a path relative to the folder the
# editor has open. Passing those through as written starts a server with the
# literal text "${GITHUB_TOKEN}" where its credential belongs, or a command at a
# path that does not exist, so the entry fails and drops out of the audit. rune
# resolves the same placeholders the client does, from its own environment and
# from where the config file sits.
#
# Two spellings, because the clients differ: VS Code writes ${env:NAME} and the
# path variables, Claude Code writes a bare ${NAME} with an optional
# ${NAME:-fallback}. Both are read wherever they turn up, since a file does not
# record which client wrote it and one project's servers are usually wired into
# more than one. A bare ${NAME} in a file whose own client happens to leave it
# alone still names the value its author meant, which is the server the audit is
# supposed to be about.

# One placeholder. Braces are excluded from the body so an unclosed "${" cannot
# run to the end of a value and swallow the placeholder after it.
_PLACEHOLDER = re.compile(r"\$\{([^{}]*)\}")
# What a bare ${...} has to look like before rune reads it as an environment
# variable. Anything else is left exactly as it was written: rune cannot know
# what "${.name}" means to the server it is about to start, and a value it does
# not understand is not a value it should rewrite.
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# The separator Claude Code uses between a variable and the value to fall back
# on when it is not set.
_FALLBACK = ":-"


@dataclass(frozen=True)
class _Variables:
    """What rune can put in place of a placeholder, and what it cannot.

    ``workspace`` is None when the config did not come from a file on disk,
    which is the one case where the path variables have nothing to resolve to.
    ``inputs`` maps a VS Code ``inputs`` id to its description, used only to say
    which prompt a refused entry was waiting on.
    """

    env: Mapping[str, str]
    workspace: str | None = None
    inputs: Mapping[str, str] = field(default_factory=dict)
    resolve: bool = True

    def expand(self, text: str, what: str) -> str:
        """Fill in every placeholder in one config value.

        ``what`` names the field for the message an unresolvable placeholder
        raises, e.g. ``"args[1]"``. The substitution is a single pass: a value
        that itself contains "${...}" is left as it came out of the environment,
        so a variable cannot expand into another variable and no config can
        drive rune round a loop.
        """
        if not self.resolve:
            return text
        return _PLACEHOLDER.sub(lambda m: self._value(m, what), text)

    def _value(self, match: re.Match[str], what: str) -> str:
        ref = match.group(1)
        name, separator, fallback = ref.partition(_FALLBACK)

        if name == "userHome":
            return os.path.expanduser("~")
        if name in ("workspaceFolder", "workspaceFolderBasename"):
            if self.workspace is None:
                raise ValueError(
                    f"{what} references {_placeholder(ref)}, but this config was "
                    "not read from a file, so there is no folder to resolve it to"
                )
            if name == "workspaceFolderBasename":
                return os.path.basename(self.workspace)
            return self.workspace
        if name.startswith("input:"):
            # The client stops and asks a person for this one. rune has nobody
            # to ask, and a guess would scan a server started with the wrong
            # credential and report the result as the audit of the real one.
            described = self.inputs.get(name[len("input:") :])
            detail = f" ({render_visible(described)})" if described else ""
            raise ValueError(
                f"{what} needs {_placeholder(ref)}{detail}, which the client "
                "prompts for and rune cannot supply"
            )
        if name.startswith("command:"):
            raise ValueError(
                f"{what} needs {_placeholder(ref)}, which only the editor that "
                "wrote this config can run"
            )

        explicit = name.startswith("env:")
        env_name = name[len("env:") :] if explicit else name
        # An explicit env: says outright that this is an environment variable,
        # so any name is taken at its word. A bare ${...} is only read as one
        # when it is shaped like a variable name, since it is also the syntax a
        # server's own arguments use for their own purposes.
        named = bool(env_name) if explicit else bool(_ENV_NAME.match(env_name))
        if not named:
            return match.group(0)
        value = self.env.get(env_name)
        if value:
            return value
        if separator:
            # ":-" is the shell's, and in the shell it covers a variable set to
            # nothing as well as one never set. A fallback declared beside a
            # variable that resolved to nothing is the case it was written for.
            return fallback
        if value is not None:
            # Set to empty with no fallback beside it: somebody chose that, and
            # it is how a scan gets past a variable whose value cannot change
            # what a server lists.
            return value
        # Substituting an empty string here is what the editors do, and it would
        # start a server that differs from the one the client starts, then report
        # the scan of it as the audit of the real thing. Naming the variable is
        # the only answer that does not overstate what was scanned.
        raise ValueError(
            f"{what} references {_placeholder(ref)}, which is not set in this "
            "environment; export it and re-run"
        )


# A disabled server is never started, so the values that would start it are
# never needed. Resolving them anyway would turn the variable somebody stopped
# exporting when they switched the server off into a failed audit of a server
# nothing is wired to.
_AS_WRITTEN = _Variables(env={}, resolve=False)


def _placeholder(ref: str) -> str:
    """A placeholder as it appears in the file, safe to print.

    The text inside the braces comes out of the config, so it is escaped like
    every other config-supplied string before it reaches a line of rune's prose.
    """
    return "${" + render_visible(ref) + "}"


def _read_inputs(data: dict[str, Any]) -> dict[str, str]:
    """Map each VS Code ``inputs`` id to its description, ignoring any junk.

    This is read only to make a refusal legible ("waiting on the Perplexity API
    Key prompt"), so a malformed entry costs the description and nothing else. A
    config is not worth refusing over the shape of a block rune never resolves.
    """
    block = data.get("inputs")
    if not isinstance(block, list):
        return {}
    described: dict[str, str] = {}
    for item in block:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            description = item.get("description")
            described[item["id"]] = description if isinstance(description, str) else ""
    return described


def _workspace_folder(path: str) -> str:
    """The folder a client would call the workspace root for a config at *path*.

    A VS Code config lives at ``<root>/.vscode/mcp.json``, so the root is the
    parent of the folder holding it; every other config sits at the root itself.
    Absolute, because that is what the placeholder stands for in the file: a
    relative --config path must not turn ${workspaceFolder} into an empty string.
    """
    folder = os.path.dirname(os.path.abspath(path))
    if os.path.basename(folder) == ".vscode":
        return os.path.dirname(folder)
    return folder


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


def _expanded_map(
    values: dict[str, str], what: str, variables: _Variables
) -> dict[str, str]:
    """Fill in the placeholders in a map's values, leaving its keys alone.

    A variable stands for a credential or a path, which is what a value holds. A
    key is the name the server reads it under, fixed by the server rather than
    by the machine rune runs on, so rewriting one would rename the setting.
    """
    return {
        key: variables.expand(value, f'"{what}" value for {_quoted(key)}')
        for key, value in values.items()
    }


def _parse_entry(name: str, entry: Any, variables: _Variables) -> ServerSpec:
    """Read one server definition, recording its own problem rather than raising."""
    try:
        return _read_entry(name, entry, variables)
    except ValueError as exc:
        return ServerSpec(name=name, error=str(exc))


def _read_entry(name: str, entry: Any, variables: _Variables) -> ServerSpec:
    if not isinstance(entry, dict):
        raise ValueError("definition must be an object")

    disabled = entry.get("disabled") is True
    if disabled:
        variables = _AS_WRITTEN
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
    # The URL is resolved before the transport is read off it, so a config that
    # keeps its endpoint in ${MCP_URL} is still recognised as SSE or HTTP by the
    # path it actually points at.
    url = entry.get("url")
    if isinstance(url, str):
        url = variables.expand(url, '"url"')
    if transport is None:
        if has_command:
            transport = "stdio"
        elif has_url:
            transport = _transport_from_url(str(url))
        else:
            raise ValueError('needs a "command" (stdio) or a "url" (http or sse)')

    if transport == "stdio":
        if not has_command:
            raise ValueError('type "stdio" needs a "command"')
        command = entry["command"]
        if isinstance(command, str):
            command = variables.expand(command, '"command"')
        if not isinstance(command, str) or not command.strip():
            raise ValueError('"command" must be a non-empty string')
        cwd = entry.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ValueError('"cwd" must be a string')
        args = _string_list(entry.get("args"), "args")
        return ServerSpec(
            name=name,
            transport="stdio",
            command=command,
            args=tuple(
                variables.expand(arg, f'"args[{i}]"') for i, arg in enumerate(args)
            ),
            env=_expanded_map(_string_map(entry.get("env"), "env"), "env", variables),
            cwd=cwd if cwd is None else variables.expand(cwd, '"cwd"'),
            disabled=disabled,
        )

    if not has_url:
        raise ValueError(f'type "{transport}" needs a "url"')
    if not isinstance(url, str) or not url.strip():
        raise ValueError('"url" must be a non-empty string')
    return ServerSpec(
        name=name,
        transport=transport,
        url=url,
        headers=_expanded_map(
            _string_map(entry.get("headers"), "headers"), "headers", variables
        ),
        disabled=disabled,
    )


def parse_config(data: Any, workspace: str | None = None) -> list[ServerSpec]:
    """Turn a parsed config document into its server entries, in file order.

    File order is kept so the report reads in the order the config is written,
    which is the order the reader already knows.

    ``workspace`` is the folder ${workspaceFolder} stands for, which only a
    config read from a file has; without one an entry that uses it records that
    as its own error rather than resolving to somewhere arbitrary.
    """
    if not isinstance(data, dict):
        raise ConfigError(
            'config must be a JSON object with an "mcpServers" or "servers" map'
        )

    variables = _Variables(os.environ, workspace, _read_inputs(data))
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
            specs.append(_parse_entry(name, entry, variables))

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
    return parse_config(data, workspace=_workspace_folder(path))


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
