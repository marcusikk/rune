"""Pagination in the live client, tested with no SDK and no subprocess.

_collect reaches the session through four listing calls and the nextCursor
attribute on their results, so a stub session is enough to prove every page is
fetched, a cursor loop is refused, and an SDK too old to pass a cursor gets an
actionable message instead of a bare TypeError. The live half, a real stdio
server that actually pages its tools/list, is in test_client_e2e.py.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from rune.client import LiveScanError, _collect, _list_all


class _Item:
    def __init__(self, name: str, description: str = "") -> None:
        self._data = {"name": name, "description": description}

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return dict(self._data)


class _Page:
    def __init__(self, field: str, names: list[str], next_cursor: str | None = None) -> None:
        setattr(self, field, [_Item(n) for n in names])
        self.nextCursor = next_cursor


def _pager(field: str, pages: dict[str | None, _Page]):
    """A listing method serving *pages* keyed by cursor, recording each call.

    The first page sits under the key None; every call's keyword arguments are
    recorded so a test can assert the first request carries no cursor at all,
    which is what keeps an unpaginated scan identical on any SDK. The call cap
    turns a regressed loop guard into a fast failure instead of a hung test.
    """
    calls: list[dict[str, Any]] = []

    async def method(**kwargs: Any) -> _Page:
        calls.append(dict(kwargs))
        if len(calls) > 10:
            raise AssertionError("listing was fetched more than 10 times: loop guard gone?")
        return pages[kwargs.get("cursor")]

    return method, calls


def test_every_page_is_fetched_in_file_order() -> None:
    method, calls = _pager(
        "tools",
        {
            None: _Page("tools", ["a", "b"], "c1"),
            "c1": _Page("tools", ["c"], "c2"),
            "c2": _Page("tools", ["d"]),
        },
    )
    items = asyncio.run(_list_all(method, "tools", "tools"))
    assert [i.model_dump()["name"] for i in items] == ["a", "b", "c", "d"]
    assert calls == [{}, {"cursor": "c1"}, {"cursor": "c2"}]


def test_single_page_makes_one_cursorless_call() -> None:
    method, calls = _pager("tools", {None: _Page("tools", ["a"])})
    items = asyncio.run(_list_all(method, "tools", "tools"))
    assert len(items) == 1
    assert calls == [{}]


def test_repeated_cursor_is_refused_after_two_calls() -> None:
    # A server can answer every request with the same cursor again. Following
    # it forever turns the scan into a stall the timeout has to kill; rune
    # names the behaviour instead, and does not quote the server-supplied
    # cursor into its own message.
    method, calls = _pager(
        "tools",
        {
            None: _Page("tools", ["a"], "again"),
            "again": _Page("tools", ["a"], "again"),
        },
    )
    with pytest.raises(LiveScanError) as excinfo:
        asyncio.run(_list_all(method, "tools", "tools"))
    assert "repeats a pagination cursor" in str(excinfo.value)
    assert "again" not in str(excinfo.value)
    assert len(calls) == 2


def test_endless_distinct_cursors_are_bounded_by_the_page_cap() -> None:
    # A server can hand back a fresh, never-repeated cursor on every page. The
    # circular-cursor guard never fires because nothing is seen twice, so
    # _list_all carries its own page bound: it stops with a named refusal after
    # _MAX_LISTING_PAGES cursors instead of running until the scan timeout. The
    # timeout path is the one the reviewer saw reach the user as "unhandled
    # errors in a TaskGroup" when a teardown race masks it, so it must not be
    # what ends this listing.
    from rune.client import _MAX_LISTING_PAGES

    calls = 0

    async def method(**kwargs: Any) -> _Page:
        nonlocal calls
        calls += 1
        return _Page("tools", ["a"], f"c{calls}")  # a distinct cursor every time

    with pytest.raises(LiveScanError) as excinfo:
        asyncio.run(_list_all(method, "tools", "tools"))
    message = str(excinfo.value)
    assert "did not end after" in message
    assert "repeats a pagination cursor" not in message  # not the circular guard
    assert str(_MAX_LISTING_PAGES) in message
    # Bounded: it stopped itself rather than paging forever, and no server-supplied
    # cursor text leaked into the message.
    assert calls <= _MAX_LISTING_PAGES + 1
    assert "c1" not in message


def test_empty_string_cursor_is_followed_then_refused_on_repeat() -> None:
    # "" is not None, so a spec-shaped client sends it back rather than
    # stopping. rune does the same, and the loop guard is what ends it when
    # the server never moves on.
    method, calls = _pager(
        "tools",
        {
            None: _Page("tools", ["a"], ""),
            "": _Page("tools", ["b"], ""),
        },
    )
    with pytest.raises(LiveScanError):
        asyncio.run(_list_all(method, "tools", "tools"))
    assert calls == [{}, {"cursor": ""}]


def test_old_sdk_without_cursor_parameter_gets_a_named_fix() -> None:
    # mcp<1.9 has no cursor parameter on the listing calls. Against a server
    # that does paginate, the raw failure would be "unexpected keyword
    # argument", which blames rune's code for a version gap with a one-line
    # fix, so the message names the fix instead.
    async def method() -> _Page:  # accepts no cursor, like an old SDK
        return _Page("tools", ["a"], "c1")

    with pytest.raises(LiveScanError) as excinfo:
        asyncio.run(_list_all(method, "tools", "tools"))
    assert "mcp>=1.9" in str(excinfo.value)


class _Err(Exception):
    """Stands in for McpError, which _collect only ever sees as a type."""


def _session(**methods: Any) -> SimpleNamespace:
    async def initialize() -> SimpleNamespace:
        return SimpleNamespace(
            capabilities=SimpleNamespace(
                prompts=object() if "list_prompts" in methods else None,
                resources=object() if "list_resources" in methods else None,
            ),
            instructions=None,
            serverInfo=None,
        )

    return SimpleNamespace(initialize=initialize, **methods)


def test_collect_merges_every_tools_page() -> None:
    method, _ = _pager(
        "tools",
        {
            None: _Page("tools", ["add"], "p2"),
            "p2": _Page("tools", ["sync_notes"]),
        },
    )
    groups = asyncio.run(_collect(_session(list_tools=method), _Err))
    assert [t["name"] for t in groups["tool"]] == ["add", "sync_notes"]


def test_collect_pages_resources_and_templates_alike() -> None:
    tools, _ = _pager("tools", {None: _Page("tools", [])})
    resources, _ = _pager(
        "resources",
        {
            None: _Page("resources", ["r1"], "more"),
            "more": _Page("resources", ["r2"]),
        },
    )
    templates, _ = _pager(
        "resourceTemplates",
        {
            None: _Page("resourceTemplates", ["t1"], "more"),
            "more": _Page("resourceTemplates", ["t2"]),
        },
    )
    groups = asyncio.run(
        _collect(
            _session(
                list_tools=tools,
                list_resources=resources,
                list_resource_templates=templates,
            ),
            _Err,
        )
    )
    assert [r["name"] for r in groups["resource"]] == ["r1", "r2", "t1", "t2"]


def test_prompts_error_on_a_later_page_still_reads_as_none() -> None:
    # A server that advertises prompts and then fails to list them is treated
    # as having none; that rule predates pagination and a failure on page two
    # keeps it, so the two paths cannot disagree about what an McpError means.
    tools, _ = _pager("tools", {None: _Page("tools", [])})

    async def prompts(**kwargs: Any) -> _Page:
        if kwargs.get("cursor") is None:
            return _Page("prompts", ["greet"], "p2")
        raise _Err("listing broke")

    groups = asyncio.run(_collect(_session(list_tools=tools, list_prompts=prompts), _Err))
    assert groups["prompt"] == []


def test_prompts_cursor_loop_is_a_refusal_not_an_empty_listing() -> None:
    # The McpError swallow must not eat the loop guard: a listing rune chose
    # to stop following is not "no prompts", it is a server it could not
    # finish reading, and reporting less than the server serves is the exact
    # miss this module exists to prevent.
    tools, _ = _pager("tools", {None: _Page("tools", [])})
    prompts, _ = _pager(
        "prompts",
        {
            None: _Page("prompts", ["greet"], "again"),
            "again": _Page("prompts", ["greet"], "again"),
        },
    )
    with pytest.raises(LiveScanError):
        asyncio.run(_collect(_session(list_tools=tools, list_prompts=prompts), _Err))
