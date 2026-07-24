"""The rules that decide where a scan's credentials are allowed to go.

No socket and no SDK: this is the arithmetic of "is that still the endpoint I
was pointed at", which is worth pinning on its own because the live tests can
only ever exercise the couple of shapes a loopback server can produce. The
end-to-end proof that a header does not reach a second origin is in
tests/test_redirect_e2e.py.
"""

from __future__ import annotations

import pytest

from rune.client import (
    LiveScanError,
    _client_factory,
    _origin,
    _OriginLock,
    _show_origin,
    _stays_on_origin,
)

_TOKEN = "s3cret-api-key-value"

# https://mcp.example.com/mcp, the endpoint a user handed rune.
_TARGET = ("https", "mcp.example.com", 443)


@pytest.mark.parametrize(
    "destination",
    [
        _TARGET,
        ("https", "mcp.example.com", 443),  # the default port written out
    ],
)
def test_a_redirect_that_stays_put_keeps_the_credentials(
    destination: tuple[str, str, int]
) -> None:
    # A different path on one origin is not a move: an endpoint that redirects
    # /entry to /mcp on itself is ordinary, and the origin triple ignores paths.
    assert _stays_on_origin(_TARGET, destination)


@pytest.mark.parametrize(
    "destination",
    [
        ("https", "collector.tk", 443),  # another host
        ("https", "mcp.example.com.evil.tk", 443),  # a host that only looks like it
        ("https", "mcp", 443),  # a prefix of it
        ("https", "mcp.example.com", 8443),  # another port on the same host
        ("http", "mcp.example.com", 80),  # the same host, downgraded to cleartext
    ],
)
def test_a_redirect_that_leaves_does_not_keep_the_credentials(
    destination: tuple[str, str, int]
) -> None:
    assert not _stays_on_origin(_TARGET, destination)


def test_a_plain_to_tls_upgrade_of_one_host_is_not_a_hand_off() -> None:
    # httpx's own exception, mirrored: the credential still reaches the host it
    # was meant for, over a better transport. Refusing it would break every
    # endpoint that answers port 80 with a redirect to itself on 443, which is
    # most of them, and buy nothing.
    plain = ("http", "mcp.example.com", 80)
    assert _stays_on_origin(plain, _TARGET)
    # Not the other way round: that puts the token on the wire in the clear.
    assert not _stays_on_origin(_TARGET, plain)
    # And not to some other host that happens to be on 443.
    assert not _stays_on_origin(plain, ("https", "collector.tk", 443))


@pytest.mark.parametrize(
    ("origin", "shown"),
    [
        (("https", "collector.tk", 443), "https://collector.tk"),
        (("http", "collector.tk", 80), "http://collector.tk"),
        (("https", "collector.tk", 8443), "https://collector.tk:8443"),
    ],
)
def test_the_refusal_names_an_origin_and_nothing_more(
    origin: tuple[str, str, int], shown: str
) -> None:
    # No path and no query string. This string is printed to a terminal and into
    # a CI log, and a query string is exactly where a token gets embedded.
    assert _show_origin(origin) == shown


def test_an_ipv6_literal_is_written_the_way_a_url_writes_it() -> None:
    # httpx hands back a bare v6 address, so the brackets are this function's
    # job. Unbracketed it reads as a host called "::1" with a port of 8080
    # hanging off the last colon, which is not an address anybody can act on.
    assert _show_origin(("http", "::1", 8080)) == "http://[::1]:8080"
    assert _show_origin(("https", "2001:db8::1", 443)) == "https://[2001:db8::1]"


def test_a_scan_with_no_credentials_installs_no_lock() -> None:
    assert not _OriginLock("https://mcp.example.com/mcp", {}).active
    assert _OriginLock("https://mcp.example.com/mcp", {"X-Api-Key": _TOKEN}).active


def _old_transport(url: str, headers: object = None, timeout: float = 1.0) -> None:
    """Stands in for an mcp release from before httpx_client_factory existed."""


def test_an_unlocked_scan_asks_the_transport_for_nothing_extra() -> None:
    # The keyword is passed only when there is a credential to protect, which is
    # what keeps an anonymous scan working on an SDK that never grew the hook.
    assert _client_factory(_old_transport, _OriginLock("https://x.example/mcp", {})) == {}


def test_an_sdk_too_old_to_lock_is_named_rather_than_scanned_anyway() -> None:
    # Scanning without the lock because the SDK is old would be the leak this
    # exists to close, quietly. The refusal has to say what to upgrade.
    lock = _OriginLock("https://x.example/mcp", {"X-Api-Key": _TOKEN})
    with pytest.raises(LiveScanError) as raised:
        _client_factory(_old_transport, lock)

    assert "mcp>=1.10" in str(raised.value)
    assert _TOKEN not in str(raised.value)


def test_the_refusal_never_carries_the_url_it_was_given() -> None:
    lock = _OriginLock(f"https://user:{_TOKEN}@mcp.example.com/mcp?key={_TOKEN}", {})
    lock.left_for = "https://collector.tk"
    with pytest.raises(LiveScanError) as raised:
        lock.check()

    assert _TOKEN not in str(raised.value)
    assert "https://collector.tk" in str(raised.value)


def test_a_lock_that_saw_nothing_leave_says_nothing() -> None:
    _OriginLock("https://mcp.example.com/mcp", {"X-Api-Key": _TOKEN}).check()


# --- parsing, which is httpx's job ------------------------------------------


def _triple(url: str) -> tuple[str, str, int]:
    httpx = pytest.importorskip("httpx")
    return _origin(httpx.URL(url))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://mcp.example.com/mcp", _TARGET),
        ("http://mcp.example.com/mcp", ("http", "mcp.example.com", 80)),
        ("https://mcp.example.com:8443/mcp", ("https", "mcp.example.com", 8443)),
        # One host spelled two ways is one origin, or a redirect that only
        # changed the case of a hostname would read as a hand-off.
        ("https://MCP.Example.COM/mcp", _TARGET),
        # The IDNA form, not the Unicode one: this triple gets printed back, and
        # a look-alike hostname does not belong in a line of rune's own prose.
        ("https://über.example/mcp", ("https", "xn--ber-goa.example", 443)),
    ],
)
def test_origin_reads_scheme_host_and_port(url: str, expected: tuple[str, str, int]) -> None:
    assert _triple(url) == expected


def test_a_user_typed_host_and_a_redirect_to_it_compare_equal() -> None:
    # Both sides go through the same parser, so an endpoint typed in Unicode and
    # a redirect to its punycode spelling are the same place, not a hand-off.
    assert _stays_on_origin(_triple("https://über.example/mcp"), _triple("https://xn--ber-goa.example/mcp"))
