"""CVE-2022-24761 -- waitress accepts a non-digit Content-Length (2.1.0 -> 2.1.1).

2.1.0 handed the raw header value to ``int()``, which accepts a leading ``+`` and
PEP 515 underscore separators. A front-end proxy that reads the header strictly
and a back-end that reads it with ``int()`` then disagree about where the request
ends, which is request smuggling.

Oracle, declared before execution: the parser reports no error and a numeric
``content_length`` for a header value that is not a digit string. Both halves
are read off the parser's own state, and the probe never opens a socket.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "waitress"
MODULE = "waitress"

#: '+5' and '5_0' are both accepted by int() and rejected by a digits-only rule.
_HOSTILE_LENGTHS = (b"+5", b"5_0")


def _parse(content_length: bytes) -> tuple[bool, int, str]:
    from waitress.adjustments import Adjustments
    from waitress.parser import HTTPRequestParser

    parser = HTTPRequestParser(Adjustments())
    request = (
        b"POST / HTTP/1.1\r\nHost: probe.invalid\r\nContent-Length: "
        + content_length
        + b"\r\n\r\nABCDE"
    )
    try:
        parser.received(request)
    except Exception as exc:
        return False, 0, f"{type(exc).__name__}: {exc}"
    error = parser.error
    name = type(error).__name__ if error is not None else "none"
    return error is None, int(parser.content_length or 0), name


def liveness(ctx: dict) -> tuple[bool, str]:
    """A plain digit Content-Length must parse, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    accepted, length, note = _parse(b"5")
    ok = accepted and length == 5
    return ok, (
        f"benign Content-Length: 5 -> accepted={accepted} length={length} error={note} "
        f"from {os.path.basename(origin)}"
    )


def control(ctx: dict) -> tuple[bool, str]:
    """A value no int() accepts must be REFUSED on both pins.

    Without this the probe could not tell "2.1.1 validates" from "2.1.1 happens
    to reject everything unusual".
    """
    accepted, length, note = _parse(b"0x5")
    return accepted, f"Content-Length: 0x5 -> accepted={accepted} length={length} error={note}"


def exploit(ctx: dict) -> tuple[bool, str]:
    details = []
    fired = False
    for value in _HOSTILE_LENGTHS:
        accepted, length, note = _parse(value)
        smuggled = accepted and length > 0
        fired = fired or smuggled
        details.append(f"{value.decode()!r}->accepted={accepted},length={length},error={note}")
    return fired, "; ".join(details)
