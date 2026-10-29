"""Helpers every probe shares, and the one check that makes the rest meaningful.

A probe that silently imported the *wrong* version would produce a perfectly
clean-looking run whose every number was attributed to code that never ran. That
is precisely the "the rig was not what you thought" failure this repository
exists to refuse, so it is checked rather than assumed: :func:`pinned_version`
is called by every probe's liveness arm, and a mismatch makes the liveness arm
fail, which makes the run ``VOID``.

Two independent things are asserted, because either alone can be fooled:

* the module was loaded **from the pin's own directory**, which is what actually
  matters and which no version string can establish; and
* the version is the expected one, read from distribution metadata **scoped to
  that directory**.

The scoping is not fussiness. An unscoped ``importlib.metadata.version`` call
searches the whole path and happily returns the ambient installation's number,
which is how the first run of this study reported PyYAML 6.0.1 while importing
the 5.3.1 source tree.
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import os

__all__ = ["attribute_names", "pinned_version"]


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _version_from(pin_dir: str, dist: str) -> str | None:
    """The version recorded by distribution metadata *inside* ``pin_dir`` only."""
    if not pin_dir or not os.path.isdir(pin_dir):
        return None
    want = _normalise(dist)
    for found in md.distributions(path=[pin_dir]):
        name = found.metadata["Name"] if found.metadata else None
        if name and _normalise(name) == want:
            return found.version
    return None


def _version_attr(module: object) -> str | None:
    for attribute in ("__version__", "version"):
        value = getattr(module, attribute, None)
        if isinstance(value, str) and value:
            return value
    return None


def pinned_version(dist: str, module_name: str, expected: str, pin_dir: str) -> str:
    """Import the module and confirm it is the pin the study thinks it is.

    Raises ``AssertionError`` on either mismatch. Returns the path the module was
    loaded from, so the arm's detail records *which* copy answered.
    """
    module = importlib.import_module(module_name)
    origin = getattr(module, "__file__", "") or ""
    if not origin:
        raise AssertionError(f"{module_name} has no __file__, so its provenance is unknown")

    resolved, pinned = os.path.realpath(origin), os.path.realpath(pin_dir)
    if os.path.commonpath([resolved, pinned]) != pinned:
        raise AssertionError(
            f"{module_name} was imported from {resolved!r}, which is outside the pin "
            f"directory {pinned!r}. The rig is not testing the version it claims."
        )

    found = _version_from(pin_dir, dist) or _version_attr(module)
    if found != expected:
        raise AssertionError(
            f"pin mismatch: expected {dist}=={expected} but the copy at {resolved!r} "
            f"reports {found!r}"
        )
    return origin


def attribute_names(tag: str) -> list[str]:
    """Attribute names in one HTML start tag, parsed rather than pattern-matched.

    The Jinja2 probes need to know whether rendering produced an attribute the
    template author never wrote. Searching the output for the payload text would
    be the catalogued FP#6 shape -- matching on a value the tester supplied -- so
    the tag is parsed with the standard library's own HTML parser and the oracle
    reads the resulting attribute *names*.
    """
    from html.parser import HTMLParser

    names: list[str] = []

    class Collect(HTMLParser):
        def handle_starttag(self, tag_name: str, attrs: list) -> None:
            names.extend(name for name, _ in attrs)

    parser = Collect(convert_charrefs=True)
    parser.feed(tag)
    parser.close()
    return names
