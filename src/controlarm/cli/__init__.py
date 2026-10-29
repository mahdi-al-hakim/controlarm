"""The command line.

``main`` is the console script entry point, wired in ``pyproject.toml`` as
``[project.scripts] controlarm = "controlarm.cli:main"``.

The modules here split along one line: ``commands`` is the only one that names
a stream, and every other one returns a value. ``exits`` holds the exit-code
contract, ``render`` the two renderers and the single ``print``, ``plan`` the
declarative plan format, ``selftest`` the instrument's own calibration,
``rules`` the rule-coverage derivation, and ``clock`` the single injectable
wall-clock read.

The dispatcher lives in ``commands.py`` rather than in ``main.py`` on purpose.
The entry point has to be reachable as the attribute ``controlarm.cli.main``, and
a submodule of that name would shadow it -- ``controlarm.cli.main`` would then
mean the function or the module depending on what had been imported first, which
is the kind of ambiguity that makes a patch in a test silently target the wrong
object.
"""

from __future__ import annotations

from controlarm.cli.commands import build_parser, main
from controlarm.cli.exits import Exit

__all__ = ["Exit", "build_parser", "main"]
