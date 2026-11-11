"""``python -m controlarm.cli``, for a checkout with no console script installed.

The supported entry point is the console script ``controlarm``. This exists so
the same code path can be reached before an install, and it returns the same
exit code: a module invocation that silently differed from the installed command
would be a second instrument reporting a different answer.
"""

from __future__ import annotations

from controlarm.cli.commands import main

if __name__ == "__main__":
    raise SystemExit(main())
