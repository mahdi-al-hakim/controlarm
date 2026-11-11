"""The CLI's only wall-clock read.

``tests/test_clock.py`` audits every module under ``src/controlarm`` and allows
a clock read only as the fallback half of ``injected or clock()``, then names
the exact set of files that contain one so a new reader has to be added to that
list deliberately. This module is the CLI's entry in that list, and it is the
only one: the subcommands that need the date or the time take it as a parameter
and the default comes from here.

The two functions are called ``stamp`` and ``date`` rather than ``now`` and
``today`` so that a call site reads as a call into this module and not as a
clock read of its own. The audit matches on the called name, which means a
``clock.now()`` in a subcommand would be indistinguishable from a
``datetime.now()`` there -- and a guard that cannot tell a disciplined call
from the thing it forbids is no guard.

Why the CLI needs one at all. Two subcommands stamp a time into a durable
artifact rather than merely reporting one: ``scope verify`` writes
``last_verified`` into the scope file, and ``ledger add`` writes a timezone-aware
``recorded`` into a row that may never be rewritten. The alternative to reading
the clock is making the operator type the date, which is worse than it sounds:
a date that has to be typed is a date that gets copied from the last command.

  1  a naive timestamp in a durable record  -> a ledger row's time could not be
     ordered against a run artifact without assuming somebody's timezone, and
     the assumption was never written down. ``now()`` here is always
     timezone-aware, and ``Ledger`` refuses a naive one anyway, so the rule is
     enforced twice.
"""

from __future__ import annotations

import datetime as dt

__all__ = ["date", "stamp"]


def stamp(injected: dt.datetime | None = None) -> dt.datetime:
    """A timezone-aware UTC timestamp, or whatever the caller passed instead."""
    return injected or dt.datetime.now(dt.timezone.utc)


def date(injected: dt.date | None = None) -> dt.date:
    """Today's date, or whatever the caller passed instead."""
    return injected or dt.date.today()
