"""The exit-code contract. Nothing else lives in this module.

A shell script wrapping this tool has to be able to tell **"the instrument
broke"** from **"the instrument refused"** without parsing text, because those
two outcomes call for opposite actions and because one of them is the normal
outcome of using the tool at all. That distinction is the whole reason the CLI
exists, so it gets its own module and its own guards.

::

    0  success
    2  tool failure.   NEVER readable as a negative result. A crashed run is
                       not a clean one.
    3  refused by a gate.  This is a NORMAL outcome, not an error. The common
                       case for this tool is refusing to let you proceed.
    4  not promoted.   A draft: something executed and has not earned a verdict.

``1`` is deliberately unassigned. A generic "the command failed" code sitting
inside a contract whose entire point is that failures are distinguishable would
re-create the ambiguity the contract removes, so there is no code here that
means only "something went wrong".

Each guard below exists because a specific wrong verdict was produced by the
practice this is ported from. The numbered defects are kept in the source so a
guard cannot be removed without removing its justification:

  1  ``|| true`` at the end of a promotion pipeline    -> refusal and crash
     both left the pipeline reporting success, so a refused run and a broken
     run were indistinguishable from the outside, and both read as a pass.
     Closed by making every outcome an explicit ``Exit`` member: there is no
     code path in this package that falls off the end into ``0``.
  2  a crash read as a clean negative                  -> an unhandled
     exception terminated a probe before any arm ran, and the surrounding
     report called the run clean. Closed by ``exit_for``: anything that is not
     a deliberately constructed outcome maps to ``TOOL_FAILURE``, never to
     ``OK`` and never to ``REFUSED``.
  3  a scope denial that used the tool-failure code    -> the ported scope
     guard exited ``2`` on a denial, which is the same code a crash produces.
     A wrapper could not tell "we were not allowed to look" from "the
     instrument broke". Closed by giving refusal its own code, ``3``.
  4  a refusal type that could also mean breakage      -> if ``Refused`` and
     ``CannotMeasure`` shared an ancestor that the mapping consulted, one
     could silently acquire the other's exit code on a refactor. They are
     therefore siblings, the mapping is keyed on the concrete classes, and
     ``tests/test_cli.py`` asserts that no refusal can ever produce ``2`` and
     that no inability-to-measure can ever produce ``3``.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum

__all__ = [
    "EXIT_FOR",
    "CannotMeasure",
    "CliOutcome",
    "Exit",
    "NotPromoted",
    "Refused",
    "exit_for",
]


class Exit(IntEnum):
    """The four codes, and the only four this package ever returns."""

    OK = 0
    """The subcommand did what it was asked."""

    TOOL_FAILURE = 2
    """The instrument broke. Never readable as a negative result: a run that
    crashed is not a run that found nothing. A usage error from the argument
    parser lands here too, and correctly so, because a mis-invoked instrument
    measured nothing either."""

    REFUSED = 3
    """A gate refused. This is the normal outcome, not an error. The reason is
    always printed, because a refusal whose reason is unstated cannot be acted
    on and so gets switched off by the next person who meets it."""

    NOT_PROMOTED = 4
    """A draft. Something executed and has not earned a verdict yet. Distinct
    from ``REFUSED`` because the next action differs: a refusal says fix the
    premise, a draft says re-run from fresh state and gather the rest."""


class CliOutcome(Exception):
    """A deliberately constructed outcome, carrying what the renderer prints.

    Never raised directly. Its subclasses are what the exit mapping is keyed
    on, and a bare instance of this class maps to ``TOOL_FAILURE`` like any
    other unexpected object -- defect 2 means an outcome nobody declared is a
    breakage, not a pass.
    """

    def __init__(
        self,
        reason: str,
        *,
        verdict: str,
        data: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.verdict = verdict
        self.data: dict[str, object] = dict(data or {})


class Refused(CliOutcome):
    """A gate said no. Exit 3, and this is not a failure.

    Raised only where a guard in the library refused, or where this package's
    own plan schema refused. It is never raised to report that something went
    wrong with the tool itself: that is ``CannotMeasure``.
    """


class NotPromoted(CliOutcome):
    """Something executed and is a draft. Exit 4."""


class CannotMeasure(CliOutcome):
    """The instrument cannot produce the number it was asked for. Exit 2.

    A sibling of ``Refused``, never a subclass, because the two mean opposite
    things: a refusal is a verdict about the subject, and this is a verdict
    about the instrument. ``audit rules`` raises it rather than printing a
    ratio it cannot derive, which is the one place in this package where
    exiting non-zero is the honest answer to a question that has no answer.
    """


#: Concrete class -> code. Keyed on concrete classes on purpose (defect 4), so
#: a new subclass does not inherit an exit code by accident; it falls through to
#: ``TOOL_FAILURE`` until somebody lists it here deliberately.
EXIT_FOR: Mapping[type[BaseException], Exit] = {
    Refused: Exit.REFUSED,
    NotPromoted: Exit.NOT_PROMOTED,
    CannotMeasure: Exit.TOOL_FAILURE,
}


def exit_for(exc: BaseException) -> Exit:
    """The code for ``exc``.

    Anything not listed in ``EXIT_FOR`` is a tool failure. Defect 2: an
    exception nobody anticipated is the instrument breaking, and the one thing
    it must never be able to produce is a code a reader could mistake for a
    result.
    """
    return EXIT_FOR.get(type(exc), Exit.TOOL_FAILURE)
