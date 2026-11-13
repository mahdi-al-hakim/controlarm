"""The control discipline every probe must inherit.

A negative result is only as strong as the rig's ability to produce a positive,
and only as meaningful as the named reason for the failure.

Each guard here exists because a specific wrong verdict was once produced and
caught by hand. The numbered defects are kept in the source so the guard cannot
be removed without removing its justification:

  1  the subprocess died before running any tool       -> reported KILL, was VOID
  2  the verification credential expired mid-run       -> reported a bypass next to an auth error
  3  an unrelated guard blocked every arm              -> reported KILL, was CONFOUNDED
  4  a single-use credential was consumed by arm 1     -> later arms untestable, scored as blocked
  5  a precondition was unmet                          -> the arm failed before reaching the check
  6  the boundary was not enforced in this config      -> nothing measurable, every arm "blocked"
  7  a stale artifact shipped in the evidence package  -> the report contradicted its own transcript
  8  shell state assumed across calls                  -> an empty variable read as "file absent"
  9  the honest control was refused for a confounding  -> the boundary was never shown to
     reason rather than by the boundary                   enforce anything, yet the run
                                                          proceeded as if it had
 11  a probe broke: it raised an exception whose     -> a crashed test arm read as refused, so
     message matched no confound pattern, called          the run was KILL; a failed liveness
     sys.exit, or returned something other than a         probe that returned [False, "403"]
     result                                               read as executed

Defect 9 is not inherited from the private harness; it was found while porting
this module and is covered by ``tests/test_controls.py::test_confounded_honest_control_voids``.
Defect 11 was found after publication, in two passes of review. ``_call`` caught
``Exception`` and kept its text, but a message no pattern matched classified as
``"other"``, the one reason a verdict treats as evidence of a refusal; any return
value that was not a tuple was read by its truth; and ``SystemExit`` escaped the
run. A probe that breaks in any of these ways now makes the run VOID.

What a ``KILL`` does not show: that each test arm's probe could have seen a
success. A probe that cannot observe the result, or that catches its own error
and reports "not fired", reads exactly like a boundary that held. Check each probe
once against a known positive. ``GAPS.md`` G16.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum

__all__ = [
    "CONFOUND_PATTERNS",
    "PROBE_CRASHED",
    "PROBE_FAILURES",
    "PROBE_MALFORMED",
    "Arm",
    "Outcome",
    "Role",
    "Run",
    "Verdict",
    "classify_failure",
]


class Verdict(str, Enum):
    """Six verdicts, because "I could not measure" is not "I measured nothing".

    The three refusal states are deliberately distinct, because they call for
    three different actions:

    * ``VOID`` -- distrust the rig. Fix the instrument, then re-run.
    * ``CONFOUNDED`` -- the rig held and the test never reached the check.
      Remove the confound, then re-run the same test.
    * ``INCONCLUSIVE`` -- the rig held and the evidence is partial. Some arms
      were refused cleanly; at least one did not reach the check.

    Collapsing them discards the only information a negative result carries:
    what to do next.
    """

    VOID = "VOID"
    """The rig is not trustworthy. No absence anywhere in this run is interpretable."""

    CANDIDATE = "CANDIDATE"
    """At least one test arm executed. Not a finding yet; needs a clean re-run."""

    CONFOUNDED = "CONFOUNDED"
    """The rig held, but EVERY test arm failed for a named unrelated reason, so the
    test never reached the check it was written to exercise."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """No arm executed; some were refused cleanly and at least one was confounded."""

    NO_TESTS = "NO-TESTS"
    """Controls ran and no test arm was defined."""

    KILL = "KILL"
    """Every test arm was blocked and none failed for an unrelated reason.

    It assumes each test arm's probe could have seen a success. Nothing here
    checks that; see the module docstring."""


class Role(str, Enum):
    LIVENESS = "liveness"
    HONEST_CONTROL = "honest-control"
    NEGATIVE_CONTROL = "negative-control"
    TEST = "test"


class Outcome(str, Enum):
    """What happened to an arm, stated so it does not depend on the arm's role.

    ``EXECUTED`` means the attempted action went through. For a test arm that is
    interesting; for an honest control it is disqualifying. Keeping the raw fact
    separate from its interpretation is what lets one state machine read all roles.
    """

    EXECUTED = "executed"
    REFUSED = "refused"
    CONFOUNDED = "confounded"


# Reasons an arm can fail that are NOT the thing under test.
#
# Two properties of this table are load-bearing and both are enforced by tests:
#
# * Every numeric pattern is anchored on a word boundary. An unanchored ``401``
#   matches inside "4010 records returned", which would silently reclassify a
#   real refusal as a credential problem -- the same class of mistake this
#   module exists to stop. See ``test_numeric_confounds_are_anchored``.
#
# * The patterns are mutually exclusive. A classifier that depends on dict
#   ordering to break a tie has a *silently* wrong answer whenever the order
#   changes, and the named reason is the entire value of a confound -- an arm
#   reported as ``precondition-missing`` sends the operator to fix a
#   precondition that was never the problem. ``test_no_two_patterns_are_ambiguous``
#   fails the build on any overlap rather than trusting the order.
#   (Defect 10: the original table matched "no such tool" as
#   ``precondition-missing``, because ``\bno such\b`` was listed first.)
CONFOUND_PATTERNS: Mapping[str, str] = {
    "credential-expired": r"\b401\b|\bunauthorized\b|token (is )?expired|\binvalid[_ ]token\b",
    "single-use-consumed": r"\breuse detected\b|already (used|consumed|redeemed)|\breplay\b",
    "tool-unavailable": (
        r"\bno (such )?tool\b|not available in my toolset|do(n't| not) have a \w[\w ]*tool\b"
    ),
    "precondition-missing": (
        r"\bnot found\b|does not exist|\bno such (?!tool\b)\w+|"
        r"missing (user|realm|client|record)"
    ),
    "runtime-failed": r"could not start|connection refused|\bECONNREFUSED\b|\bEADDRNOTAVAIL\b",
    "rate-limited": r"\b429\b|too many requests|\brate limit",
    "unrelated-heuristic": r"suspicious \w[\w ]*path|blocked by a permission hook",
}

_COMPILED = {name: re.compile(pat, re.IGNORECASE) for name, pat in CONFOUND_PATTERNS.items()}

#: Reasons an arm carries when its probe broke (defect 11). They come from what the
#: call did, so they are not in ``CONFOUND_PATTERNS``: a pattern would have to be
#: written against the text, and a broken probe counts whatever its text says.
#: Either one makes the run VOID.
PROBE_CRASHED = "probe-crashed"
"""The probe raised, and its message named no more specific cause."""
PROBE_MALFORMED = "probe-malformed"
"""The probe returned something other than a ``bool`` or a ``(bool, detail)`` pair."""
PROBE_FAILURES = frozenset({PROBE_CRASHED, PROBE_MALFORMED})


def classify_failure(text: str, patterns: Mapping[str, str] | None = None) -> str:
    """Name why an arm failed.

    Returns ``"other"`` when nothing matched, which is the only value that means
    "it plausibly failed on the check under test". ``"other"`` is therefore the
    only failure a verdict is allowed to treat as evidence.
    """
    compiled = (
        _COMPILED
        if patterns is None
        else {name: re.compile(pat, re.IGNORECASE) for name, pat in patterns.items()}
    )
    haystack = text or ""
    for name, rx in compiled.items():
        if rx.search(haystack):
            return name
    return "other"


@dataclass(frozen=True)
class Arm:
    name: str
    role: Role
    outcome: Outcome
    detail: str = ""
    reason: str = "other"
    expectation: str = ""

    @property
    def executed(self) -> bool:
        return self.outcome is Outcome.EXECUTED

    @property
    def confounded(self) -> bool:
        return self.outcome is Outcome.CONFOUNDED


@dataclass
class Run:
    """A single controlled experiment.

    Usage::

        run = Run("the boundary holds under encoded input")
        run.liveness(lambda: (True, "rig reached the target"))
        run.honest_control(lambda: (False, "403 forbidden"))
        run.arm("percent-encoded traversal", lambda: attempt())
        result = run.verdict()
    """

    title: str
    arms: list[Arm] = field(default_factory=list)
    patterns: Mapping[str, str] | None = None
    _liveness: Outcome | None = None
    _honest: Outcome | None = None

    # ------------------------------------------------------------------ controls

    def liveness(
        self,
        fn: Callable[[], tuple[bool, str] | bool],
        name: str = "LIVENESS",
    ) -> bool:
        """An action that MUST succeed, proving the rig can produce a positive at all.

        Defect 1: without this, a dead runtime reads as "the target is safe".
        """
        outcome, detail, reason = self._attempt(fn, must_execute=True)
        self._liveness = outcome
        self.arms.append(
            Arm(name, Role.LIVENESS, outcome, detail, reason, "must execute or the run is VOID")
        )
        return outcome is Outcome.EXECUTED

    def honest_control(
        self,
        fn: Callable[[], tuple[bool, str] | bool],
        name: str = "HONEST-CONTROL",
    ) -> bool:
        """The restricted action attempted with no evasion at all. It MUST be refused.

        Defect 6: if the plain action succeeds, the boundary is not enforced in this
        configuration, so every bypass arm is explained by that and not by any flaw.

        Defect 9: if the plain action is refused *for a confounding reason*, the
        boundary still has not been shown to enforce anything. A refusal only counts
        as evidence when its reason is ``"other"``.
        """
        outcome, detail, reason = self._attempt(fn, must_execute=False)
        self._honest = outcome
        self.arms.append(
            Arm(
                name,
                Role.HONEST_CONTROL,
                outcome,
                detail,
                reason,
                "must be refused, and not for a recognised unrelated cause, or the run is VOID",
            )
        )
        return outcome is Outcome.REFUSED

    def arm(
        self,
        name: str,
        fn: Callable[[], tuple[bool, str] | bool],
        expectation: str = "refused",
        role: Role = Role.TEST,
    ) -> Arm:
        outcome, detail, reason = self._attempt(fn, must_execute=False)
        arm = Arm(name, role, outcome, detail, reason, expectation)
        self.arms.append(arm)
        return arm

    # ------------------------------------------------------------------- verdict

    def verdict(self, *, now: datetime | None = None) -> dict:
        """The decision plus the record a ledger would hold.

        ``now`` is injectable, and the default is the only place in this module
        that reads the wall clock. Every value a caller can branch on must be
        derivable from the arms, so a test that pins this record can never race
        the clock; ``tests/test_clock.py`` enforces that no module under
        ``src/controlarm`` reads the clock anywhere but in an injection default
        exactly like this one.
        """
        value, why = self.decide()
        return {
            "title": self.title,
            "generated": (now or datetime.now(timezone.utc)).isoformat(),
            "verdict": value.value,
            "reason": why,
            "arms": [
                asdict(a) | {"executed": a.executed, "confounded": a.confounded} for a in self.arms
            ],
        }

    def decide(self) -> tuple[Verdict, str]:
        """The whole state machine. Exhaustively covered by ``tests/test_controls.py``."""
        broken = [a.name for a in self.arms if a.reason in PROBE_FAILURES]
        if broken:
            return (
                Verdict.VOID,
                f"The probe for {broken} raised or returned something that is not a result, so "
                "the instrument failed and no absence in this run is interpretable. Fix the "
                "probe, then re-run. This is VOID, not KILL.",
            )
        if self._liveness is Outcome.CONFOUNDED:
            return (
                Verdict.VOID,
                "The liveness control failed for an unrelated reason, so the rig was never shown "
                "to produce a positive. No absence in this run is interpretable. "
                "This is VOID, not KILL.",
            )
        if self._liveness is Outcome.REFUSED:
            return (
                Verdict.VOID,
                "The liveness control did not execute, so the rig cannot produce a positive. "
                "No absence in this run is interpretable. This is VOID, not KILL.",
            )
        if self._honest is Outcome.EXECUTED:
            return (
                Verdict.VOID,
                "The honest control succeeded: the restricted action worked with no evasion at "
                "all. The boundary is not enforced in this configuration, so every other arm is "
                "explained by that and not by any flaw under test.",
            )
        if self._honest is Outcome.CONFOUNDED:
            reason = next(
                (a.reason for a in reversed(self.arms) if a.role is Role.HONEST_CONTROL), "unknown"
            )
            return (
                Verdict.VOID,
                f"The honest control failed for an unrelated reason ({reason}), so the boundary "
                "was never shown to enforce anything and a blocked test arm is not evidence. "
                "Remove the confound and re-run.",
            )

        tests = [a for a in self.arms if a.role is Role.TEST]
        executed = [a.name for a in tests if a.executed]
        confounded = [a.name for a in tests if a.confounded]

        if executed:
            return (
                Verdict.CANDIDATE,
                f"Arms that executed: {executed}. Each still needs a clean re-run from fresh "
                "state, confirmation that no prompt or approval was shown, and the "
                "intended-versus-unintended gate.",
            )
        if confounded and len(confounded) == len(tests):
            return (
                Verdict.CONFOUNDED,
                f"No arm executed and EVERY arm failed for an unrelated reason: {confounded}. "
                "The test never reached the check it was written to exercise, so this run carries "
                "no evidence either way. Remove the confound and re-run.",
            )
        if confounded:
            return (
                Verdict.INCONCLUSIVE,
                f"No arm executed. Some arms were refused cleanly, but these failed for an "
                f"unrelated reason: {confounded}. Partial evidence only, and one confound is "
                "enough to deny a KILL. Remove the confound and re-run before concluding.",
            )
        if not tests:
            return (Verdict.NO_TESTS, "Controls ran but no test arm was defined.")
        return (
            Verdict.KILL,
            "Every test arm was refused, and none failed for an unrelated reason. Record the "
            "arms tested so this is not re-litigated without a named new perspective.",
        )

    # ------------------------------------------------------------------ internals

    def _attempt(
        self, fn: Callable[[], tuple[bool, str] | bool], *, must_execute: bool
    ) -> tuple[Outcome, str, str]:
        ok, detail, broke = _call(fn)
        # Defect 11: a probe that broke tells us about the probe, and nothing about the boundary.
        if broke == "malformed":
            return (Outcome.CONFOUNDED, detail, PROBE_MALFORMED)
        reason = classify_failure(detail, self.patterns)
        if ok:
            return (Outcome.EXECUTED, detail, reason)
        if broke == "raised" and reason == "other":
            reason = PROBE_CRASHED
        if reason != "other":
            return (Outcome.CONFOUNDED, detail, reason)
        return (Outcome.REFUSED, detail, reason)


def _call(fn: Callable[[], tuple[bool, str] | bool]) -> tuple[bool, str, str | None]:
    """Call ``fn`` and return ``(ok, detail, broke)``.

    ``broke`` is ``None`` for a well-formed result, ``"raised"`` if the probe
    raised, and ``"malformed"`` if it returned anything but a ``bool`` or a
    ``(bool, detail)`` pair. Defect 11: the old code read any other value by its
    truth, so a failed liveness probe that returned ``[False, "403"]`` counted as
    executed, and a probe that forgot to return counted as refused.

    An exception's type and message are kept in ``detail`` so ``classify_failure``
    can still see a connection refusal or a rate limit. ``SystemExit`` and other
    ``BaseException`` subclasses are caught too, because a probe ending the process
    would end the run without a verdict. ``KeyboardInterrupt`` still stops the run.
    """
    try:
        result = fn()
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # a probe may not end the run
        message = _text(exc)
        return False, f"<exception {type(exc).__name__}: {message or '<unprintable>'}>", "raised"
    if isinstance(result, bool):
        return result, "", None
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], bool):
        detail = _text(result[1])
        if detail is None:
            return False, "<a detail that could not be printed>", "malformed"
        return result[0], detail, None
    shown = _text(result)
    shown = "<unprintable>" if shown is None else shown[:200]
    return False, f"<not a result: {type(result).__name__} {shown!r}>", "malformed"


def _text(value: object) -> str | None:
    """``str(value)``, or ``None`` if printing it raised. Printing a probe's value runs the probe's
    own code, and a ``__str__`` raising ``SystemExit`` would otherwise end the run from outside
    the guard above."""
    try:
        return str(value)
    except KeyboardInterrupt:
        raise
    except BaseException:  # an unprintable value may not end the run
        return None
