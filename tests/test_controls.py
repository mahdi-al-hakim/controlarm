"""Tests for the verdict state machine.

The point of this file is not coverage. It is that the one claim the harness
makes about itself -- *no configuration yields CANDIDATE without a live rig and a
boundary demonstrably enforced by the boundary itself* -- is checked
exhaustively rather than asserted.
"""

from __future__ import annotations

import dataclasses
import itertools

import pytest

from controlarm.controls.run import (
    CONFOUND_PATTERNS,
    Arm,
    Outcome,
    Role,
    Run,
    Verdict,
    classify_failure,
)

# --------------------------------------------------------------------- helpers

EXECUTES = lambda: (True, "went through")
REFUSED = lambda: (False, "403 forbidden")
CONFOUNDED = lambda: (False, "401 unauthorized")

#: The three ways an arm can resolve, as callables plus the outcome each must produce.
ARM_KINDS = {
    Outcome.EXECUTED: EXECUTES,
    Outcome.REFUSED: REFUSED,
    Outcome.CONFOUNDED: CONFOUNDED,
}


def build(liveness, honest, test_arms):
    """Assemble a Run from symbolic outcomes. ``None`` means the control was never called."""
    run = Run("t")
    if liveness is not None:
        run.liveness(ARM_KINDS[liveness])
    if honest is not None:
        run.honest_control(ARM_KINDS[honest])
    for i, kind in enumerate(test_arms):
        run.arm(f"arm{i}", ARM_KINDS[kind])
    return run


# ------------------------------------------------------- the attempt classifier


def test_attempt_maps_success_to_executed():
    run = build(Outcome.EXECUTED, None, [])
    assert run.arms[0].outcome is Outcome.EXECUTED


def test_attempt_maps_plain_refusal_to_refused():
    run = build(None, None, [Outcome.REFUSED])
    assert run.arms[0].outcome is Outcome.REFUSED
    assert run.arms[0].reason == "other"


def test_attempt_maps_named_failure_to_confounded():
    run = build(None, None, [Outcome.CONFOUNDED])
    assert run.arms[0].outcome is Outcome.CONFOUNDED
    assert run.arms[0].reason == "credential-expired"


def test_exception_is_captured_not_raised_and_keeps_its_reason():
    def boom():
        raise ConnectionRefusedError("connection refused")

    run = Run("t")
    arm = run.arm("explodes", boom)
    assert arm.outcome is Outcome.CONFOUNDED
    assert arm.reason == "runtime-failed"
    assert "ConnectionRefusedError" in arm.detail


def test_bare_bool_return_is_accepted():
    run = Run("t")
    assert run.liveness(lambda: True) is True
    assert run.arms[0].outcome is Outcome.EXECUTED


# -------------------------------------------------------------- the truth table

ALL_CONTROL_STATES = [None, Outcome.EXECUTED, Outcome.REFUSED, Outcome.CONFOUNDED]
ALL_TEST_SHAPES = [
    (),
    (Outcome.REFUSED,),
    (Outcome.CONFOUNDED,),
    (Outcome.EXECUTED,),
    (Outcome.REFUSED, Outcome.CONFOUNDED),
    (Outcome.REFUSED, Outcome.EXECUTED),
    (Outcome.CONFOUNDED, Outcome.EXECUTED),
    (Outcome.CONFOUNDED, Outcome.CONFOUNDED),
]

CELLS = list(itertools.product(ALL_CONTROL_STATES, ALL_CONTROL_STATES, ALL_TEST_SHAPES))


def expected(liveness, honest, tests) -> Verdict:
    """An independent restatement of the rule, written from the docstrings rather
    than from ``decide()``. If this and ``decide()`` ever disagree, one of them is
    wrong and the test says which cell."""
    if liveness in (Outcome.REFUSED, Outcome.CONFOUNDED):
        return Verdict.VOID
    if honest is Outcome.EXECUTED or honest is Outcome.CONFOUNDED:
        return Verdict.VOID
    if any(t is Outcome.EXECUTED for t in tests):
        return Verdict.CANDIDATE
    confounded = [t for t in tests if t is Outcome.CONFOUNDED]
    if confounded and len(confounded) == len(tests):
        return Verdict.CONFOUNDED
    if confounded:
        return Verdict.INCONCLUSIVE
    if not tests:
        return Verdict.NO_TESTS
    return Verdict.KILL


@pytest.mark.parametrize("liveness,honest,tests", CELLS)
def test_every_cell_of_the_truth_table(liveness, honest, tests):
    got, why = build(liveness, honest, tests).decide()
    assert got is expected(liveness, honest, tests), (
        f"liveness={liveness} honest={honest} tests={tests}: got {got}, "
        f"expected {expected(liveness, honest, tests)}\n{why}"
    )


def test_the_truth_table_actually_covers_every_verdict():
    """A table that never produces some verdict is not covering the state machine."""
    produced = {build(lv, h, ts).decide()[0] for lv, h, ts in CELLS}
    assert produced == set(Verdict), f"verdicts never exercised: {set(Verdict) - produced}"


# ------------------------------------------------------- the load-bearing claims


@pytest.mark.parametrize("liveness,honest,tests", CELLS)
def test_candidate_requires_a_live_rig_and_an_enforced_boundary(liveness, honest, tests):
    """The claim the whole harness rests on, checked on all 112 cells.

    CANDIDATE is reachable only when the rig was shown to produce a positive and
    the boundary was shown to refuse the plain action *by the boundary itself*.
    """
    got, _ = build(liveness, honest, tests).decide()
    if got is Verdict.CANDIDATE:
        assert liveness is Outcome.EXECUTED or liveness is None
        assert honest is Outcome.REFUSED or honest is None
        assert any(t is Outcome.EXECUTED for t in tests)


@pytest.mark.parametrize("liveness,honest,tests", CELLS)
def test_kill_is_never_returned_when_anything_was_confounded(liveness, honest, tests):
    """A KILL on a confounded run is defect 3: the unrelated guard, read as a defence."""
    got, _ = build(liveness, honest, tests).decide()
    if got is Verdict.KILL:
        assert liveness is not Outcome.CONFOUNDED
        assert honest is not Outcome.CONFOUNDED
        assert all(t is not Outcome.CONFOUNDED for t in tests)


def test_dead_rig_voids_rather_than_kills():
    """Defect 1. A dead runtime must not read as 'the target is safe'."""
    got, why = build(Outcome.REFUSED, Outcome.REFUSED, (Outcome.REFUSED,)).decide()
    assert got is Verdict.VOID
    assert "VOID, not KILL" in why


def test_unenforced_boundary_voids():
    """Defect 6. If the plain action works, no bypass arm means anything."""
    got, why = build(Outcome.EXECUTED, Outcome.EXECUTED, (Outcome.REFUSED,)).decide()
    assert got is Verdict.VOID
    assert "not enforced" in why


def test_confounded_honest_control_voids():
    """Defect 9 -- found while porting this module, absent from the original.

    The plain action was refused, so the original implementation treated the
    boundary as enforced. But it was refused by an expired credential, so the
    boundary was never exercised and a blocked test arm is not evidence.
    """
    got, why = build(Outcome.EXECUTED, Outcome.CONFOUNDED, (Outcome.REFUSED,)).decide()
    assert got is Verdict.VOID
    assert "never shown to enforce" in why


def test_confound_beats_blocked_when_both_present():
    """Defect 3, at arm level: one confounded arm is enough to deny a KILL."""
    got, _ = build(
        Outcome.EXECUTED, Outcome.REFUSED, (Outcome.REFUSED, Outcome.CONFOUNDED)
    ).decide()
    assert got is Verdict.INCONCLUSIVE


def test_all_arms_confounded_is_distinct_from_partial_evidence():
    """CONFOUNDED and INCONCLUSIVE call for different actions, so they are different.

    Every arm confounded means the test never reached the check and the run
    carries no evidence either way. A mix means some arms were refused cleanly,
    so there is partial evidence -- not enough for a KILL, but not nothing.
    Collapsing the two loses the only thing a negative tells you: what to do next.
    """
    all_confounded, why_all = build(
        Outcome.EXECUTED, Outcome.REFUSED, (Outcome.CONFOUNDED, Outcome.CONFOUNDED)
    ).decide()
    assert all_confounded is Verdict.CONFOUNDED
    assert "never reached the check" in why_all

    mixed, why_mixed = build(
        Outcome.EXECUTED, Outcome.REFUSED, (Outcome.REFUSED, Outcome.CONFOUNDED)
    ).decide()
    assert mixed is Verdict.INCONCLUSIVE
    assert "Partial evidence" in why_mixed
    assert all_confounded is not mixed


def test_a_single_confounded_arm_is_fully_confounded():
    """One arm, confounded, is the degenerate case of "every arm confounded"."""
    got, _ = build(Outcome.EXECUTED, Outcome.REFUSED, (Outcome.CONFOUNDED,)).decide()
    assert got is Verdict.CONFOUNDED


def test_executed_beats_confound_when_both_present():
    got, _ = build(
        Outcome.EXECUTED, Outcome.REFUSED, (Outcome.CONFOUNDED, Outcome.EXECUTED)
    ).decide()
    assert got is Verdict.CANDIDATE


def test_controls_are_not_counted_as_test_arms():
    """A run whose only executed arm is the liveness control has no findings."""
    got, _ = build(Outcome.EXECUTED, Outcome.REFUSED, ()).decide()
    assert got is Verdict.NO_TESTS


# --------------------------------------------------------- the confound patterns


@pytest.mark.parametrize(
    "text,expected_reason",
    [
        ("HTTP 401 Unauthorized", "credential-expired"),
        ("the token is expired", "credential-expired"),
        ("invalid_token", "credential-expired"),
        ("replay detected", "single-use-consumed"),
        ("code already redeemed", "single-use-consumed"),
        ("record not found", "precondition-missing"),
        ("no such tool", "tool-unavailable"),
        ("I don't have a browser tool", "tool-unavailable"),
        ("I do not have a shell tool", "tool-unavailable"),
        ("connection refused", "runtime-failed"),
        ("ECONNREFUSED 127.0.0.1:8080", "runtime-failed"),
        ("HTTP 429 Too Many Requests", "rate-limited"),
        ("blocked by a permission hook", "unrelated-heuristic"),
        ("403 forbidden", "other"),
        ("denied: insufficient scope", "other"),
        ("", "other"),
    ],
)
def test_classify_failure(text, expected_reason):
    assert classify_failure(text) == expected_reason


@pytest.mark.parametrize(
    "text",
    [
        "4010 records returned",  # unanchored 401 would match this
        "query took 4299 ms",  # unanchored 429 would match this
        "the 401k export completed",  # a word boundary is not enough on its own
    ],
)
def test_numeric_confounds_are_anchored(text):
    """A status code embedded in a longer number is not a status code.

    Without the word boundaries, each of these is silently reclassified as a
    confound and a real refusal stops counting as evidence.
    """
    assert classify_failure(text) == "other", (
        f"{text!r} was misread as a confound -- the anchoring regression is back"
    )


def test_caller_can_extend_the_patterns_without_losing_other():
    run = Run("t", patterns={**CONFOUND_PATTERNS, "quota": r"\bquota exhausted\b"})
    arm = run.arm("a", lambda: (False, "quota exhausted for this project"))
    assert arm.outcome is Outcome.CONFOUNDED
    assert arm.reason == "quota"


def test_every_confound_pattern_compiles_and_is_anchored():
    """A pattern that is not anchored is the bug this table already had once."""
    for name, pattern in CONFOUND_PATTERNS.items():
        assert re_compiles(pattern), f"{name} does not compile"
        if any(ch.isdigit() for ch in pattern):
            assert r"\b" in pattern, f"{name} contains a bare numeric literal"


#: One realistic failure message per confound reason. These are the probe strings
#: the ambiguity test uses, so adding a reason means adding a probe for it.
CONFOUND_PROBES = {
    "credential-expired": ["HTTP 401 Unauthorized", "the token is expired", "invalid_token"],
    "single-use-consumed": ["reuse detected", "code already redeemed", "replay"],
    "tool-unavailable": [
        "no such tool",
        "no tool",
        "that is not available in my toolset",
        "I don't have a browser tool",
    ],
    "precondition-missing": [
        "record not found",
        "the realm does not exist",
        "no such client",
        "missing user",
    ],
    "runtime-failed": ["could not start", "connection refused", "ECONNREFUSED 127.0.0.1:8080"],
    "rate-limited": ["HTTP 429 Too Many Requests", "too many requests", "rate limit exceeded"],
    "unrelated-heuristic": ["suspicious file path", "blocked by a permission hook"],
}


def test_every_reason_has_probes():
    """A reason with no probe string is a reason nothing checks."""
    assert set(CONFOUND_PROBES) == set(CONFOUND_PATTERNS)


@pytest.mark.parametrize("reason", sorted(CONFOUND_PROBES))
def test_each_probe_classifies_to_its_own_reason(reason):
    for probe in CONFOUND_PROBES[reason]:
        assert classify_failure(probe) == reason, (
            f"{probe!r} should be {reason}, got {classify_failure(probe)!r}"
        )


def test_no_two_patterns_are_ambiguous():
    """Defect 10. The named reason is the whole value of a confound.

    The original table classified "no such tool" as ``precondition-missing``
    because ``\\bno such\\b`` happened to be listed first, which would send the
    operator to fix a precondition that was never the problem. Relying on dict
    order to break a tie means the answer changes silently when the order does,
    so overlap fails the build instead.
    """
    import re

    compiled = {n: re.compile(p, re.IGNORECASE) for n, p in CONFOUND_PATTERNS.items()}
    overlaps = []
    for owner, probes in CONFOUND_PROBES.items():
        for probe in probes:
            matched = sorted(n for n, rx in compiled.items() if rx.search(probe))
            if matched != [owner]:
                overlaps.append((probe, owner, matched))
    assert not overlaps, "patterns are not mutually exclusive:\n" + "\n".join(
        f"  {p!r}: owned by {o}, also matched by {[m for m in ms if m != o]}"
        for p, o, ms in overlaps
    )


def re_compiles(pattern: str) -> bool:
    import re

    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


# ------------------------------------------------------------------- the record


def test_verdict_record_is_serialisable_and_complete():
    import json

    record = build(Outcome.EXECUTED, Outcome.REFUSED, (Outcome.EXECUTED,)).verdict()
    text = json.dumps(record)
    assert '"verdict": "CANDIDATE"' in text
    assert record["reason"]
    assert len(record["arms"]) == 3
    for arm in record["arms"]:
        # Both the raw outcome and its two interpretations are recorded, so a
        # reader never has to re-derive whether an arm counted.
        assert {"outcome", "executed", "confounded", "reason", "role"} <= set(arm)


def test_arm_is_immutable():
    """An arm is a record of what happened. Nothing downstream may edit it."""
    arm = Arm("a", Role.TEST, Outcome.REFUSED)
    with pytest.raises(dataclasses.FrozenInstanceError):
        arm.detail = "rewritten"  # type: ignore[misc]
