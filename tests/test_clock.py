"""The suite must be deterministic under an arbitrary system clock.

Three separate things are checked here, and the reason they are one file is that
they are one failure mode: a module that reads the wall clock makes a test that
pins its output intermittently wrong, and the module whose entire job is to
refuse a verdict for being stale is the worst possible place for that.

1. **No module under ``src/controlarm`` reads the clock** except as the default
   of an injectable parameter -- written as ``now or datetime.now(tz)`` or
   ``self.today or date.today()``, where the left operand is the injection
   point. Checked by walking the AST rather than by grepping, so a renamed
   import or an aliased call cannot slip past.
2. **The freshness window's boundary is tested on both sides and exactly on it.**
   ``age > window`` is strictly greater, so a verdict stamped exactly one window
   ago is still valid. That is a decision and it deserves a test at the boundary
   rather than near it -- "23 hours is fine, 25 hours is stale" leaves the
   24-hour case to whoever reads the source next.
3. **No test anywhere passes the real clock into a module that ages something.**

A note on what prompted this file. Three ``priorart`` and ``fp`` tests were
observed failing intermittently, and the first explanation offered was a
wall-clock race. It was not: an interrupted ``tools/mutate_guards.py`` run had
left a mutation applied in the working tree, and the mutation in place at the
time -- ``assert_gated refuses an inadmissible CLEAR verdict`` neutered to
``if False:`` -- makes exactly
``test_a_stale_clear_verdict_is_refused_for_being_stale`` fail and nothing else.
The suite is not reentrant: ``pristine``-marked tests assert properties of the
unmutated source, so ``pytest`` must never run while the mutation sweep holds a
file. The audit below was written anyway, because "we looked and there is no
clock dependency" is worth strictly less than a test that says so every time.
"""

from __future__ import annotations

import ast
import datetime as dt
import pathlib

import pytest

from controlarm.controls.run import Outcome, Role, Run
from controlarm.gates.priorart import (
    DEFAULT_FRESHNESS,
    CountBasis,
    PriorArtError,
    PriorArtQuery,
    StaticSource,
    assert_gated,
    gate,
)

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "controlarm"
TESTS = pathlib.Path(__file__).resolve().parent

#: Call targets that read the wall clock, by the attribute chain they end in.
CLOCK_CALLS = ("now", "utcnow", "today", "time", "monotonic", "perf_counter")

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)


def _clock_call_sites(tree: ast.AST) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in CLOCK_CALLS:
            out.append(node)
    return out


def _is_injection_default(module: ast.AST, call: ast.Call) -> bool:
    """True when ``call`` is the fallback half of ``<injected> or <clock>()``.

    That shape is the whole permitted use: a caller who passes ``now`` never
    reaches the clock, so a test can always make the module deterministic.
    """
    for node in ast.walk(module):
        if (
            isinstance(node, ast.BoolOp)
            and isinstance(node.op, ast.Or)
            and len(node.values) == 2
            and node.values[1] is call
            and isinstance(node.values[0], ast.Name | ast.Attribute)
        ):
            return True
    return False


def _python_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_module_reads_the_clock_outside_an_injection_default():
    """A clock read that a test cannot override is a flaky test waiting to exist."""
    offenders = []
    for path in _python_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in _clock_call_sites(tree):
            if not _is_injection_default(tree, call):
                offenders.append(f"{path.relative_to(SRC)}:{call.lineno}")
    assert not offenders, (
        "these call the wall clock where no caller can inject a value:\n"
        + "\n".join(offenders)
        + "\nWrap it as `parameter or <clock>()` and give the function an "
        "injectable parameter, or the suite's determinism depends on when it runs."
    )


def test_the_audit_would_catch_an_unguarded_clock_read():
    """Without this, the test above passes on a file that has no clock calls at all."""
    bad = ast.parse("import datetime\ndef f():\n    return datetime.datetime.now()\n")
    calls = _clock_call_sites(bad)
    assert len(calls) == 1
    assert not _is_injection_default(bad, calls[0])
    good = ast.parse(
        "import datetime\ndef f(now=None):\n    return now or datetime.datetime.now()\n"
    )
    calls = _clock_call_sites(good)
    assert len(calls) == 1
    assert _is_injection_default(good, calls[0])


def test_the_injection_points_that_exist_are_the_ones_expected():
    """Name them, so a new one has to be added here deliberately."""
    found = set()
    for path in _python_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _clock_call_sites(tree):
            found.add(str(path.relative_to(SRC)).replace("\\", "/"))
    assert found == {
        "cli/clock.py",
        "controls/run.py",
        # Fetcher._stamp and Fetcher._tick: the retrieval timestamp written
        # into a new recording, and the monotonic reading the per-host rate
        # limiter spaces calls by. Both are injectable fields on the Fetcher
        # (``stamped``, ``ticked``), so a test can hold either clock still.
        "gates/sources/cassette.py",
        "ledger.py",
        "rails/scope.py",
    }, found


def test_every_run_verdict_field_a_caller_can_branch_on_is_clock_free():
    """``Run.verdict`` stamps a time; nothing else in the record comes from one."""
    run = Run("a title")
    run.liveness(lambda: (True, "ok"))
    run.honest_control(lambda: (False, "403"))
    run.arm("probe", lambda: (False, "silent"), role=Role.TEST)
    pinned = run.verdict(now=NOW)
    assert pinned["generated"] == NOW.isoformat()
    again = run.verdict(now=NOW)
    assert pinned == again
    live = run.verdict()
    assert {k: v for k, v in live.items() if k != "generated"} == {
        k: v for k, v in pinned.items() if k != "generated"
    }
    assert pinned["arms"][0]["outcome"] == Outcome.EXECUTED.value


# ----------------------------------------------------- the freshness boundary


def _assessment(stamp: dt.datetime | None = None):
    """A CLEAR assessment with one measured query, stamped where the test says."""
    record = PriorArtQuery(
        query="component AND class",
        source="advisories",
        retrieved=stamp or NOW,
        row_count=0,
        url="https://example.invalid/search?q=component+AND+class",
        basis=CountBasis.MEASURED,
    )
    return gate("subject", [StaticSource("advisories", [record])], now=NOW)


MICROSECOND = dt.timedelta(microseconds=1)


@pytest.mark.parametrize(
    ("offset", "valid", "why"),
    [
        (-MICROSECOND, True, "one microsecond inside the window"),
        (dt.timedelta(0), True, "exactly at the window: `age > window` is strictly greater"),
        (MICROSECOND, False, "one microsecond past the window"),
    ],
)
def test_the_assessment_freshness_boundary_is_tested_on_both_sides_and_on_it(offset, valid, why):
    """The window's edge is a decision, so it is asserted at the edge.

    An assessment stamped exactly one freshness window ago is **still valid**:
    the comparison is ``age > window``, not ``>=``. Asserting that at 23 and 25
    hours leaves the reader to guess what happens at 24.
    """
    assessment = _assessment()
    checked_at = NOW + DEFAULT_FRESHNESS + offset
    assert assessment.validity(checked_at).valid is valid, why


@pytest.mark.parametrize(
    ("offset", "valid"),
    [(-MICROSECOND, True), (dt.timedelta(0), True), (MICROSECOND, False)],
)
def test_the_query_record_freshness_boundary_is_tested_the_same_way(offset, valid):
    """``query_age > window`` as well. Re-stamping an assessment is not re-running it."""
    stale_by = DEFAULT_FRESHNESS + offset
    assessment = _assessment(stamp=NOW - stale_by)
    assert assessment.validity(NOW).valid is valid


def test_the_window_is_a_parameter_and_the_boundary_moves_with_it():
    """A hard-coded 24 hours in the comparison would pass the tests above."""
    assessment = _assessment()
    tight = dt.timedelta(minutes=5)
    assert assessment.validity(NOW + tight, window=tight).valid
    assert not assessment.validity(NOW + tight + MICROSECOND, window=tight).valid


def test_assert_gated_uses_the_same_boundary_as_validity():
    """The refusal path and the reporting path must not disagree at the edge."""
    assessment = _assessment()
    assert_gated(assessment, now=NOW + DEFAULT_FRESHNESS)
    with pytest.raises(PriorArtError, match="not admissible"):
        assert_gated(assessment, now=NOW + DEFAULT_FRESHNESS + MICROSECOND)


# ------------------------------------------------- no test lets the clock back in


def test_no_test_module_passes_the_real_clock_into_something_that_ages():
    """A fixed ``NOW`` in the test and a live clock in the call is the race.

    The audit is syntactic and deliberately blunt: a test file may not call a
    clock function at all. Freshness behaviour is asserted against stamps the
    test chose, which is the only way the assertion means the same thing on
    every run.
    """
    offenders = []
    for path in _python_files(TESTS):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in _clock_call_sites(tree):
            offenders.append(f"{path.name}:{call.lineno}")
    assert not offenders, (
        "a test reads the wall clock, so its result depends on when it runs:\n"
        + "\n".join(offenders)
    )
