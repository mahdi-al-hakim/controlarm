"""Tests for the mutation harness itself.

The tool writes to the repository's own source files, so its failure modes are
not theoretical. Defect 1 -- restoring a captured copy over somebody else's
concurrent edit, silently -- destroyed a real change before it was caught, and
it is exactly the class of defect the rest of this package exists to prevent:
a tool that loses state and leaves no evidence of having done so.

Every test here runs against a temporary file. Nothing in this module points
the tool at the real sources.
"""

from __future__ import annotations

import hashlib

import pytest
from tools.mutate_guards import (
    ConcurrentModification,
    Mutation,
    apply_mutation,
    digest,
    main,
    restore_or_refuse,
)

PRISTINE = "def f(x):\n    if x:\n        return 1\n    return 0\n"
MUTATED = "def f(x):\n    if False:  # MUTATED\n        return 1\n    return 0\n"
INTRUDER = "def f(x):\n    if x:\n        return 2  # somebody else's edit\n    return 0\n"

GUARD = Mutation("t", "the guard", r"if x:", "if False:  # MUTATED")


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "subject.py"
    path.write_text(PRISTINE, encoding="utf-8")
    return path


# ------------------------------------------------------------------ the digest


def test_digest_is_sha256_of_the_utf8_bytes():
    assert digest(PRISTINE) == hashlib.sha256(PRISTINE.encode("utf-8")).hexdigest()


def test_digest_separates_contents_that_differ_only_in_line_endings():
    """Not normalised on purpose: if the tool normalised newlines it could not
    tell a real edit from its own write-back on a platform that rewrites them."""
    assert digest("a\nb\n") != digest("a\r\nb\r\n")


# ------------------------------------------------------------ apply_mutation


def test_a_pattern_matching_once_applies():
    mutated, note = apply_mutation(PRISTINE, GUARD)
    assert mutated == MUTATED
    assert note == ""


def test_a_pattern_matching_twice_is_stale_rather_than_guessed():
    doubled = PRISTINE + PRISTINE
    mutated, note = apply_mutation(doubled, GUARD)
    assert mutated is None
    assert "matched 2 times" in note


def test_a_pattern_matching_nothing_is_stale():
    mutated, note = apply_mutation("def g():\n    pass\n", GUARD)
    assert mutated is None
    assert "matched 0 times" in note


def test_a_replacement_identical_to_the_match_proves_nothing():
    noop = Mutation("t", "no-op", r"if x:", "if x:")
    mutated, note = apply_mutation(PRISTINE, noop)
    assert mutated is None
    assert "identical" in note


def test_a_mutant_that_does_not_parse_is_stale_rather_than_applied():
    """Defect 2, and the subtler of the two.

    A replacement that breaks the file's syntax makes the whole suite red
    because nothing can be imported. The run then reports the guard as pinned
    on the strength of a syntax error rather than of a test, which is a false
    pass -- the exact failure the tool exists to detect, inside the tool.
    """
    breaks_syntax = Mutation("t", "unbalanced", r"if x:", "if x(:  # MUTATED")
    mutated, note = apply_mutation(PRISTINE, breaks_syntax)
    assert mutated is None
    assert "does not parse" in note
    assert "prove nothing" in note


def test_the_comment_swallowing_a_trailing_comma_is_caught_by_that_guard():
    """The concrete shape the defect took: a pattern that excluded a trailing
    comma, so the appended ``# MUTATED`` comment commented the comma out."""
    source = "f(\n    a=g(1),\n    b=2,\n)\n"
    swallows = Mutation("t", "swallows the comma", r"a=g\(1\)", "a=1  # MUTATED")
    mutated, note = apply_mutation(source, swallows)
    assert mutated is None
    assert "does not parse" in note


# -------------------------------------------------------- restore_or_refuse


def test_an_untouched_target_is_restored(target):
    baseline = digest(PRISTINE)
    target.write_text(MUTATED, encoding="utf-8")
    restore_or_refuse(target, MUTATED, PRISTINE, baseline)
    assert target.read_text(encoding="utf-8") == PRISTINE
    assert not target.with_suffix(".py.orig.bak").exists()


def test_a_concurrently_modified_target_is_not_clobbered(target):
    """Defect 1. The intruder's bytes must still be there afterwards."""
    baseline = digest(PRISTINE)
    target.write_text(MUTATED, encoding="utf-8")
    target.write_text(INTRUDER, encoding="utf-8")  # somebody else, mid-run

    with pytest.raises(ConcurrentModification) as exc:
        restore_or_refuse(target, MUTATED, PRISTINE, baseline)

    assert target.read_text(encoding="utf-8") == INTRUDER, "the other edit was clobbered"
    message = str(exc.value)
    assert "NOT RESTORING" in message
    assert str(target) in message
    assert digest(MUTATED) in message and digest(INTRUDER) in message


def test_the_captured_pristine_content_is_written_beside_the_target(target):
    """Nothing is lost either: the tool's own copy goes to a .orig.bak."""
    target.write_text(MUTATED, encoding="utf-8")
    target.write_text(INTRUDER, encoding="utf-8")
    with pytest.raises(ConcurrentModification):
        restore_or_refuse(target, MUTATED, PRISTINE, digest(PRISTINE))
    backup = target.with_suffix(".py.orig.bak")
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == PRISTINE


def test_restoring_something_other_than_the_baseline_is_also_a_refusal(target):
    """ "The tool restored something different from what it saved."

    Passing an ``original`` that does not hash to the recorded baseline stands
    in for the restoring write itself being raced. Either way the file no longer
    matches how the run found it, and that has to be loud.
    """
    target.write_text(MUTATED, encoding="utf-8")
    with pytest.raises(ConcurrentModification) as exc:
        restore_or_refuse(target, MUTATED, INTRUDER, digest(PRISTINE))
    assert "does not match the baseline" in str(exc.value)
    assert digest(PRISTINE) in str(exc.value)


# -------------------------------------------------------------- end to end


class FakeSuite:
    """A stand-in for ``run_suite``, scripted call by call.

    ``on_call`` lets a test make the "suite" modify the target as a side
    effect, which is how concurrent modification is simulated without a second
    process.
    """

    def __init__(self, results, on_call=None):
        self.results = list(results)
        self.on_call = on_call or {}
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls in self.on_call:
            self.on_call[self.calls]()
        return self.results[min(self.calls, len(self.results)) - 1]


def test_main_reports_a_pinned_guard(target, monkeypatch, capsys):
    monkeypatch.setattr(
        "tools.mutate_guards.run_suite",
        FakeSuite([(True, "green"), (False, "test_the_guard")]),
    )
    code = main([""], targets={"t": target}, mutations=[GUARD])
    assert code == 0
    assert "pinned" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8") == PRISTINE


def test_main_reports_an_unpinned_guard(target, monkeypatch, capsys):
    monkeypatch.setattr("tools.mutate_guards.run_suite", FakeSuite([(True, "green")]))
    code = main([""], targets={"t": target}, mutations=[GUARD])
    assert code == 1
    assert "UNPINNED" in capsys.readouterr().out
    assert target.read_text(encoding="utf-8") == PRISTINE


def test_main_refuses_to_conclude_anything_from_a_red_baseline(target, monkeypatch, capsys):
    monkeypatch.setattr("tools.mutate_guards.run_suite", FakeSuite([(False, "already red")]))
    code = main([""], targets={"t": target}, mutations=[GUARD])
    assert code == 2
    assert "BASELINE IS RED" in capsys.readouterr().out


def test_main_exits_non_zero_and_does_not_clobber_a_concurrent_edit(target, monkeypatch, capsys):
    """The end-to-end form of defect 1.

    The second call to the "suite" writes to the target, exactly as another
    process would. The run must stop, say so, keep the other edit, and exit
    non-zero -- not finish quietly with a report nobody can trust.
    """

    def intrude() -> None:
        target.write_text(INTRUDER, encoding="utf-8")

    monkeypatch.setattr(
        "tools.mutate_guards.run_suite",
        FakeSuite([(True, "green"), (False, "test_the_guard")], on_call={2: intrude}),
    )

    code = main([""], targets={"t": target}, mutations=[GUARD])

    assert code == 3
    assert target.read_text(encoding="utf-8") == INTRUDER, "the other edit was clobbered"
    out = capsys.readouterr().out
    assert "ABORTING" in out
    assert "NOT RESTORING" in out
    assert target.with_suffix(".py.orig.bak").read_text(encoding="utf-8") == PRISTINE


def test_main_rejects_an_unknown_target_name(target, monkeypatch, capsys):
    monkeypatch.setattr("tools.mutate_guards.run_suite", FakeSuite([(True, "green")]))
    code = main(["", "nope"], targets={"t": target}, mutations=[GUARD])
    assert code == 2
    assert "unknown target" in capsys.readouterr().out


def test_a_stale_mutation_is_reported_as_unpinned(target, monkeypatch, capsys):
    """A mutation that never applied looks exactly like a guard that was pinned,
    so it is counted against the run rather than skipped."""
    monkeypatch.setattr("tools.mutate_guards.run_suite", FakeSuite([(True, "green")]))
    stale = Mutation("t", "no longer there", r"if nothing_like_this:", "if False:")
    code = main([""], targets={"t": target}, mutations=[stale])
    assert code == 1
    assert "STALE" in capsys.readouterr().out


# ----------------------------------------------------- the real mutation table


@pytest.mark.pristine
def test_every_real_mutation_matches_its_real_target_exactly_once():
    """The table is checked against the live sources without mutating them.

    A pattern that has drifted out of sync with the source it describes would
    otherwise only surface as a STALE line in a run somebody has to remember to
    read.
    """
    import re

    from tools.mutate_guards import MUTATIONS, TARGETS

    drifted = []
    for mut in MUTATIONS:
        source = TARGETS[mut.target].read_text(encoding="utf-8")
        found = len(re.findall(mut.pattern, source))
        if found != 1:
            drifted.append(f"{mut.target}/{mut.label}: matched {found} times")
    assert not drifted, "stale mutation patterns:\n" + "\n".join(drifted)


@pytest.mark.pristine
def test_every_target_file_exists():
    from tools.mutate_guards import MUTATIONS, TARGETS

    for name, path in TARGETS.items():
        assert path.exists(), f"target {name} points at {path}, which is not there"
    assert {m.target for m in MUTATIONS} == set(TARGETS), (
        "a target with no mutations, or a mutation with no target"
    )
