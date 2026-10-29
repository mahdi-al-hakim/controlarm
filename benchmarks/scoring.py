"""Precision, recall and the three-class confusion matrix.

The positive class is **genuine**: a case where the signal really is evidence
about the target. So

* ``recall`` answers "of the true findings, how many did the gate let through",
  which is the number the private corpus never had and GAP-6 names as missing;
* ``precision`` answers "of what the gate let through, how much was real".

Recall is the headline because a gate's catches are the easy half to publish. A
gate scoring 1.00 precision and 0.70 recall is a publishable honest result; a
gate that publishes only precision is not a measurement.

The confusion matrix is three-class, not two, because ``UNINTERPRETABLE``
(``VOID`` / ``CONFOUNDED`` / ``INCONCLUSIVE``) is a distinct outcome from
"no bug" and the whole of claim C1 is the difference between them.

An earlier version of this docstring said that the naive configuration cannot
emit ``UNINTERPRETABLE`` at all, "which is the point rather than a bug in the
baseline". That sentence was doing more work than it looked like: it converted
the headline from a comparison into a restatement of two output alphabets, and
an external reviewer said so. The naive arm's inability to express the correct
class is **why it is no longer the comparison**. It is retained and reported as
the corpus's provenance -- it is the check that actually produced each
catalogued error -- and the comparison is against ``gates._fair``, which can
emit every class in :data:`CLASSES`. See ``benchmarks/gates.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["CLASSES", "Confusion", "Score", "classify_result", "confusion", "score"]

CLASSES = ("FINDING", "NO_BUG", "UNINTERPRETABLE")

_UNINTERPRETABLE = frozenset({"VOID", "CONFOUNDED", "INCONCLUSIVE", "NO-TESTS"})


def classify_result(decision: str, verdict: str) -> str:
    """Map a gate result onto the three predicted classes.

    Deliberately keyed on the *verdict*, not the decision: a refusal that names
    the rig (``VOID``) and a refusal that clears the target (``KILL``) are
    different answers to the operator, and collapsing them would hide exactly
    the effect C1 predicts.
    """
    if verdict in _UNINTERPRETABLE:
        return "UNINTERPRETABLE"
    if decision == "SUPPORTED" and verdict == "CANDIDATE":
        return "FINDING"
    if decision == "SUPPORTED" and verdict in ("KILL", "no-bug"):
        # The naive baseline "supports" a clean-negative claim by asserting
        # there is no bug. That is a NO_BUG prediction, not a finding.
        return "NO_BUG"
    if decision == "REFUSED" and verdict == "CANDIDATE":
        # A refusal whose only recorded verdict is CANDIDATE: the naive
        # baseline rejecting a clean-negative claim because an arm executed.
        return "FINDING"
    return "NO_BUG"


@dataclass(frozen=True)
class Score:
    """Binary scoring with ``genuine`` as the positive class."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return None if denom == 0 else self.tp / denom

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self) -> float | None:
        return None if self.total == 0 else (self.tp + self.tn) / self.total

    def plus(self, member: str, decision: str) -> Score:
        supported = decision == "SUPPORTED"
        if member == "genuine":
            return Score(self.tp + supported, self.fp, self.fn + (not supported), self.tn)
        return Score(self.tp, self.fp + supported, self.fn, self.tn + (not supported))

    def as_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }


@dataclass(frozen=True)
class Confusion:
    """``cells[(truth, predicted)] -> count`` over :data:`CLASSES`."""

    cells: dict[tuple[str, str], int]

    def get(self, truth: str, predicted: str) -> int:
        return self.cells.get((truth, predicted), 0)

    def row_total(self, truth: str) -> int:
        return sum(v for (t, _), v in self.cells.items() if t == truth)

    def correct(self) -> int:
        return sum(v for (t, p), v in self.cells.items() if t == p)

    def total(self) -> int:
        return sum(self.cells.values())

    def as_dict(self) -> dict:
        return {f"{t}->{p}": self.cells.get((t, p), 0) for t in CLASSES for p in CLASSES} | {
            "correct": self.correct(),
            "total": self.total(),
        }


def score(observations: list[tuple[str, str]]) -> Score:
    """``observations`` is ``[(member, decision), ...]``."""
    out = Score()
    for member, decision in observations:
        out = out.plus(member, decision)
    return out


def confusion(observations: list[tuple[str, str]]) -> Confusion:
    """``observations`` is ``[(truth_class, predicted_class), ...]``."""
    cells: dict[tuple[str, str], int] = {}
    for truth, predicted in observations:
        for value in (truth, predicted):
            if value not in CLASSES:
                raise ValueError(f"{value!r} is not one of {CLASSES}")
        cells[(truth, predicted)] = cells.get((truth, predicted), 0) + 1
    return Confusion(cells)
