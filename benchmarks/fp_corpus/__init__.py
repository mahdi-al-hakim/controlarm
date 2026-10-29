"""The paired false-positive corpus: the benchmark's ground truth.

Sixteen catalogued false verdicts plus three extensions, each as a **pair**: one
fixture exhibiting the false signal, and a sibling where the very same signal is
genuine. The pairing is the whole design. A corpus of false positives alone can
only measure a gate's catches, and a tool that reports only its catches is
exactly the instrument the method forbids.

The three extensions beyond the sixteen are labelled as such:

* ``ext17`` -- a fourth self-inflicted false positive (a detector pointed at the
  PoC instead of the source). The catalogue's own enumeration lists three of the
  four items in its section 3.6, which is why the headline count is sixteen and
  not seventeen. The fourth is included and labelled rather than quietly folded
  into the total.
* ``hard18`` and ``hard19`` -- the two documented near-misses, a true finding
  nearly retracted and a second code path wrongly cleared, both because the PoC
  could not express the positive. They are the corpus's only evidence that the
  gates' false-negative rate is not zero, so a benchmark without them would be
  measuring the flattering half.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CASES_DIR",
    "CRITIC_DIR",
    "HOLDOUT_DIR",
    "REQUIRED_FIELDS",
    "Case",
    "load_cases",
    "load_critic",
    "load_holdout",
    "pairs",
]

CASES_DIR = Path(__file__).parent / "cases"

#: Written after ``benchmarks/gates.py`` and specifically to attack the
#: implementation rather than the rule. Loaded separately and scored separately,
#: because folding it into the headline would hide the one number that is not
#: circular. See ``holdout/08_adversarial_holdout.json`` for the caveats.
HOLDOUT_DIR = Path(__file__).parent / "holdout"

#: Twelve cases written by an independent research critic against
#: ``benchmarks/gates.py`` as implemented, together with that reviewer's own
#: runner and fair baseline. This is the only subcorpus somebody else wrote, so
#: it is the honest headline for C2 and it is a permanent fixture: four of the
#: six failures it found are now repaired and two are published unfixed, and all
#: twelve stay in the tree as regression tests either way.
CRITIC_DIR = Path(__file__).parent / "critic"

#: Ground-truth classes, derived from ``correct_verdict`` alone so that the
#: mapping is auditable and no case can be labelled two ways.
VERDICT_CLASS = {
    "CANDIDATE": "FINDING",
    "KILL": "NO_BUG",
    "VOID": "UNINTERPRETABLE",
    "CONFOUNDED": "UNINTERPRETABLE",
    "INCONCLUSIVE": "UNINTERPRETABLE",
    "NO-TESTS": "UNINTERPRETABLE",
}

#: Keys a gate must never see. ``load_cases`` keeps them out of ``observation``
#: by construction, and ``tests/test_benchmark.py`` re-checks it.
LABEL_KEYS = frozenset(
    {
        "asserts_absence",
        "conclusion_in_fixture",
        "correct_decision",
        "correct_verdict",
        "label_basis",
        "label_rule",
        "member",
        "naive_oracle_strength",
        "gated_oracle_strength",
        "note",
        "shape",
        "shape_title",
    }
)

#: Every field a case record must carry. ``asserts_absence``,
#: ``conclusion_in_fixture`` and ``label_rule`` were added after an external
#: critique and are required rather than optional, because each one exists to
#: stop a class of quiet error and an optional field can be omitted by whoever
#: finds it inconvenient.
REQUIRED_FIELDS = (
    "id",
    "shape",
    "shape_title",
    "catalogue_ref",
    "member",
    "correct_decision",
    "correct_verdict",
    "naive_oracle_strength",
    "gated_oracle_strength",
    "note",
    "observation",
    "asserts_absence",
    "conclusion_in_fixture",
    "label_rule",
)


@dataclass(frozen=True)
class Case:
    id: str
    shape: str
    shape_title: str
    catalogue_ref: str
    member: str  # "false" | "genuine"
    correct_decision: str  # "REFUSED" | "SUPPORTED"
    correct_verdict: str
    naive_oracle_strength: int
    gated_oracle_strength: int
    note: str
    observation: dict
    source_file: str
    #: Whether this fixture's claim is that **nothing is there**. Stated, not
    #: inferred from the ``claim`` string: an external reviewer found that the
    #: headline "untrustworthy negative" count had been computed over every
    #: ``UNINTERPRETABLE`` case, four of which make non-negative claims (a
    #: finding, an over-broad finding, and two claims about a metric). The
    #: denominator was wrong, so the membership is now a label like any other.
    asserts_absence: bool = False
    #: Whether the fixture hands the gate its own conclusion as a literal field.
    #: ``True`` means the hard inferential step was performed by whoever wrote
    #: the JSON, so the case measures a lookup rather than a detector and is
    #: **excluded from the headline count** while still being scored and
    #: published. Only ``hard19`` is marked: the set of code paths a target
    #: reaches is the whole difficulty, and no fixture can make a gate derive it.
    conclusion_in_fixture: bool = False
    #: The gate rule the label's own mechanism belongs to. Asserted against the
    #: rule that actually decided the case, so that a case cannot pass through a
    #: different gate than the one it was written to test -- which is how one of
    #: the adversarial holdout's two passes turned out to be an accident.
    label_rule: str = ""
    label_basis: str = ""

    @property
    def truth_class(self) -> str:
        return VERDICT_CLASS[self.correct_verdict]

    @property
    def claim(self) -> str:
        return self.observation.get("claim", "")

    @property
    def is_untrustworthy_negative(self) -> bool:
        """Ground truth is a negative that cannot be relied on. The headline set.

        Three conditions, all of them labels: the correct answer is a refusal
        naming the rig, the fixture's claim is an absence, and the fixture does
        not state the gate's conclusion as a field.
        """
        return (
            self.truth_class == "UNINTERPRETABLE"
            and self.asserts_absence
            and not self.conclusion_in_fixture
        )


def load_cases(cases_dir: Path | None = None) -> list[Case]:
    """Read every committed case file, in filename order, then id order."""
    root = cases_dir or CASES_DIR
    out: list[Case] = []
    for path in sorted(root.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for record in payload["cases"]:
            missing = [k for k in REQUIRED_FIELDS if k not in record]
            if missing:
                raise ValueError(f"{path.name}: case {record.get('id')!r} is missing {missing}")
            leaked = LABEL_KEYS & set(record["observation"])
            if leaked:
                raise ValueError(
                    f"{path.name}: case {record['id']!r} leaks label keys {sorted(leaked)} into "
                    "its observation. A gate that can read the label is not being measured."
                )
            out.append(
                Case(
                    id=record["id"],
                    shape=record["shape"],
                    shape_title=record["shape_title"],
                    catalogue_ref=record["catalogue_ref"],
                    member=record["member"],
                    correct_decision=record["correct_decision"],
                    correct_verdict=record["correct_verdict"],
                    naive_oracle_strength=int(record["naive_oracle_strength"]),
                    gated_oracle_strength=int(record["gated_oracle_strength"]),
                    note=record["note"],
                    asserts_absence=bool(record["asserts_absence"]),
                    conclusion_in_fixture=bool(record["conclusion_in_fixture"]),
                    label_rule=str(record["label_rule"]),
                    label_basis=record.get("label_basis", ""),
                    observation=record["observation"],
                    source_file=path.name,
                )
            )
    return sorted(out, key=lambda c: (c.source_file, c.id))


def pairs(cases: list[Case] | None = None) -> dict[str, dict[str, Case]]:
    """``{shape: {"false": case, "genuine": case}}``. Incomplete pairs are kept
    so the self-consistency test can name them rather than silently pass."""
    grouped: dict[str, dict[str, Case]] = {}
    for case in cases if cases is not None else load_cases():
        grouped.setdefault(case.shape, {})[case.member] = case
    return grouped


def load_holdout() -> list[Case]:
    """The adversarial holdout. Never merged into :func:`load_cases`."""
    return load_cases(HOLDOUT_DIR)


def load_critic() -> list[Case]:
    """The external reviewer's set. Never merged into :func:`load_cases`."""
    return load_cases(CRITIC_DIR)
