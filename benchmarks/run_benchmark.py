"""Run the three measurements and write the committed results.

    python benchmarks/run_benchmark.py            # measure and write results/
    python benchmarks/run_benchmark.py --check    # measure and diff against results/

``--check`` is what CI runs: it recomputes everything and fails if the committed
numbers no longer reproduce. A benchmark whose results file can drift from its
scorer is a benchmark that can be quietly improved after the fact.

What is measured, and what is not
---------------------------------
**C2** -- precision and recall of the gates over the paired corpus, per false
positive shape and overall, recall first.

**C1** -- every corpus case under **three** arms, as a three-class confusion
matrix per arm. The falsifiable prediction is *not* better detection. It is that
an unguarded configuration turns untrustworthy negatives into "no bug" while the
guarded configuration turns the same runs into ``VOID`` / ``CONFOUNDED`` /
``INCONCLUSIVE``.

The three arms, and why there are three rather than two: an external reviewer
established that the original comparison arm could emit only ``CANDIDATE`` and
``no-bug``, so its score on the cases the headline is computed over was fixed
before any fixture was read. The primary comparison is therefore against
``fair`` -- a competent engineer with no library who reads their own positive
control, reads the number they are reporting, and may abstain. ``naive`` is
retained as a third arm because it is the check that actually produced each
catalogued error, which is the corpus's provenance, and it is labelled as
provenance rather than as a comparison.

The headline denominator was also wrong. It was computed over all eleven
``UNINTERPRETABLE`` cases; only seven of those make a negative claim at all, and
one of the seven states the gate's conclusion as a literal field. The headline
set is now the six cases that are untrustworthy negatives *and* make the gate
derive its answer, and the membership is a declared label on each fixture rather
than something inferred from a claim string.

**The oracle experiment** -- the target held fixed, the lattice held fixed, and
only the oracle varied. See ``oracle_experiment.py``.

The thing none of the three measures is whether any of this generalises. The
corpus is derived from the same catalogue the gates are derived from, so C2 is
substantially circular and the results file says so in its own words rather than
in a footnote.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from math import comb
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from benchmarks import gates  # noqa: E402
from benchmarks.fp_corpus import (  # noqa: E402
    Case,
    load_cases,
    load_critic,
    load_holdout,
    pairs,
)
from benchmarks.oracle_experiment import run_oracle_experiment  # noqa: E402
from benchmarks.scoring import CLASSES, Score, classify_result, confusion, score  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results"

#: ``gated`` is the thing being measured, ``fair`` is the primary comparison and
#: ``naive`` is the corpus's provenance. See ``benchmarks/gates.py``.
CONFIGS = gates.ARMS


def _adjudicate_all(cases: list[Case]) -> dict[str, dict[str, gates.GateResult]]:
    """``{arm: {case_id: result}}``. The observation is the only input."""
    return {
        config: {case.id: gates.adjudicate(case.observation, arm=config) for case in cases}
        for config in CONFIGS
    }


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p for the 2x2 table ``[[a, b], [c, d]]``. Stdlib only.

    Computed rather than quoted, because the one number this project most needs
    to publish is the one that says its headline comparison is not significant,
    and a number a reader cannot recompute from the committed results is a
    number they have to take on trust. Summing every table whose probability is
    at most the observed table's is the conventional two-sided definition.

    An external reviewer's point stands and is the reason this exists: at these
    denominators the interesting question is not the point estimate but whether
    anything is distinguishable at all.
    """
    n = a + b + c + d
    if n == 0 or (a + b) == 0 or (c + d) == 0 or (a + c) == 0 or (b + d) == 0:
        return 1.0

    def probability(x: int) -> float:
        return comb(a + c, x) * comb(b + d, (a + b) - x) / comb(n, a + b)

    observed = probability(a)
    low, high = max(0, (a + b) - (b + d)), min(a + b, a + c)
    return min(
        1.0,
        sum(
            probability(x) for x in range(low, high + 1) if probability(x) <= observed * (1 + 1e-9)
        ),
    )


# ------------------------------------------------------------------------ C2


def measure_c2(cases: list[Case], results: dict[str, dict[str, gates.GateResult]]) -> dict:
    out: dict = {"by_shape": {}, "overall": {}}
    grouped = pairs(cases)
    for config in CONFIGS:
        per_shape = {}
        for shape, members in sorted(grouped.items()):
            obs = [(m.member, results[config][m.id].decision) for m in members.values()]
            per_shape[shape] = score(obs).as_dict()
        overall = score([(c.member, results[config][c.id].decision) for c in cases])
        out["by_shape"][config] = per_shape
        out["overall"][config] = overall.as_dict()
    out["per_case"] = {
        case.id: {
            "shape": case.shape,
            "member": case.member,
            "correct_decision": case.correct_decision,
            "correct_verdict": case.correct_verdict,
            "label_rule": case.label_rule,
            "asserts_absence": case.asserts_absence,
            "conclusion_in_fixture": case.conclusion_in_fixture,
        }
        | {
            config: {
                "decision": results[config][case.id].decision,
                "verdict": results[config][case.id].verdict,
                "rule": results[config][case.id].rule,
                "fired": list(results[config][case.id].fired),
                "agrees": results[config][case.id].decision == case.correct_decision,
            }
            for config in CONFIGS
        }
        for case in cases
    }
    # Which lattice and oracle rules the corpus actually exercises. The reviewer
    # computed this census by hand and found B-stale-control and B-reachability
    # firing zero times across all 38 cases while the results file reported
    # catalogue coverage as complete. It is published now so the claim cannot
    # drift from the fact again.
    census: dict[str, int] = {}
    for case in cases:
        for rule in results["gated"][case.id].fired or ():
            census[rule] = census.get(rule, 0) + 1
    out["gated_fired_rule_census"] = dict(sorted(census.items()))
    # Claim C3(a): false-positive rate against the operator-declared strength of
    # the oracle the check used. OPERATOR_SUPPLIED, not measured -- the strength
    # labels are a judgement about each fixture, so this table is a restatement
    # of those judgements and cannot confirm them.
    strength: dict[str, dict] = {}
    for case in cases:
        declared = (
            ("gated", "gated_oracle_strength"),
            ("fair", "naive_oracle_strength"),
            ("naive", "naive_oracle_strength"),
        )
        for config, field in declared:
            key = f"{config}/strength-{getattr(case, field)}"
            row = strength.setdefault(key, {"cases": 0, "wrong": 0})
            row["cases"] += 1
            row["wrong"] += results[config][case.id].decision != case.correct_decision
    for row in strength.values():
        row["error_rate"] = row["wrong"] / row["cases"] if row["cases"] else None
    out["c3a_error_rate_by_declared_oracle_strength"] = dict(sorted(strength.items()))
    out["c3a_provenance"] = "OPERATOR_SUPPLIED"
    return out


#: What the external reviewer measured **before** any repair, taken from their
#: own run of ``benchmarks/fp_corpus/critic/run_critic.py --critic`` against the
#: gates as they stood at the time of the review. Hard-coded here on purpose:
#: the point of publishing a repair is that the reader can see what it was a
#: repair *of*, and a pre-fix number recomputed from the fixed code is not a
#: pre-fix number. ``GAPS.md`` G2c lists every case and its disposition.
CRITIC_PREFIX = {
    "cases": 12,
    "failures": ["c01-false", "c02-false", "c03-genuine", "c04-false", "c05-false", "c06-false"],
    "recall": 5 / 6,
    "precision": 0.5,
    "accuracy": 0.5,
    "tp": 5,
    "fn": 1,
    "fp": 5,
    "tn": 1,
}

#: The same, for the three-arm table on the committed corpus: the reviewer
#: computed it over all eleven ``UNINTERPRETABLE`` cases and over the seven of
#: those that make a negative claim.
C1_PREFIX = {
    "uninterpretable_cases": 11,
    "negative_cases": 7,
    "gated_no_bug": 0,
    "fair_no_bug": 2,
    "naive_no_bug": 7,
    "gated_accuracy": 38 / 38,
    "fair_accuracy": 27 / 38,
    "naive_accuracy": 19 / 38,
}


def measure_external() -> dict:
    """Score the independent reviewer's set. The honest headline for C2.

    Written by someone other than the gates' author, against the gates as
    implemented. Four of the six failures it found are repaired and two are
    published unfixed; all twelve stay in the tree either way, and the pre-fix
    numbers are carried alongside so the repair is auditable rather than
    retroactive.
    """
    cases = load_critic()
    results = _adjudicate_all(cases)
    grouped = pairs(cases)
    out: dict = {
        "cases": len(cases),
        "pairs": len(grouped),
        "author": "an independent research critic",
        "pre_fix": CRITIC_PREFIX,
        "by_shape": {},
        "overall": {},
    }
    for config in CONFIGS:
        out["by_shape"][config] = {
            shape: score(
                [(m.member, results[config][m.id].decision) for m in members.values()]
            ).as_dict()
            for shape, members in sorted(grouped.items())
        }
        out["overall"][config] = score(
            [(c.member, results[config][c.id].decision) for c in cases]
        ).as_dict()
    out["failures"] = [
        {
            "id": c.id,
            "shape": c.shape,
            "expected": c.correct_decision,
            "got": results["gated"][c.id].decision,
            "verdict": results["gated"][c.id].verdict,
            "rule": results["gated"][c.id].rule,
            "error_kind": (
                "false-negative (a genuine case the gate rejected)"
                if c.member == "genuine"
                else "false-positive (a false signal the gate accepted)"
            ),
            "why_the_gate_was_wrong": c.label_basis or c.note,
        }
        for c in cases
        if results["gated"][c.id].decision != c.correct_decision
    ]
    out["repaired"] = sorted(
        c.id
        for c in cases
        if c.id in CRITIC_PREFIX["failures"]
        and results["gated"][c.id].decision == c.correct_decision
    )
    out["published_unfixed"] = sorted(
        c.id
        for c in cases
        if c.id in CRITIC_PREFIX["failures"]
        and results["gated"][c.id].decision != c.correct_decision
    )
    return out


def measure_holdout() -> dict:
    """Score the adversarial holdout, and do not fix what it breaks.

    The holdout was written after the gates and aimed at the implementation, so
    it is the only part of C2 that is not circular. Its failures are recorded
    here as named gaps. Repairing the gates until this passes would rebuild the
    circularity it exists to break; the correct response is to publish the
    failures and let a reviewer judge whether the rule or the vocabulary was
    encoded.
    """
    cases = load_holdout()
    results = _adjudicate_all(cases)
    out: dict = {"cases": len(cases), "pairs": len(pairs(cases)), "by_shape": {}, "overall": {}}
    grouped = pairs(cases)
    for config in CONFIGS:
        out["by_shape"][config] = {
            shape: score(
                [(m.member, results[config][m.id].decision) for m in members.values()]
            ).as_dict()
            for shape, members in sorted(grouped.items())
        }
        out["overall"][config] = score(
            [(c.member, results[config][c.id].decision) for c in cases]
        ).as_dict()
    out["failures"] = [
        {
            "id": c.id,
            "shape": c.shape,
            "expected": c.correct_decision,
            "got": results["gated"][c.id].decision,
            "verdict": results["gated"][c.id].verdict,
            "rule": results["gated"][c.id].rule,
            "error_kind": (
                "false-negative (a genuine case the gate rejected)"
                if c.member == "genuine"
                else "false-positive (a false signal the gate accepted)"
            ),
            "why_the_gate_was_wrong": c.label_basis or c.note,
        }
        for c in cases
        if results["gated"][c.id].decision != c.correct_decision
    ]
    return out


# ------------------------------------------------------------------------ C1


def measure_c1(cases: list[Case], results: dict[str, dict[str, gates.GateResult]]) -> dict:
    out: dict = {}
    for config in CONFIGS:
        obs = [
            (
                case.truth_class,
                classify_result(
                    results[config][case.id].decision, results[config][case.id].verdict
                ),
            )
            for case in cases
        ]
        matrix = confusion(obs)
        out[config] = matrix.as_dict()
        out[config]["accuracy"] = matrix.correct() / matrix.total()

    # The headline sub-measurement: cases whose ground truth is an UNTRUSTWORTHY
    # NEGATIVE -- a run whose silence is a property of the rig. Nothing about
    # the target can be concluded from them, and that is the whole prediction.
    #
    # Three conditions, all three of them declared labels on the fixture, after
    # an external reviewer showed that this set had been computed as "every
    # UNINTERPRETABLE case" and was therefore wrong in two ways at once:
    #
    #   * ``truth_class == UNINTERPRETABLE``   the correct answer names the rig;
    #   * ``asserts_absence``                  the fixture's claim is an absence.
    #     Four of the original eleven are not negatives at all -- one is a
    #     finding, one an over-broad finding, two are claims about a metric --
    #     and counting them under a headline that reads "ground truth is an
    #     untrustworthy negative" is a category error;
    #   * ``not conclusion_in_fixture``        the gate has to derive its
    #     answer. One case (``hard19``) hands the gate the set of code paths the
    #     target reaches, which in reality is the entire difficulty, and no
    #     fixture can be written that makes a gate derive it. It is still scored
    #     and still published; it is excluded from the headline and reported
    #     separately, because a case that measures a lookup cannot carry a claim
    #     about a detector.
    untrustworthy = [c for c in cases if c.is_untrustworthy_negative]
    excluded = [
        c
        for c in cases
        if c.truth_class == "UNINTERPRETABLE" and c.asserts_absence and c.conclusion_in_fixture
    ]
    not_negatives = [
        c for c in cases if c.truth_class == "UNINTERPRETABLE" and not c.asserts_absence
    ]
    detail = {}
    for config in CONFIGS:
        classes = [
            classify_result(results[config][c.id].decision, results[config][c.id].verdict)
            for c in untrustworthy
        ]
        detail[config] = {
            "cases": len(untrustworthy),
            "called_no_bug": classes.count("NO_BUG"),
            "called_finding": classes.count("FINDING"),
            "called_uninterpretable": classes.count("UNINTERPRETABLE"),
            "false_negative_rate": classes.count("NO_BUG") / len(untrustworthy),
            "refused_to_call_rate": classes.count("UNINTERPRETABLE") / len(untrustworthy),
        }
    out["untrustworthy_negatives"] = detail
    out["untrustworthy_negative_ids"] = [c.id for c in untrustworthy]
    # The number that decides whether the headline is a result. Gated versus the
    # fair arm, counts of "called no bug" against "did not", as a 2x2.
    n = len(untrustworthy)
    gated_nb = detail["gated"]["called_no_bug"]
    fair_nb = detail["fair"]["called_no_bug"]
    naive_nb = detail["naive"]["called_no_bug"]
    out["fisher"] = {
        "gated_vs_fair": fisher_two_sided(fair_nb, n - fair_nb, gated_nb, n - gated_nb),
        "gated_vs_naive": fisher_two_sided(naive_nb, n - naive_nb, gated_nb, n - gated_nb),
        "unit": "case",
        "note": (
            "Two-sided Fisher exact on 'called no bug' versus 'did not', over the "
            "untrustworthy-negative set. The gated-versus-fair figure is the one that "
            "carries the claim; the gated-versus-naive figure is reported for completeness "
            "and is not a comparison, because the naive arm cannot emit a refusal verdict."
        ),
    }
    out["denominator_audit"] = {
        "all_uninterpretable": [c.id for c in cases if c.truth_class == "UNINTERPRETABLE"],
        "excluded_not_a_negative": [{"id": c.id, "claim": c.claim} for c in not_negatives],
        "excluded_conclusion_in_fixture": [c.id for c in excluded],
        "headline": [c.id for c in untrustworthy],
    }
    out["excluded_conclusion_in_fixture"] = {
        config: {
            "cases": len(excluded),
            "called_no_bug": sum(
                classify_result(results[config][c.id].decision, results[config][c.id].verdict)
                == "NO_BUG"
                for c in excluded
            ),
        }
        for config in CONFIGS
    }
    return out


# ------------------------------------------------------------------- rendering


def _shape_table(c2: dict, grouped: dict) -> list[str]:
    lines = [
        "| FP shape | recall | precision | tp | fn | fp | tn | gate rule that fired |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for shape in sorted(grouped):
        s = c2["by_shape"]["gated"][shape]
        rules = sorted(
            {
                c2["per_case"][m.id]["gated"]["rule"]
                for m in grouped[shape].values()
                if c2["per_case"][m.id]["gated"]["decision"] == "REFUSED"
            }
        )
        lines.append(
            f"| `{shape}` | **{_fmt(s['recall'])}** | {_fmt(s['precision'])} | {s['tp']} | "
            f"{s['fn']} | {s['fp']} | {s['tn']} | {', '.join(rules) or '-'} |"
        )
    return lines


def _matrix_table(block: dict) -> list[str]:
    lines = [
        "| ground truth \\ predicted | FINDING | NO_BUG | UNINTERPRETABLE |",
        "|---|---|---|---|",
    ]
    for truth in CLASSES:
        row = " | ".join(str(block[f"{truth}->{p}"]) for p in CLASSES)
        lines.append(f"| **{truth}** | {row} |")
    return lines


def _holdout_table(hold: dict) -> list[str]:
    if not hold["failures"]:
        return [
            "The gates scored the holdout perfectly, which is itself worth distrusting:",
            "it means the holdout was not adversarial enough.",
        ]
    lines = [
        "| case | expected | the gate said | verdict | rule | error |",
        "|---|---|---|---|---|---|",
    ]
    for f in hold["failures"]:
        lines.append(
            f"| `{f['id']}` | {f['expected']} | {f['got']} | {f['verdict']} | `{f['rule']}` | "
            f"{f['error_kind']} |"
        )
    lines.append("")
    lines.append("Why each one is a real failure, not a mislabel:")
    lines.append("")
    for f in hold["failures"]:
        lines.append(f"- **`{f['id']}`** -- {f['why_the_gate_was_wrong']}")
    return lines


_ARM_LABEL = {
    "gated": "gates enforced",
    "fair": "fair unguarded baseline -- **the primary comparison**",
    "naive": "the check that produced each catalogued error -- provenance, not a comparison",
}


def _arm_table(block: dict) -> list[str]:
    rows = [
        "| arm | recall | precision | tp | fn | fp | tn |",
        "|---|---|---|---|---|---|---|",
    ]
    for arm in CONFIGS:
        s = block[arm]
        rows.append(
            f"| {_ARM_LABEL[arm]} | {_fmt(s['recall'])} | {_fmt(s['precision'])} | {s['tp']} | "
            f"{s['fn']} | {s['fp']} | {s['tn']} |"
        )
    return rows


def render_markdown(payload: dict, cases: list[Case]) -> str:
    grouped = pairs(cases)
    c2, c1, oracle = payload["c2"], payload["c1"], payload["oracle_experiment"]
    hold, ext = payload["c2_holdout"], payload["c2_external"]
    g = c2["overall"]["gated"]
    un = c1["untrustworthy_negatives"]
    audit = c1["denominator_audit"]
    excl = c1["excluded_conclusion_in_fixture"]
    det = oracle["determinate"]
    eg = ext["overall"]["gated"]
    pre = ext["pre_fix"]

    lines: list[str] = [
        "# Benchmark results",
        "",
        f"Generated by `benchmarks/run_benchmark.py` at {payload['generated']}.",
        "Reproduce with `python benchmarks/run_benchmark.py --check`, which recomputes every",
        "number below and exits non-zero if any of them has moved.",
        "",
        f"Corpus: **{len(cases)} cases** in **{len(grouped)} pairs**. Scored implementation:",
        f"`{payload['implementation']}`.",
        f"Oracle-experiment transport: {', '.join(oracle['transport'])}.",
        "",
        "> **Read this first.** An independent research critic attacked this benchmark and found",
        "> real defects. Every number below is post-repair, and every repaired number is printed",
        "> beside the pre-repair number it replaced, because a repair that hides what it repaired",
        "> is indistinguishable from a benchmark that was always right. The critique's own cases",
        "> and its runner are permanent fixtures in `benchmarks/fp_corpus/critic/`.",
        "",
        "---",
        "",
        "## The external set -- the honest headline",
        "",
        f"{ext['cases']} cases in {ext['pairs']} pairs, written by **{ext['author']}** against",
        "`benchmarks/gates.py` as implemented. This is the only subcorpus somebody other than the",
        "gates' author wrote, so it is the C2 number worth quoting.",
        "",
        "| | cases wrong | recall | precision | accuracy |",
        "|---|---|---|---|---|",
        f"| **pre-repair** (the reviewer's own run) | {len(pre['failures'])} of {pre['cases']} | "
        f"{pre['recall']:.2f} | {pre['precision']:.2f} | {pre['accuracy']:.2f} |",
        f"| **post-repair** (this run) | {len(ext['failures'])} of {ext['cases']} | "
        f"{_fmt(eg['recall'])} | {_fmt(eg['precision'])} | {_fmt(eg['accuracy'])} |",
        "",
        f"Repaired: {', '.join('`' + i + '`' for i in ext['repaired']) or 'none'}. Each was the",
        "gate failing **its own documented rule**, which is an implementation defect and not a",
        "finding about the rule:",
        "",
        "- **`c01-false`** -- the body was canonicalised before the differential and the key-set",
        "  was not, so an echo reflected into a JSON *key* name was erased from `same_body` and",
        "  survived in `same_keys`, and both the A3 and the A9 branch require `same_keys`. Rule A3",
        "  says canonicalise before *any* differential; a key-set is a differential.",
        "- **`c02-false`** -- the control-independence check compared two hosts with `==`. DNS is",
        "  case-insensitive, so `LISTENER.invalid` and `listener.invalid` are one host and one",
        "  containment. The comparison is now case-insensitive, and where a run recorded the",
        "  egress allowlist the gate derives shared containment from it rather than from equality.",
        "- **`c05-false`** -- `if expected and expected not in observed` made an *empty*",
        "  `expected_observable` short-circuit the only check that the positive control proved",
        "  anything, so VOID-1's own failure mode passed the gate written to catch it. An empty",
        "  observable is now `VOID`, and a control claimed to have run with its observable keys",
        "  absent raises rather than defaulting to the empty string.",
        "- **`c06-false`** -- the predicate flagged every line that was short and followed by a",
        "  non-blank line, which is every list item, every table row and every line of a code",
        "  fence, while its verdict text claimed that no line was a mid-paragraph hard wrap. A",
        "  wrap candidate must now sit inside a paragraph, tested against markdown block grammar.",
        "",
        "Published **unfixed**: "
        + (", ".join("`" + i + "`" for i in ext["published_unfixed"]) or "none")
        + ". These are limits of the rule, not of this implementation, and repairing them would",
        "mean encoding a judgement the project's own thesis says a mechanical check must not",
        "attempt:",
        "",
        "- **`c03-genuine`** is a **false negative manufactured by the gates**, which is the harm",
        "  `GAPS.md` G9 says this project should be judged on. `REFUSAL_MARKERS` contains bare",
        "  `denied` and `blocked`, and a refusal marker claims its own line and the next one, so a",
        "  genuine credential relay that happens to sit on the line after an unrelated",
        "  'was denied by the edge proxy' reads as a refusal quoting itself. **There is no",
        "  mechanical fix.** Dropping the two tokens re-opens the catalogue's FP#3, whose",
        "  refusals say exactly those words. Narrowing the span to the marker's own line",
        "  re-opens FP#3 too: `c03-false` is accepted without the next-line rule, because a",
        "  refusal quotes the thing it is refusing on the following line. Deciding that",
        "  'denied by the edge proxy' is an infrastructure log rather than the agent refusing",
        "  requires understanding what the sentence is *about*, which is the interpretive",
        "  judgement this project exists to keep out of oracles. Stated plainly: rule A6 cannot",
        "  be stated mechanically over vendor prose, and a token list is the best available",
        "  approximation with a known, published false-negative mode.",
        "- **`c04-false`** is a **schema gap**, and naming it as one is the honest disposition.",
        "  Rule A5 asks *who populated this field*. The implementation keys on a list of field",
        "  names, and the reviewer's fixture puts the rig's own startup configuration under the",
        "  key `host`, which is in that list. Adding `listener_startup` to the config-field list",
        "  is the same vocabulary substitution in the other direction, and holdout `h02-genuine`",
        "  already publishes what that costs. The field the gate would need -- provenance -- is",
        "  not expressible in this fixture schema, and the reason matters: a `provenance` field",
        "  *asserted by the fixture's author* would be the gate reading its own conclusion, which",
        "  is the labelling defect the same critique identified elsewhere in this corpus. Closing",
        "  this gap requires provenance **recorded by the rig at capture time**, which means",
        "  instrumenting a real collector, not editing JSON.",
        "",
        "| case | expected | the gate said | verdict | rule | error |",
        "|---|---|---|---|---|---|",
        *[
            f"| `{f['id']}` | {f['expected']} | {f['got']} | {f['verdict']} | `{f['rule']}` | "
            f"{f['error_kind']} |"
            for f in ext["failures"]
        ],
        "",
        "---",
        "",
        "## C2 -- the gates over the paired corpus",
        "",
        "Positive class is **genuine**. Recall answers the question the private corpus never",
        "asked: of the cases where the signal really is evidence, how many did the gate let",
        "through. It is first because a gate's catches are the easy half to publish.",
        "",
        *_arm_table(c2["overall"]),
        "",
        "This table is **near-circular and should be ignored**: the corpus and the gates derive",
        "from the same 16-item catalogue, so a high score means the implementation encodes the",
        "catalogue. The external set above is the number that is not circular.",
        "",
        *_shape_table(c2, grouped),
        "",
        "Every shape has exactly two cases, so a per-shape recall or precision can only be",
        "0.00, 0.50 or 1.00. The per-shape column localises a failure; it does not estimate a",
        f"rate. Only the overall row is a rate, and its denominator is {len(cases)}.",
        "",
        "### Which rules the corpus actually exercises",
        "",
        "The reviewer computed this census by hand and found `B-stale-control` and",
        "`B-reachability` firing **zero** times across all 38 cases, because `void08-false` trips",
        "three lattice preconditions at once and the gate returned on the first. The lattice now",
        "evaluates every precondition and records every one that fired, so the census is complete",
        "and the claim cannot drift from the fact again.",
        "",
        "| rule | cases in which it fired |",
        "|---|---|",
        *[f"| `{k}` | {v} |" for k, v in c2["gated_fired_rule_census"].items()],
        "",
        "### The adversarial holdout",
        "",
        f"{hold['cases']} cases in {hold['pairs']} pairs, written **after** `benchmarks/gates.py`",
        "by the gates' own author and aimed at the implementation rather than at the rule. Weaker",
        "than the external set for that reason.",
        "",
        f"**Gates enforced on the holdout: recall {_fmt(hold['overall']['gated']['recall'])}, "
        f"precision {_fmt(hold['overall']['gated']['precision'])}** "
        f"(tp {hold['overall']['gated']['tp']}, fn {hold['overall']['gated']['fn']}, "
        f"fp {hold['overall']['gated']['fp']}, tn {hold['overall']['gated']['tn']}).",
        "",
        *_holdout_table(hold),
        "",
        "These failures are **left unfixed on purpose.** They are limits of the rules rather than",
        "of the implementation: `h02-genuine` is the field-name-versus-provenance gap that",
        "`c04-false` attacks from the other side, and `h03-false` names a rule (`B-route`) that",
        "the implementation does not have at all.",
        "",
        "`h01-false` **passes, and that pass was an accident.** Its `label_basis` used to claim",
        "the arms were identical in body after canonicalisation and that A3 refused it. They are",
        "not -- `_normalise` is a literal `str.replace`, so `DOC_1001` survives a caller who",
        "supplied `doc_1001` -- and the refusal comes from A9 instead. The basis now says so,",
        "every case in every subcorpus carries a `label_rule`, and `tests/test_benchmark.py`",
        "asserts that a case which passes does so through the gate its own label names. The A3",
        "canonicalisation defect this case was written to expose is real and remains unfixed.",
        "",
        "---",
        "",
        "## C1 -- three arms over the same fixtures",
        "",
        "Three predicted classes, because `UNINTERPRETABLE` (`VOID` / `CONFOUNDED` /",
        '`INCONCLUSIVE`) is a different answer from "no bug" and the whole claim is the',
        "difference between them.",
        "",
        "The reviewer's central objection to the old version of this measurement was that its",
        "comparison arm could emit only `CANDIDATE` and `no-bug`, so its score on the cases the",
        "headline is about was **0 before any fixture was read**. That arm is still here, as",
        "provenance -- it is the check that actually produced each catalogued error -- but the",
        "comparison is now against an arm that can express the right answer.",
        "",
        *[
            line
            for arm in CONFIGS
            for line in (
                [
                    f"### {_ARM_LABEL[arm].replace('**', '')}",
                    "",
                    *_matrix_table(c1[arm]),
                    "",
                    f"Accuracy {c1[arm]['accuracy']:.2f} "
                    f"({c1[arm]['correct']}/{c1[arm]['total']}).",
                    "",
                ]
            )
        ],
        "### The denominator, audited",
        "",
        "The old headline was computed over every `UNINTERPRETABLE` case. Two things were wrong",
        "with that, and both made the number look better than it was.",
        "",
        f"- All `UNINTERPRETABLE` cases: {len(audit['all_uninterpretable'])} "
        f"({', '.join('`' + i + '`' for i in audit['all_uninterpretable'])}).",
        "- **Not negatives at all**, by the claim their own fixture makes: "
        + ", ".join(f"`{e['id']}` (claim `{e['claim']}`)" for e in audit["excluded_not_a_negative"])
        + ". One is a finding, one an over-broad finding, two are claims about a metric.",
        '  Counting them under a headline that reads "ground truth is an untrustworthy',
        '  negative" is a category error.',
        "- **Excluded because the fixture states the gate's conclusion**: "
        + ", ".join(f"`{i}`" for i in audit["excluded_conclusion_in_fixture"])
        + ". `hard19` hands the gate the set of code paths the target reaches, which in reality",
        "  is the entire difficulty. Five of the six cases the reviewer flagged this way have",
        "  been re-expressed so the gate has to derive what it used to read (see below); this one",
        "  cannot be, because no fixture can make a gate discover a target's reachable paths. It",
        f"  is still scored and still published -- gated called it no-bug "
        f"{excl['gated']['called_no_bug']} of {excl['gated']['cases']} times, fair "
        f"{excl['fair']['called_no_bug']} of {excl['fair']['cases']} -- and it is out of the",
        "  headline.",
        f"- **The headline set: {len(audit['headline'])} cases** "
        f"({', '.join('`' + i + '`' for i in audit['headline'])}).",
        "",
        "### The prediction, stated and tested",
        "",
        f"On the {un['gated']['cases']} cases whose ground truth is an untrustworthy negative:",
        "",
        "| arm | called no-bug | called a finding | refused to call | false-negative rate |",
        "|---|---|---|---|---|",
        *[
            f"| {_ARM_LABEL[arm]} | {un[arm]['called_no_bug']} | {un[arm]['called_finding']} | "
            f"{un[arm]['called_uninterpretable']} | {un[arm]['false_negative_rate']:.2f} |"
            for arm in CONFIGS
        ],
        "",
        "**Pre-repair, for comparison.** The reviewer measured, over the wrong denominator of "
        f"{C1_PREFIX['negative_cases']} negatives drawn from "
        f"{C1_PREFIX['uninterpretable_cases']} `UNINTERPRETABLE` cases: gated "
        f"{C1_PREFIX['gated_no_bug']} no-bug, fair {C1_PREFIX['fair_no_bug']}, provenance "
        f"{C1_PREFIX['naive_no_bug']}; overall accuracy "
        f"{C1_PREFIX['gated_accuracy']:.2f} / {C1_PREFIX['fair_accuracy']:.2f} / "
        f"{C1_PREFIX['naive_accuracy']:.2f}.",
        "",
        "**The honest reading of the post-repair numbers is that the effect got smaller, not",
        f"larger.** The margin over a fair baseline is now {un['fair']['called_no_bug']} of "
        f"{un['fair']['cases']} versus {un['gated']['called_no_bug']} of "
        f"{un['gated']['cases']}, which is a two-sided **Fisher exact "
        f"p = {c1['fisher']['gated_vs_fair']:.2f}** -- not distinguishable from no effect, and",
        "not close to it. Against the provenance arm the same test gives "
        f"p = {c1['fisher']['gated_vs_naive']:.4f}, but that arm cannot emit a refusal verdict",
        "so the figure measures its output alphabet rather than its judgement. The",
        "cases are one author's recalled history rather than a sample of anything, so they are",
        "counts and not rates. Dropping `hard19` from the denominator removed one of the two",
        "cases that carried the entire pre-repair margin; re-expressing `void09` kept the other",
        "one, but it now rests on the gate deriving shared containment from the recorded egress",
        "allowlist rather than on `str.__eq__` over two labels an author chose.",
        "",
        "### Fixtures re-expressed so the gate must derive its answer",
        "",
        "The reviewer found that for 6 of the 11 cases the old headline was computed over, the",
        "fixture wrote the rule's antecedent down as a literal -- and that the only two cases",
        "where the gates beat a fair baseline were both from that set. Five are re-expressed:",
        "",
        "- `void08` -- `reached_application_layer: false` became the probe's own transport record",
        "  (`ECONNREFUSED on tcp/8081 before any HTTP exchange`, no app-layer status), and",
        "  `control_recorded_in_run: false` became the run's start and end stamps against the",
        "  control record's stamp. The gate derives both.",
        "- `void09` -- the two arms now target **different** hosts, so no equality test can decide",
        "  the case. The gate reads the egress allowlist that was in force and establishes that it",
        '  covers neither host, which is what "the control tested the same containment" means.',
        "- `ext17` -- the scanned artifact is derived from the detector's recorded invocation (its",
        "  argv and the files it opened) instead of being a second declared label sitting beside",
        "  the first. Only the claim side is now a declaration.",
        "- `scope13` -- one dict mapping branched fields to the fixture's own values became two",
        "  separately sourced records, the target's branch fields and the PoC's recorded values,",
        "  and the gate intersects them.",
        "- `self15` -- the fixture recorded `independent_minimum: 384` and the gate compared",
        "  against it. The fixture now records the **factor model** and the gate computes the",
        "  bound as the product of the three largest cardinalities (8 x 8 x 6 = 384).",
        "",
        "The legacy summary fields are retained where an external artifact reads them, and",
        "`tests/test_benchmark.py` poisons each one with the wrong value and asserts the verdict",
        "does not move, which is the only way to show that a gate derives rather than reads.",
        "",
        "---",
        "",
        "## The oracle experiment -- target fixed, lattice fixed, oracle varied",
        "",
        f"{oracle['probes']} probes x {len(oracle['modes'])} target modes. The control lattice is",
        "identical in both arms, so the only difference between the two rows below is which",
        "oracle read the response. Modes `refuse-all` and `unauthorized-all` are reported",
        "separately: the lattice decides those, not the oracle, and folding them in would",
        "dilute the comparison with trivially-correct rows. That exclusion also **doubles the",
        "absolute gap**, in the headline's favour, which a reader should know.",
        "",
        "| oracle | probe results | false verdicts | rate | direction of the errors |",
        "|---|---|---|---|---|",
        f"| mechanical (strength 3-4) | {det['mechanical']['probe_results']} | "
        f"{det['mechanical']['false_verdicts']} | "
        f"{det['mechanical']['false_verdict_rate']:.2f} | "
        f"{det['mechanical']['by_direction'] or '-'} |",
        f"| interpretive (strength 0-1) | {det['interpretive']['probe_results']} | "
        f"{det['interpretive']['false_verdicts']} | "
        f"{det['interpretive']['false_verdict_rate']:.2f} | "
        f"{det['interpretive']['by_direction'] or '-'} |",
        "",
        f"Mechanical oracle's wrong probes: {det['mechanical']['wrong_probes'] or 'none'}.",
        "",
        f"Interpretive oracle's wrong probes: {det['interpretive']['wrong_probes'] or 'none'}.",
        "",
        "**The direction survives; the magnitude does not.** The two target modes share one",
        "oracle function per probe, so the probe is the correct unit of analysis: that gives 1 of",
        "12 versus 7 of 12, Fisher p = 0.027, with overlapping Clopper-Pearson intervals. Drop",
        "the single probe where the mechanical oracle returns `UNINTERPRETABLE` unconditionally",
        "and no interpretive callable can, and p = 0.063. Both numerators are also authored: six",
        "probes were planted to defeat the interpretive oracle and one to defeat the mechanical",
        "one, and the measured error counts recover that ratio.",
        "",
        "In the two degenerate modes both oracles scored "
        f"{oracle['degenerate']['mechanical']['false_verdicts']} and "
        f"{oracle['degenerate']['interpretive']['false_verdicts']} false verdicts out of "
        f"{oracle['degenerate']['mechanical']['probe_results']} each, because the lattice voided",
        "every probe before either oracle ran. Said the other way round: **in half of the target",
        "configurations tested, which oracle you used made no difference at all.**",
        "",
        "---",
        "",
        "## What these numbers do not establish",
        "",
        "1. **The construct is not the one on the label.** This benchmark measures",
        "   catalogue-encoding fidelity, not negative trustworthiness. It shows whether the gates",
        "   implement the 16-item catalogue; it does not show that a negative produced under them",
        "   is trustworthy, because the cases whose ground truth is untrustworthy were labelled",
        "   by the author of the rules. See `GAPS.md` G1b.",
        "2. **C2 over the main corpus is substantially circular.** The corpus was derived from",
        "   the same 16-item catalogue as the gates. Quote the external set instead.",
        "3. **n = 38, in 19 pairs, from one operator's history.** Counts, not rates. The",
        "   Clopper-Pearson intervals reported for the oracle experiment are wide enough that the",
        "   magnitude of that effect does not survive a change in the unit of analysis.",
        "4. **The injected-defect target bounds nothing about real software.** Its ground truth",
        "   is known because somebody wrote it down.",
        "5. **The oracle experiment measures the false-positive axis much better than the",
        "   false-negative one.** On this target the interpretive oracle's errors are nearly all",
        "   false positives and the one mechanical error is a false negative.",
        "6. **The scored gate implementation lives in `benchmarks/gates.py`, not in the",
        "   package.** Until it is promoted into `src/controlarm/gates/`, this measures a",
        "   reference implementation of the rules rather than the shipping code path.",
        "7. **`CONFOUNDED` is not in the package's verdict enum.**",
        "   `controlarm.controls.run.Verdict` has five members and folds a confounded",
        "   comparison into `VOID`. The gate emits the token directly; one corpus case",
        "   (`void09-false`) depends on the distinction, and it is reported here rather than",
        "   smoothed over.",
        "8. **Two of the external set's six failures are published unfixed**, and one of them is a",
        "   false negative the gates manufacture out of ordinary log vocabulary. That is the",
        "   failure direction this project asks to be judged on.",
        "",
        "## Which claims held",
        "",
    ]

    held: list[str] = []
    fair_nb = un["fair"]["called_no_bug"]
    if un["gated"]["false_negative_rate"] == 0 and fair_nb > 0:
        held.append(
            "**C1 held in direction and is not significant in magnitude.** On the "
            f"{un['gated']['cases']} corpus cases whose ground truth is an untrustworthy "
            "negative, the guarded configuration called none of them no-bug (0 of "
            f"{un['gated']['cases']}); a fair unguarded baseline that reads its own positive "
            f"control and may abstain called {fair_nb} of {un['fair']['cases']}; the historical "
            f"check that produced each catalogued error called {un['naive']['called_no_bug']} of "
            f"{un['naive']['cases']}, but that check cannot emit a refusal verdict at all, so "
            f"its score was fixed before any fixture was read. A margin of {fair_nb} of "
            f"{un['fair']['cases']} against 0 of {un['gated']['cases']} is not distinguishable "
            "from no effect at this n."
        )
    elif un["gated"]["false_negative_rate"] == 0:
        held.append(
            "**C1's guarded half held and the comparison is now empty.** The guarded "
            f"configuration called none of the {un['gated']['cases']} untrustworthy negatives "
            "no-bug -- and neither did the fair baseline. The measured advantage over a "
            "competent engineer without this library is zero on this corpus."
        )
    else:
        held.append(
            "**C1 did NOT hold as predicted.** Guarded false-negative rate "
            f"{un['gated']['false_negative_rate']:.2f}, fair "
            f"{un['fair']['false_negative_rate']:.2f}. The predicted asymmetry is not present."
        )
    held.append(
        f"**The external set is the number to quote: the gates get {len(ext['failures'])} of "
        f"{ext['cases']} wrong** (recall {_fmt(eg['recall'])}, precision {_fmt(eg['precision'])}, "
        f"accuracy {_fmt(eg['accuracy'])}), against {len(pre['failures'])} of {pre['cases']} "
        f"before the repairs listed above. {len(ext['repaired'])} of the reviewer's "
        f"{len(pre['failures'])} failures were implementation defects and are fixed; "
        f"{len(ext['published_unfixed'])} are limits of the rule and are published unfixed."
    )
    if g["recall"] is not None and g["recall"] == 1.0:
        held.append(
            f"**C2's recall column over the main corpus is {_fmt(g['recall'])}** and is "
            "near-circular. Read it as the implementation matching its own specification, not "
            "as a measured false-negative rate for the discipline."
        )
    else:
        held.append(
            f"**C2 recall over the main corpus is {_fmt(g['recall'])}**, so the gates rejected "
            f"{g['fn']} genuine case(s). Those are published above, per shape."
        )
    hg = hold["overall"]["gated"]
    held.append(
        "**On the author-written adversarial holdout the gates scored recall "
        f"{_fmt(hg['recall'])} and precision {_fmt(hg['precision'])}** over {hold['cases']} "
        f"cases ({len(hold['failures'])} failures, listed above and left unfixed), and one of "
        "its passes turned out to be through a different gate than its label claimed."
    )
    if det["mechanical"]["false_verdict_rate"] < det["interpretive"]["false_verdict_rate"]:
        held.append(
            "**The oracle experiment reproduced the catalogue's direction**: "
            f"{_plural(det['mechanical']['false_verdicts'], 'false verdict')} for the mechanical "
            f"oracle against {det['interpretive']['false_verdicts']} for the interpretive one, "
            f"over {det['mechanical']['probe_results']} probe results each, with the target and "
            "the lattice held fixed. It is the least circular measurement here -- the target was "
            "written before either oracle -- but temporal order is not independence: the probe "
            "set and the target's defect set are both derivations of the same catalogue by the "
            "same author, and the magnitude does not survive taking the probe as the unit of "
            "analysis."
        )
    else:
        held.append(
            "**The oracle experiment did NOT reproduce the catalogue's direction**: mechanical "
            f"{det['mechanical']['false_verdicts']} versus interpretive "
            f"{det['interpretive']['false_verdicts']} false verdicts."
        )
    lines.extend(f"- {item}" for item in held)
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------------ main


def build(use_http: bool = True) -> tuple[dict, list[Case]]:
    cases = load_cases()
    results = _adjudicate_all(cases)
    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "implementation": "benchmarks/gates.py (reference implementation of the catalogue)",
        "corpus": {
            "cases": len(cases),
            "pairs": len(pairs(cases)),
            "case_ids": [c.id for c in cases],
        },
        "c2": measure_c2(cases, results),
        "c2_holdout": measure_holdout(),
        "c2_external": measure_external(),
        "c1": measure_c1(cases, results),
        "oracle_experiment": run_oracle_experiment(use_http=use_http),
    }
    return payload, cases


def _comparable(payload: dict) -> dict:
    """Everything that must reproduce exactly.

    Two fields are excluded and nothing else. ``generated`` is a timestamp. The
    oracle experiment's ``transport`` records whether the probes went over
    loopback HTTP or in-process, which is provenance rather than a measurement:
    an environment that cannot bind a port still has to reproduce the same
    verdicts, and if it ever does not, the rest of the payload says so.
    """
    out = {k: v for k, v in payload.items() if k != "generated"}
    if "oracle_experiment" in out:
        out["oracle_experiment"] = {
            k: v for k, v in out["oracle_experiment"].items() if k != "transport"
        }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="diff against the committed results")
    parser.add_argument("--no-http", action="store_true", help="probe in-process only")
    args = parser.parse_args(argv)

    payload, cases = build(use_http=not args.no_http)
    json_path, md_path = RESULTS / "fp_corpus.json", RESULTS / "fp_corpus.md"

    if args.check:
        if not json_path.exists():
            print(f"{json_path} does not exist; run without --check first", file=sys.stderr)
            return 2
        committed = json.loads(json_path.read_text(encoding="utf-8"))
        fresh, old = _comparable(payload), _comparable(committed)
        if fresh != old:
            for key in sorted(set(fresh) | set(old)):
                if fresh.get(key) != old.get(key):
                    print(f"MOVED: {key}", file=sys.stderr)
            print("committed results do not reproduce", file=sys.stderr)
            return 3
        print(f"results reproduce exactly ({len(cases)} cases)")
        return 0

    RESULTS.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload, cases), encoding="utf-8")
    overall = payload["c2"]["overall"]
    print(f"cases={len(cases)} pairs={payload['corpus']['pairs']}")
    print(
        "C2 gated:      recall="
        f"{_fmt(Score(**{k: overall['gated'][k] for k in ('tp', 'fp', 'fn', 'tn')}).recall)}"
        f" precision={_fmt(overall['gated']['precision'])}"
    )
    for arm in ("fair", "naive"):
        print(
            f"C2 {arm:9s}:  recall={_fmt(overall[arm]['recall'])}"
            f" precision={_fmt(overall[arm]['precision'])}"
        )
    ext = payload["c2_external"]
    eg = ext["overall"]["gated"]
    print(
        f"External set ({ext['cases']} cases, independent author): "
        f"{len(ext['failures'])} wrong (was {len(ext['pre_fix']['failures'])}), "
        f"recall={_fmt(eg['recall'])} precision={_fmt(eg['precision'])}"
    )
    un = payload["c1"]["untrustworthy_negatives"]
    print(
        f"C1 untrustworthy negatives ({un['gated']['cases']}, "
        f"was {C1_PREFIX['negative_cases']} over a wrong denominator): "
        f"gated no-bug={un['gated']['called_no_bug']} "
        f"refused={un['gated']['called_uninterpretable']} | "
        f"fair no-bug={un['fair']['called_no_bug']} | "
        f"naive no-bug={un['naive']['called_no_bug']}"
    )
    det = payload["oracle_experiment"]["determinate"]
    print(
        f"Oracle experiment: mechanical {det['mechanical']['false_verdicts']}"
        f"/{det['mechanical']['probe_results']} false verdicts, "
        f"interpretive {det['interpretive']['false_verdicts']}"
        f"/{det['interpretive']['probe_results']}"
    )
    print(f"wrote {json_path.name} and {md_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
