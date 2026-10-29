"""Every figure the README quotes must equal the committed measurement.

This exists because the CI workflow previously claimed that the benchmark's
``--check`` mode meant "the README cannot drift". It did not: ``--check``
regenerates the measurement and compares it to the committed results JSON, and
never opens the README at all. **Every figure in the README could have been
edited and CI would have stayed green.**

Numbered defects of this file, kept here for the same reason the modules keep
theirs. A verification file that does not record how it failed is the shape of
defect it exists to catch.

  1  the gate read one results file  -> the first version of this file bound
     seven ``fp_corpus.json`` figures and nothing else. The CVE study, the
     localisation finding and the dedup study -- the whole of what the second
     version of this repository added -- were bound by nothing at all. An
     adversarial reviewer proved it rather than arguing it: he falsified three
     of the new headline numbers in the README, including a Fisher p of
     ``1.0e-99`` and a confidence interval that excludes the truth, ran the
     full suite, and **all 1154 tests passed**. That is a false pass inside
     this project's own verification tooling, which is worse than the drift it
     was built to stop, because a green build is what tells a reader not to
     check. Every quantitative figure the README publishes is now bound to the
     committed artifact it is derived from, and the expected value is computed
     from that artifact here rather than written down here. A figure typed into
     this file would only pin the README to this file.

  2  no binding had ever been seen to fail  -> the rule this repository applies
     to a security control is that a control whose absence is not observable is
     not a control. The same rule applies to a drift gate, and it had not been
     applied: nobody had watched a binding go red.
     ``test_no_published_figure_binding_is_vacuous`` falsifies the number in
     every bound figure, in a copy of the README, and asserts the binding stops
     matching -- so a pattern loose enough to match any text fails here.
     ``test_the_whole_gate_goes_red_on_a_falsified_readme`` re-runs this file as
     a subprocess against a temporary README carrying the reviewer's exact four
     falsifications and asserts a non-zero exit. Neither is expensive, which is
     not why they did not exist.

  3  the figure bindings were themselves unpinned  -> ``tools/mutate_guards.py``
     proves each guard in the harness is load-bearing by removing it and
     watching a test break. The README's figures were outside that loop.
     ``tools/mutate_guards.py --figures`` now falsifies the README's published
     numbers in place, one at a time, and reports any whose falsification
     leaves the suite green. Its table is *derived* from ``BINDINGS`` rather
     than written alongside it, because a hand-kept second copy of this list is
     the next thing to go stale: a binding added here cannot be added without
     its mutation.

The README is read through ``CONTROLARM_README`` when that variable is set, so
defect 2's subprocess can point this module at a falsified copy. Nothing else
sets it, and it is deliberately not a way to relax the gate: unset means the
committed README.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Set only by this file's own non-vacuity proof. Unset means the real README.
README_ENV = "CONTROLARM_README"
README_PATH = pathlib.Path(os.environ.get(README_ENV) or (ROOT / "README.md"))
README = README_PATH.read_text(encoding="utf-8")

#: Relative paths, because they are published in the inventory this file emits
#: and a reader has to be able to open them.
FP_CORPUS = "benchmarks/results/fp_corpus.json"
CVE_STUDY = "benchmarks/cve_study/results/cve_study.json"
DEDUP_RESULTS = "benchmarks/dedup/results/dedup.md"
DEDUP_MANIFEST = "benchmarks/dedup/manifest.json"
DEDUP_INDEX = "benchmarks/dedup/cassettes.index.json"
GUARD_TABLE = "tools/mutate_guards.py"

RESULTS = json.loads((ROOT / FP_CORPUS).read_text(encoding="utf-8"))
CVE = json.loads((ROOT / CVE_STUDY).read_text(encoding="utf-8"))
DEDUP_MD = (ROOT / DEDUP_RESULTS).read_text(encoding="utf-8")
MANIFEST = json.loads((ROOT / DEDUP_MANIFEST).read_text(encoding="utf-8"))
INDEX = json.loads((ROOT / DEDUP_INDEX).read_text(encoding="utf-8"))

#: Where the generated inventory of published figures lands. The in-repository
#: copy is canonical; the publication tree gets a mirror when it is there, so a
#: claim ledger has a machine-generated source to copy from instead of
#: re-deriving every figure by hand.
INVENTORY = ROOT / "benchmarks" / "results" / "figure-inventory.md"
INVENTORY_MIRROR = ROOT.parent / "STATE" / "evidence" / "figure-inventory.md"

#: Numbers the README spells out. Derived the same way as the digits: the word
#: is produced from the measured count, so a count that moves stops matching.
_WORDS = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
}


def _word(n: int) -> str:
    assert n in _WORDS, f"no spelled form for {n}; the README would have to be read again"
    return _WORDS[n]


class MissingFigure(Exception):
    """A results file no longer carries a key a published figure comes from.

    Defect 6. A ``KeyError`` raised while the binding table is built happens at
    import time, which pytest reports as a collection error -- and a binding
    test that cannot be collected is indistinguishable from one that passes to
    anybody reading the tail of the output. So the lookup says which key, in
    which file, at which point in the path, and the table is built in a way
    that turns the failure into a red test rather than an interrupted run.
    """


def _at(path: str, root: dict | None = None, source: str = FP_CORPUS):
    cur = RESULTS if root is None else root
    walked: list[str] = []
    for part in path.split("."):
        try:
            cur = cur[part]
        except (KeyError, IndexError, TypeError) as exc:
            raise MissingFigure(
                f"{source} no longer carries the key path {path!r}: "
                f"{'.'.join(walked) or '<root>'} has no {part!r} "
                f"({type(exc).__name__}). A figure derived from a key that has moved is "
                f"checked by nothing, so this fails rather than skips. Keys available "
                f"at that point: {sorted(cur) if isinstance(cur, dict) else type(cur).__name__}"
            ) from exc
        walked.append(part)
    return cur


def _cve(path: str):
    return _at(path, CVE, CVE_STUDY)


# --------------------------------------------------------------------------- #
# The dedup study publishes its measurement as markdown rather than as JSON, so
# the counts table is parsed and the three rates are recomputed from it with the
# benchmark's own interval code. That is deliberately not a string match of the
# README against the results file's headline: the counts are the measurement,
# the rates are derived, and both documents are checked against the derivation
# rather than against each other.
# --------------------------------------------------------------------------- #

_COUNTS_ROW = re.compile(
    r"^\|\s*(?P<row>all items|coordinate|identifier)\s*\|"
    r"\s*(?P<n>\d+)\s*\|\s*(?P<tp>\d+)\s*\|\s*(?P<fn>\d+)\s*\|"
    r"\s*(?P<fp>\d+)\s*\|\s*(?P<tn>\d+)\s*\|",
    re.MULTILINE,
)


def _dedup_counts() -> dict[str, dict[str, int]]:
    rows = {
        m.group("row"): {k: int(m.group(k)) for k in ("n", "tp", "fn", "fp", "tn")}
        for m in _COUNTS_ROW.finditer(DEDUP_MD)
    }
    missing = {"all items", "coordinate", "identifier"} - set(rows)
    assert not missing, (
        f"the dedup results file no longer carries a counts row for {sorted(missing)}, "
        "so no dedup figure in the README can be checked against anything"
    )
    return rows


DEDUP = _dedup_counts()


def _rate_str(successes: int, total: int) -> str:
    """``str(Rate)`` is the exact form the benchmark publishes."""
    from benchmarks.dedup.interval import rate

    computed = rate(successes, total)
    assert computed is not None, "a rate out of an empty denominator is not a number"
    return str(computed)


def _pct(successes: int, total: int) -> str:
    return f"{successes / total * 100:.1f}%"


def _fisher(a: int, b: int, c: int, d: int) -> float:
    from benchmarks.cve_study.stats import fisher_two_sided

    return fisher_two_sided(a, b, c, d)


def _cp(successes: int, total: int) -> tuple[float, float]:
    from benchmarks.cve_study.stats import clopper_pearson

    return clopper_pearson(successes, total)


# --------------------------------------------------------------------------- #
# Derivations over the raw rows. These are the figures that are not a key in any
# results file: the mode-level localisation test, the probe-level oracle test,
# and the within-mode variation that justifies the mode as the unit of analysis.
# Recomputing them here is the point. The reviewer's finding was that a
# published statistic had been computed at the wrong unit, so the unit has to be
# derived rather than quoted.
# --------------------------------------------------------------------------- #


def _mode_level(realism: str | None) -> tuple[int, int, int, float]:
    """(modes, lattice wrong, baseline-denied-reachability wrong, Fisher p).

    A mode counts as wrong for a configuration when that configuration called a
    broken rig "no bug" on it. Every mode is eleven replicates of one outcome,
    which is why the mode and not the run is the denominator.
    """
    modes = {
        name: body
        for name, body in _cve("measurement.seeded_breakage.by_mode").items()
        if realism is None or body["realism"] == realism
    }
    n = len(modes)
    gated = sum(1 for body in modes.values() if body["configs"]["gated"]["no_bug"] > 0)
    denied = sum(
        1 for body in modes.values() if body["configs"]["fair_no_reachability"]["no_bug"] > 0
    )
    return n, gated, denied, _fisher(denied, n - denied, gated, n - gated)


def _modes_with_one_outcome() -> tuple[int, int]:
    """(modes whose outcome is constant across the eleven CVEs, modes).

    The whole justification for the mode-level denominator: where the breakage
    mode determines every arm's verdict and the CVE contributes nothing, a
    run-level denominator counts one result eleven times.
    """
    runs = [r for r in CVE["runs"] if r.get("breakage") and r["breakage"] != "none"]
    modes = sorted({r["breakage"] for r in runs})
    constant = 0
    for mode in modes:
        outcomes = {tuple(sorted(r["predictions"].items())) for r in runs if r["breakage"] == mode}
        constant += len(outcomes) == 1
    return constant, len(modes)


def _oracle_probe_level() -> tuple[int, int, int, float, float]:
    """(probes, mechanical wrong, interpretive wrong, Fisher p, drop-one p).

    Round one's reviewer established the probe as the unit here, because the two
    determinate target modes share one oracle function. The README applies that
    correction; this recomputes it from the rows rather than trusting it.
    """
    rows = [r for r in _at("oracle_experiment.rows") if r["mode"] in {"flawed", "patched"}]
    probes = sorted({r["probe"] for r in rows})
    wrong = {
        oracle: {
            p
            for p in probes
            if any(not r["correct"] for r in rows if r["probe"] == p and r["oracle"] == oracle)
        }
        for oracle in ("mechanical", "interpretive")
    }
    n = len(probes)
    mech, interp = len(wrong["mechanical"]), len(wrong["interpretive"])
    full = _fisher(mech, n - mech, interp, n - interp)
    # Drop one probe the interpretive oracle got wrong and the mechanical one
    # did not: the README's sensitivity check on the single probe that no
    # interpretive callable can match.
    kept, fewer = n - 1, interp - 1
    return n, mech, interp, full, _fisher(mech, kept - mech, fewer, kept - fewer)


# --------------------------------------------------------------------------- #
# The bindings.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Binding:
    """One published figure, its source, and the regex that must match.

    ``value`` is the figure as the source has it, formatted the way the README
    publishes it. ``pattern`` embeds that value, so a README whose number has
    moved stops matching. ``key`` names where in the source the value comes
    from and is published in the generated inventory, so a reader can open the
    file and check the number without running anything.
    """

    label: str
    source: str
    key: str
    value: str
    pattern: str


def _build_bindings() -> list[Binding]:
    out: list[Binding] = []

    def add(label: str, source: str, key: str, value: object, pattern: str) -> None:
        out.append(Binding(label, source, key, str(value), pattern))

    # ----------------------------------------------- the false-positive corpus
    un = "c1.untrustworthy_negatives"
    cases = _at(f"{un}.gated.cases")
    add(
        "corpus cases whose ground truth is an untrustworthy negative",
        FP_CORPUS,
        f"{un}.gated.cases",
        cases,
        rf"{_word(cases).capitalize()} corpus cases",
    )
    add(
        "gates enforced, called no bug",
        FP_CORPUS,
        f"{un}.gated.called_no_bug",
        _at(f"{un}.gated.called_no_bug"),
        rf"\| gates enforced \| {_at(f'{un}.gated.called_no_bug')} \|",
    )
    add(
        "gates enforced, refused to call",
        FP_CORPUS,
        f"{un}.gated.called_uninterpretable",
        _at(f"{un}.gated.called_uninterpretable"),
        rf"\| gates enforced \| 0 \| {_at(f'{un}.gated.called_uninterpretable')} \|",
    )
    add(
        "fair baseline, called no bug",
        FP_CORPUS,
        f"{un}.fair.called_no_bug",
        _at(f"{un}.fair.called_no_bug"),
        rf"\*\*{_at(f'{un}.fair.called_no_bug')}\*\* \| 5 \|",
    )
    add(
        "fair baseline, false-negative rate",
        FP_CORPUS,
        f"{un}.fair.false_negative_rate",
        f"{_at(f'{un}.fair.false_negative_rate'):.2f}",
        rf"\*\*{_at(f'{un}.fair.false_negative_rate'):.2f}\*\* \|",
    )
    add(
        "provenance arm, called no bug",
        FP_CORPUS,
        f"{un}.naive.called_no_bug",
        _at(f"{un}.naive.called_no_bug"),
        rf"\| {_at(f'{un}.naive.called_no_bug')} \| 0 \| 1\.00 \|",
    )
    add(
        "Fisher p, gates against the fair baseline",
        FP_CORPUS,
        "c1.fisher.gated_vs_fair",
        f"{_at('c1.fisher.gated_vs_fair'):.2f}",
        rf"Fisher exact p = {_at('c1.fisher.gated_vs_fair'):.2f}",
    )
    add(
        "Fisher p, gates against the provenance arm",
        FP_CORPUS,
        "c1.fisher.gated_vs_naive",
        f"{_at('c1.fisher.gated_vs_naive'):.4f}",
        rf"p = {_at('c1.fisher.gated_vs_naive'):.4f}",
    )

    # ------------------------------------------------------- the held-out sets
    add(
        "the catalogue the corpus and the gates both derive from",
        FP_CORPUS,
        "c2.gated_fired_rule_census (distinct rules)",
        len(_at("c2.gated_fired_rule_census")),
        rf"{len(_at('c2.gated_fired_rule_census'))}-item catalogue",
    )
    add(
        "catalogue corpus, gated precision and recall",
        FP_CORPUS,
        "c2.overall.gated.precision and c2.overall.gated.recall",
        f"{_at('c2.overall.gated.precision'):.2f}/{_at('c2.overall.gated.recall'):.2f}",
        rf"score {_at('c2.overall.gated.precision'):.2f}/{_at('c2.overall.gated.recall'):.2f}",
    )
    hold = "c2_holdout"
    add(
        "adversarial holdout, cases and the gated scores",
        FP_CORPUS,
        f"{hold}.cases with {hold}.overall.gated.recall, .precision, .accuracy",
        f"{_at(f'{hold}.cases')} cases at "
        f"{_at(f'{hold}.overall.gated.recall'):.2f}/"
        f"{_at(f'{hold}.overall.gated.precision'):.2f}/"
        f"{_at(f'{hold}.overall.gated.accuracy'):.2f}",
        (
            rf"\| {_at(f'{hold}.cases')} \| "
            rf"{_at(f'{hold}.overall.gated.recall'):.2f} \| "
            rf"{_at(f'{hold}.overall.gated.precision'):.2f} \| "
            rf"{_at(f'{hold}.overall.gated.accuracy'):.2f} \|"
        ),
    )
    ext = "c2_external"
    add(
        "external critique set, as the reviewer found it",
        FP_CORPUS,
        f"{ext}.cases with {ext}.pre_fix.recall, .precision, .accuracy",
        f"{_at(f'{ext}.cases')} cases at "
        f"{_at(f'{ext}.pre_fix.recall'):.2f}/"
        f"{_at(f'{ext}.pre_fix.precision'):.2f}/"
        f"{_at(f'{ext}.pre_fix.accuracy'):.2f}",
        (
            rf"\| {_at(f'{ext}.cases')} \| "
            rf"{_at(f'{ext}.pre_fix.recall'):.2f} \| "
            rf"{_at(f'{ext}.pre_fix.precision'):.2f} \| "
            rf"{_at(f'{ext}.pre_fix.accuracy'):.2f} \|"
        ),
    )
    add(
        "external critique set, after repair",
        FP_CORPUS,
        f"{ext}.overall.gated.recall, .precision, .accuracy",
        f"{_at(f'{ext}.overall.gated.recall'):.2f}/"
        f"{_at(f'{ext}.overall.gated.precision'):.2f}/"
        f"{_at(f'{ext}.overall.gated.accuracy'):.2f}",
        (
            rf"\*\*{_at(f'{ext}.overall.gated.recall'):.2f}\*\* \| "
            rf"\*\*{_at(f'{ext}.overall.gated.precision'):.2f}\*\* \| "
            rf"\*\*{_at(f'{ext}.overall.gated.accuracy'):.2f}\*\* \|"
        ),
    )
    pre_wrong = _at(f"{ext}.pre_fix.fp") + _at(f"{ext}.pre_fix.fn")
    add(
        "external critique set, cases the gates got wrong before repair",
        FP_CORPUS,
        f"{ext}.pre_fix.fp + {ext}.pre_fix.fn",
        f"{pre_wrong} of {_at(f'{ext}.cases')}",
        rf"\*\*{pre_wrong} of {_at(f'{ext}.cases')} wrong\*\*",
    )
    add(
        "external critique set, the split of those failures",
        FP_CORPUS,
        f"{ext}.pre_fix.fp and {ext}.pre_fix.fn",
        f"{_at(f'{ext}.pre_fix.fp')} false positives, {_at(f'{ext}.pre_fix.fn')} false negative",
        (
            rf"{_word(_at(f'{ext}.pre_fix.fp'))} false positives and "
            rf"{_word(_at(f'{ext}.pre_fix.fn'))} false negative"
        ),
    )
    correct = round(_at(f"{ext}.overall.gated.accuracy") * _at(f"{ext}.cases"))
    low, high = _cp(correct, _at(f"{ext}.cases"))
    add(
        "external critique set, the interval on post-repair accuracy",
        FP_CORPUS,
        f"Clopper-Pearson on {ext}.overall.gated.accuracy x {ext}.cases",
        f"[{low:.2f}, {high:.2f}] on {_at(f'{ext}.cases')}",
        rf"\[{low:.2f}, {high:.2f}\] at 95%",
    )

    # ---------------------------------------------------- the oracle contrast
    det = "oracle_experiment.determinate"
    add(
        "oracle experiment, probes and target modes",
        FP_CORPUS,
        "oracle_experiment.probes with the two determinate oracle_experiment.modes",
        _at("oracle_experiment.probes"),
        rf"{_at('oracle_experiment.probes')} probes across 2 target modes",
    )
    for arm, strength in (("mechanical", "3-4"), ("interpretive", "0-1")):
        results = _at(f"{det}.{arm}.probe_results")
        wrong = _at(f"{det}.{arm}.false_verdicts")
        lo, hi = _cp(wrong, results)
        add(
            f"oracle experiment, the {arm} oracle",
            FP_CORPUS,
            f"{det}.{arm}.false_verdicts over .probe_results, Clopper-Pearson",
            f"{wrong}/{results} = {wrong / results:.3f} [{lo:.3f}, {hi:.3f}]",
            (
                rf"\| {arm} \(strength {strength}\) \| {results} \| {wrong} \| "
                rf"{wrong / results:.3f} \| \[{lo:.3f}, {hi:.3f}\] \|"
            ),
        )
    probes, mech, interp, full_p, drop_p = _oracle_probe_level()
    add(
        "oracle experiment, at the probe level",
        FP_CORPUS,
        "oracle_experiment.rows grouped by probe over the two determinate modes",
        f"{mech} of {probes} versus {interp} of {probes}, p = {full_p:.3f}",
        rf"{mech} of {probes} versus {interp} of {probes}, \*\*p = {full_p:.3f}\*\*",
    )
    add(
        "oracle experiment, probe level with the unmatchable probe dropped",
        FP_CORPUS,
        "oracle_experiment.rows, one interpretive-only error removed",
        f"p = {drop_p:.3f}",
        rf"brings it to \*\*p = {drop_p:.3f}\*\*",
    )

    # ------------------------------------------------------- the guard census
    from tools.mutate_guards import MUTATIONS

    add(
        "guards neutered in CI",
        GUARD_TABLE,
        "len(MUTATIONS)",
        len(MUTATIONS),
        rf"\*\*{len(MUTATIONS)} guards, each one neutered in CI\.\*\*",
    )

    # ---------------------------------------------------------- the CVE study
    add(
        "CVEs reached",
        CVE_STUDY,
        "measurement.cves_reached",
        _cve("measurement.cves_reached"),
        rf"\*\*{_cve('measurement.cves_reached')} real public CVEs\*\*",
    )
    add(
        "CVE study, runs",
        CVE_STUDY,
        "measurement.runs_total",
        _cve("measurement.runs_total"),
        rf"{_cve('measurement.runs_total')} runs",
    )
    reached = [t for t in CVE["targets"] if t["status"] == "REACHED"]
    classes = len({t["class"] for t in reached})
    add(
        "CVE study, vulnerability classes",
        CVE_STUDY,
        "targets[status=REACHED].class, distinct",
        classes,
        rf"{_word(classes).capitalize()} vulnerability\s+classes",
    )
    packages = [t["package"] for t in reached]
    add(
        "CVE study, distributions",
        CVE_STUDY,
        "targets[status=REACHED].package, distinct",
        len(set(packages)),
        rf"{_word(len(set(packages)))} distributions",
    )
    repeated = sum(1 for p in set(packages) if packages.count(p) == 2)
    add(
        "CVE study, distributions contributing two CVEs each",
        CVE_STUDY,
        "targets[status=REACHED].package where the count is 2",
        repeated,
        rf"{_word(repeated)} distributions contributing {_word(2)} CVEs each",
    )
    prefix = _cve("measurement.prefix_clean.configs.gated.error_rate")
    add(
        "CVE study, pre-fix false-negative rate, both arms",
        CVE_STUDY,
        "measurement.prefix_clean.configs.[gated|fair].error_rate",
        f"{prefix['successes']}/{prefix['total']} = {prefix['rate']:.2f}",
        rf"\*\*{prefix['successes']}/{prefix['total']} = {prefix['rate']:.2f} ",
    )
    add(
        "CVE study, the interval on the pre-fix rate",
        CVE_STUDY,
        "measurement.prefix_clean.configs.gated.error_rate.ci95",
        f"[{prefix['ci95'][0]:.2f}, {prefix['ci95'][1]:.2f}]",
        rf"\[{prefix['ci95'][0]:.2f}, {prefix['ci95'][1]:.2f}\]",
    )
    add(
        "CVE study, pre-fix Fisher p",
        CVE_STUDY,
        "measurement.prefix_clean.fisher_gated_vs_fair.p_two_sided",
        f"{_cve('measurement.prefix_clean.fisher_gated_vs_fair.p_two_sided'):.2f}",
        rf"Fisher \*\*p = "
        rf"{_cve('measurement.prefix_clean.fisher_gated_vs_fair.p_two_sided'):.2f}\*\*",
    )
    postfix = _cve("measurement.postfix_clean.configs.gated.error_rate")
    add(
        "CVE study, post-fix false positives, both arms",
        CVE_STUDY,
        "measurement.postfix_clean.configs.[gated|fair].error_rate",
        f"{postfix['successes']}/{postfix['total']}",
        rf"{postfix['successes']}/{postfix['total']} false positives",
    )
    real_n = _cve("measurement.seeded_breakage.real_modes_only.n")
    real_table = _cve("measurement.seeded_breakage.real_modes_only.fisher_gated_vs_fair.table")
    add(
        "CVE study, real seeded breakage with both arms intact",
        CVE_STUDY,
        "measurement.seeded_breakage.real_modes_only.fisher_gated_vs_fair.table",
        f"{real_table['gated_wrong']} and {real_table['fair_wrong']} of {real_n}",
        rf'"no bug" {real_table["gated_wrong"]}\s+times out of {real_n}',
    )

    # ---------------------------------------------- the localisation, by mode
    constant, modes_total = _modes_with_one_outcome()
    add(
        "breakage modes whose outcome is constant across the eleven CVEs",
        CVE_STUDY,
        "runs[].predictions grouped by runs[].breakage",
        f"{constant} of {modes_total}",
        rf"{_word(constant).capitalize()} of the {_word(modes_total)} modes produce exactly one",
    )
    for realism, printed in (("real", "real"), (None, "all")):
        n, gated, denied, p = _mode_level(realism)
        add(
            f"localisation at the mode level, {printed} breakage modes",
            CVE_STUDY,
            "measurement.seeded_breakage.by_mode[*].configs"
            f"[gated|fair_no_reachability].no_bug, realism={realism!r}",
            f"{gated} of {n} versus {denied} of {n}, p = {p:.4f}",
            (
                rf"\| {printed} breakage modes \| \*?\*?mode\*?\*? \| {gated} of {n} \| "
                rf"\*?\*?{denied} of {n}\*?\*? \| \*?\*?p = {p:.4f}\*?\*? \|"
            ),
        )
    sens = (
        "measurement.sensitivity_fair_without_reachability"
        ".fisher_gated_vs_fair_no_reachability_on_real_breakage"
    )
    run_wrong = _cve(f"{sens}.table.fair_no_reachability_wrong")
    run_p = _cve(f"{sens}.p_two_sided")
    add(
        "localisation at the run level, shown as the inflated denominator it is",
        CVE_STUDY,
        f"{sens}.table.fair_no_reachability_wrong with .p_two_sided",
        f"{run_wrong} of {real_n}, p = {run_p:.1e}",
        (
            rf"\| real breakage modes \| run \(not independent\) \| 0 of {real_n} \| "
            rf"{run_wrong} of {real_n} \| p = {run_p:.1e} \|"
        ),
    )
    n_real, _, denied_real, _ = _mode_level("real")
    add(
        "the real modes where the denied baseline still refuses correctly",
        CVE_STUDY,
        "measurement.seeded_breakage.by_mode, real modes minus the ones it calls no bug",
        n_real - denied_real,
        rf"the {_word(n_real - denied_real)} real modes where",
    )
    stale = _cve("measurement.seeded_breakage.by_mode.stale_positive_control.configs.fair.finding")
    add(
        "the lattice's cost on the over-conservative mode",
        CVE_STUDY,
        "measurement.seeded_breakage.by_mode.stale_positive_control.configs.fair.finding",
        stale,
        rf"costs it {stale} correct findings",
    )

    # --------------------------------------------------------- the dedup study
    allc = DEDUP["all items"]
    coord = DEDUP["coordinate"]
    add(
        "dedup, labelled items",
        DEDUP_RESULTS,
        "Counts table, row 'all items', column n",
        allc["n"],
        rf"{allc['n']} labelled items",
    )
    advisories = len({i["ghsa"] for i in MANIFEST["items"]})
    add(
        "dedup, advisories the items were drawn from",
        DEDUP_MANIFEST,
        "items[].ghsa, distinct",
        advisories,
        rf"over {advisories} advisories",
    )
    recordings = round(len(INDEX["files"]) / 10) * 10
    add(
        "dedup, committed recordings replayed",
        DEDUP_INDEX,
        "files, counted and rounded to the nearest ten as the README states it",
        f"{len(INDEX['files'])} (about {recordings})",
        rf"about {recordings} committed recordings",
    )
    add(
        "dedup, recall",
        DEDUP_RESULTS,
        "Counts 'all items': tp / (tp + fn)",
        _rate_str(allc["tp"], allc["tp"] + allc["fn"]),
        rf"\*\*{re.escape(_rate_str(allc['tp'], allc['tp'] + allc['fn']))}\*\*",
    )
    add(
        "dedup, precision",
        DEDUP_RESULTS,
        "Counts 'all items': tp / (tp + fp)",
        _rate_str(allc["tp"], allc["tp"] + allc["fp"]),
        rf"\*\*{re.escape(_rate_str(allc['tp'], allc['tp'] + allc['fp']))}\*\*",
    )
    add(
        "dedup, specificity",
        DEDUP_RESULTS,
        "Counts 'all items': tn / (tn + fp)",
        _rate_str(allc["tn"], allc["tn"] + allc["fp"]),
        rf"\*\*{re.escape(_rate_str(allc['tn'], allc['tn'] + allc['fp']))}\*\*",
    )
    add(
        "dedup, coordinate-family precision",
        DEDUP_RESULTS,
        "Counts 'coordinate': tp / (tp + fp)",
        _pct(coord["tp"], coord["tp"] + coord["fp"]),
        rf"precision {_pct(coord['tp'], coord['tp'] + coord['fp'])}",
    )
    add(
        "dedup, coordinate-family specificity",
        DEDUP_RESULTS,
        "Counts 'coordinate': tn / (tn + fp)",
        _rate_str(coord["tn"], coord["tn"] + coord["fp"]),
        rf"\*\*specificity {re.escape(_rate_str(coord['tn'], coord['tn'] + coord['fp']))}\*\*",
    )
    add(
        "dedup, novel items the coordinate family flagged as prior art",
        DEDUP_RESULTS,
        "Counts 'coordinate': fp of (tn + fp)",
        f"{coord['fp']} of {coord['tn'] + coord['fp']}",
        rf"flagging {coord['fp']} of\s+{coord['tn'] + coord['fp']} genuinely novel items",
    )
    return out


#: Defect 6. Building the table must not raise at import: an exception here is
#: a collection error, the parametrized tests below then contribute no cases at
#: all, and a run that collected nothing looks exactly like a run that passed.
#: The failure is carried as data and asserted by a test instead.
try:
    BINDINGS = _build_bindings()
    BINDING_TABLE_ERROR: str | None = None
except Exception as exc:  # the message is the whole point; see MissingFigure
    BINDINGS = []
    BINDING_TABLE_ERROR = f"{type(exc).__name__}: {exc}"

#: A floor, not the count. Asserting the exact number would make every added
#: figure edit this line; asserting a floor catches the failure that matters,
#: which is a table that silently stopped binding most of the document.
MINIMUM_BINDINGS = 40


# --------------------------------------------------------------------------- #
# The gate.
# --------------------------------------------------------------------------- #


def test_the_binding_table_was_built_and_covers_every_published_source():
    """The gate's own liveness arm. Without this, an empty table passes.

    This is the control this file was missing: the parametrized assertions
    below are only evidence if the thing they are parametrized over is
    populated. A gate with no cases is the harness's own ``NO-TESTS`` verdict,
    and it must not read as green.
    """
    assert BINDING_TABLE_ERROR is None, (
        "the binding table could not be built, so no figure in the README was checked "
        f"against anything:\n{BINDING_TABLE_ERROR}"
    )
    assert len(BINDINGS) >= MINIMUM_BINDINGS, (
        f"only {len(BINDINGS)} figures are bound, fewer than the {MINIMUM_BINDINGS} this "
        "README publishes; a figure that lost its binding is a figure CI no longer reads"
    )
    for source in (FP_CORPUS, CVE_STUDY, DEDUP_RESULTS, DEDUP_MANIFEST, DEDUP_INDEX, GUARD_TABLE):
        assert any(b.source == source for b in BINDINGS), (
            f"nothing in the README is bound to {source}, which is how the first version "
            "of this file came to bind one results file and leave three studies unchecked"
        )
    labels = [b.label for b in BINDINGS]
    duplicated = sorted({label for label in labels if labels.count(label) > 1})
    assert not duplicated, (
        f"duplicate binding labels {duplicated}; the inventory and the figure mutation "
        "table are both keyed by label, so a duplicate would hide one of the two figures"
    )


def _failure(binding: Binding, text: str) -> str | None:
    if re.search(binding.pattern, text) is not None:
        return None
    return (
        f"the README no longer states {binding.label} as the committed measurement has it.\n"
        f"  source  {binding.source}\n"
        f"  key     {binding.key}\n"
        f"  value   {binding.value}\n"
        f"  expected to find /{binding.pattern}/ in {README_PATH.name}"
    )


@pytest.mark.parametrize("binding", BINDINGS, ids=[b.label for b in BINDINGS])
def test_every_published_figure_matches_its_source(binding: Binding):
    problem = _failure(binding, README)
    assert problem is None, problem


def falsify(matched: str) -> str:
    """Make the matched text say something the measurement does not say.

    Shared with ``tools/mutate_guards.py``, which applies it to the README in
    place: the figure mutations and the non-vacuity test must falsify a figure
    the same way, or one of them would be testing something else.
    """
    if any(ch.isdigit() for ch in matched):
        return "".join(str((int(c) + 1) % 10) if c.isdigit() else c for c in matched)
    for number, word in sorted(_WORDS.items()):
        for form in (word, word.capitalize()):
            if form in matched:
                other = _WORDS[(number + 3) % len(_WORDS)]
                return matched.replace(form, other.capitalize() if form[0].isupper() else other, 1)
    return matched


def _carries_a_number(text: str) -> bool:
    lowered = text.lower()
    return any(ch.isdigit() for ch in text) or any(w in lowered for w in _WORDS.values())


@pytest.mark.parametrize("binding", BINDINGS, ids=[b.label for b in BINDINGS])
def test_no_published_figure_binding_is_vacuous(binding: Binding):
    """Defect 2. A binding nobody has watched fail is not known to bind anything.

    Every occurrence of the figure is falsified, not only the first: a pattern
    that still matched elsewhere in the document would pass the gate against a
    README whose quoted number had been edited.
    """
    match = re.search(binding.pattern, README)
    assert match is not None, f"{binding.label} is not in the README at all"
    assert _carries_a_number(match.group(0)), (
        f"{binding.label} matched {match.group(0)!r}, which carries no number, so the "
        "binding cannot tell the published figure from any other text"
    )
    falsified = re.sub(binding.pattern, lambda m: falsify(m.group(0)), README)
    assert falsified != README, f"{binding.label}: falsifying the figure changed nothing"
    assert _failure(binding, falsified) is not None, (
        f"{binding.label} still matches a README whose figure has been falsified, so the "
        f"binding is vacuous: /{binding.pattern}/ matches text it must reject"
    )


#: The four falsifications an adversarial reviewer made to prove this gate was
#: vacuous, verbatim from his report, including the Fisher p of 1.0e-99. They
#: are kept as the end-to-end proof that the gate now catches exactly them.
REVIEWER_FALSIFICATIONS = (
    ("p = 0.4444", "p = 1.0e-99"),
    ("22 of 55", "54 of 55"),
    ("[0.00, 0.28]", "[0.00, 0.01]"),
    ("95% CI 91.2%-100.0%", "95% CI 99.9%-100.0%"),
)


@pytest.mark.pristine
def test_the_whole_gate_goes_red_on_a_falsified_readme(tmp_path):
    """Defect 2, end to end. Run this file against a falsified README copy.

    The parametrized test above checks each pattern in isolation. This checks
    the thing that actually failed: the suite's exit code. The reviewer edited
    three headline figures, ran 1154 tests and got a zero exit. The same edits
    must now produce a non-zero one.
    """
    if os.environ.get(README_ENV):
        pytest.skip("already running against a substituted README; no recursion")
    text = README
    for figure, lie in REVIEWER_FALSIFICATIONS:
        assert figure in text, f"the README no longer publishes {figure!r} to falsify"
        text = text.replace(figure, lie)
    falsified = tmp_path / "README.md"
    falsified.write_text(text, encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            pathlib.Path(__file__).name,
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "-m",
            "not pristine",
        ],
        cwd=ROOT / "tests",
        capture_output=True,
        text=True,
        env={**os.environ, README_ENV: str(falsified)},
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode != 0, (
        "the figure gate passed against a README carrying a Fisher p of 1.0e-99, a "
        f"falsified localisation count and two falsified intervals:\n{output}"
    )
    assert "no longer states" in output, output
    for expected in (
        "localisation at the mode level, real breakage modes",
        "localisation at the run level",
        "the interval on the pre-fix rate",
        "dedup, recall",
    ):
        assert expected in output, (
            f"the gate went red, but not on {expected!r}, so that figure is still "
            f"unbound:\n{output}"
        )


@pytest.mark.pristine
def test_every_binding_is_pinned_by_a_figure_mutation():
    """Defect 3. Each binding must have a mutation that falsifies its figure.

    ``tools/mutate_guards.py --figures`` is the end-to-end proof that each
    binding is load-bearing. Its table is derived from this one, so the thing
    worth asserting is that every derived mutation actually applies: a pattern
    that matches the README twice, or not at all, would be reported STALE by
    the tool rather than proving anything, and this is where that surfaces
    without a ten-minute run.
    """
    from tools.mutate_guards import FIGURE_TARGETS, figure_mutations

    mutations = figure_mutations()
    assert {m.label for m in mutations} == {b.label for b in BINDINGS}
    stale = []
    for mut in mutations:
        source = FIGURE_TARGETS[mut.target].read_text(encoding="utf-8")
        found = len(re.findall(mut.pattern, source))
        if found != 1:
            stale.append(f"{mut.target}/{mut.label}: matched {found} times, expected 1")
    assert not stale, (
        "figure mutations that cannot be applied, so the bindings they would pin are "
        "unpinned:\n" + "\n".join(stale)
    )


def test_the_claim_about_what_the_small_interval_excludes_is_not_stronger_than_it():
    """The README says 0/11 cannot separate a true rate of 0.00 from one of 0.25.

    That is a statement about the upper bound, so it has to sit inside it. A
    rounded-up version of this sentence would be the same overclaim the
    mode-level correction was about, one decimal place down.
    """
    upper = _cve("measurement.prefix_clean.configs.gated.error_rate.ci95")[1]
    stated = re.search(r"from one of (\d\.\d+)", README)
    assert stated, "the README no longer bounds what 0/11 can exclude"
    assert float(stated.group(1)) <= upper, (
        f"the README says 0/11 cannot exclude {stated.group(1)}, but the committed "
        f"interval's upper bound is {upper}, so the claim is stronger than the measurement"
    )


def test_the_fair_baseline_is_the_primary_comparison():
    """The claim rests on the fair arm, not the arm that cannot refuse."""
    assert "primary comparison" in README
    assert _at("c1.fisher.gated_vs_fair") == 1.0, (
        "the headline comparison is no longer p = 1.00; the README's null-result "
        "framing must be rewritten rather than left in place"
    )


def test_the_readme_reports_the_external_set_not_only_the_holdout():
    """The circular 1.00/1.00 must never be the headline again."""
    external = _at("c2_external")
    assert "external critique set" in README
    assert str(external["cases"]) in README, "the external set's case count is not in the README"


def test_the_dedup_results_file_agrees_with_its_own_counts():
    """The results file publishes rates; its counts table is the measurement.

    Binding the README to the counts is only worth something if the file's own
    headline comes from the same counts. This is also where specificity is
    pinned, independently of whether any document chooses to quote it -- the
    README omitted it for a whole version, and a figure only a prose document
    carries is a figure nothing checks.
    """
    allc = DEDUP["all items"]
    for name, value in (
        ("recall", _rate_str(allc["tp"], allc["tp"] + allc["fn"])),
        ("precision", _rate_str(allc["tp"], allc["tp"] + allc["fp"])),
        ("specificity", _rate_str(allc["tn"], allc["tn"] + allc["fp"])),
    ):
        assert value in DEDUP_MD, (
            f"{DEDUP_RESULTS} does not state {name} as its own counts table gives it "
            f"({value}); one of the two was edited by hand"
        )


def _retracted() -> dict[str, str]:
    """Figures published once and then retracted.

    Each may still appear, but only inside a sentence that marks it as
    retracted. A bare reappearance is a regression; keeping the retraction
    visible is the point.
    """
    from tools.mutate_guards import MUTATIONS

    return {
        "0.64": "the false-negative rate computed over the wrong denominator",
        "1.00 guarded and 0.50": "the accuracy pair from the strawman comparison",
        "11 cases": "the denominator that counted four non-negatives",
        "Five verdicts": "there are six",
        # Derived rather than written down: an earlier version of this registry
        # read "there are 102" when there were 179, which is a stale number
        # inside the registry built to catch stale numbers.
        "88 guards": f"there are {len(MUTATIONS)}",
        "0.40 [0.27, 0.54]": "the localisation rate over the run-level denominator",
        "four times in ten": "a rate restated from two of five authored breakage modes",
        "Glasswing": "a citation that does not support the claim made from it",
    }


RETRACTED = _retracted()

#: Phrasings that mark a figure as retracted rather than asserted. Each one is
#: taken from text already written in this repository, not invented for the
#: test: a marker list that does not match how the corrections are actually
#: worded fails documents that are perfectly honest, which is what happened to
#: GAPS.md G2b on the first widened run.
RETRACTION_MARKERS = (
    "earlier version",
    "replaced",
    "retract",
    "external critique established",
    "pre-repair",
    "as received",
    "not independent",
    "substantively meaningless",
    "the original c1 claim",
    "was wrong",
    "were wrong",
    "corrected",
    "weaker after the correction",
    "wrong unit",
    "inflation is visible",
)


#: Paths excluded from the retraction sweep: third-party content we did not
#: write, caches, and the test files that necessarily name the retracted figures
#: in order to check for them.
_NOT_AUTHORED = ("__pycache__", "vendor", ".cache", ".ruff_cache", ".pytest_cache", "tests")


def _authored_documents() -> list[pathlib.Path]:
    return [
        path
        for path in sorted(ROOT.rglob("*.md"))
        if not any(part in _NOT_AUTHORED for part in path.parts)
    ]


def test_the_retraction_sweep_reaches_more_than_the_root_readme():
    """The reason three retracted figures survived.

    An earlier version of this test scanned only `README.md`, so a retracted
    number living in `docs/`, `benchmarks/` or a results file was invisible to
    it. A sweep that covers one file is not a sweep.
    """
    found = {path.name for path in _authored_documents()}
    assert "README.md" in found
    assert len(_authored_documents()) >= 6, (
        f"the sweep reached only {len(_authored_documents())} documents, which is "
        f"fewer than this repository has; it is probably walking the wrong root"
    )
    # The documents that actually carried the surviving figures must be in scope.
    reached = {path.relative_to(ROOT).as_posix() for path in _authored_documents()}
    for required in ("docs/cve-study.md", "benchmarks/fp_corpus/README.md"):
        assert required in reached, f"{required} is not covered by the retraction sweep"


@pytest.mark.parametrize("figure", sorted(RETRACTED), ids=sorted(RETRACTED))
def test_a_retracted_figure_appears_only_inside_its_retraction(figure):
    """A retracted number may be discussed. It may not be re-asserted.

    The distinction is the whole point: this project's credibility rests on the
    record of what it got wrong staying visible, so deleting the history would
    be as bad as leaving the claim standing.

    Every authored document is checked, not only the root README. Scoping this
    to one file is how `docs/cve-study.md` came to present a retracted
    run-level rate as a live claim.
    """
    offences = []
    for path in _authored_documents():
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(re.escape(figure), text):
            window = text[max(0, match.start() - 400) : match.end() + 400].lower()
            if not any(marker in window for marker in RETRACTION_MARKERS):
                rel = path.relative_to(ROOT).as_posix()
                line = text[: match.start()].count(chr(10)) + 1
                offences.append(f"{rel}:{line}")
    assert not offences, (
        f"{figure!r} ({RETRACTED[figure]}) appears without any retraction marker "
        f"nearby at {offences}, so it reads there as a live claim"
    )


def test_glasswing_is_gone_entirely_rather_than_merely_retracted():
    """The one case where discussion is not enough.

    The quotation attributed to that page does not exist on it. There is no
    honest way to cite it, so unlike the numeric retractions above it must not
    appear at all.
    """
    assert "Glasswing" not in README


def test_the_guard_count_in_the_readme_matches_the_mutation_table():
    """The README says how many guards are pinned; the table is the truth.

    The figure mutations are deliberately not counted here. They falsify a
    published number rather than neuter a control in the harness, they live in
    their own table, and ``tools/mutate_guards.py`` with no arguments still
    reports exactly the count the README quotes.
    """
    from tools.mutate_guards import MUTATIONS, figure_mutations

    stated = re.search(r"(\d+) guards", README)
    assert stated, "the README no longer states a guard count"
    assert int(stated.group(1)) == len(MUTATIONS), (
        f"the README says {stated.group(1)} guards; the mutation table has {len(MUTATIONS)}"
    )
    assert not {m.label for m in MUTATIONS} & {m.label for m in figure_mutations()}, (
        "a label appears in both mutation tables, so the guard census and the figure "
        "census would double-count it"
    )


# --------------------------------------------------------------------------- #
# The inventory.
# --------------------------------------------------------------------------- #


def inventory() -> str:
    """The published figure inventory, as markdown."""
    sources = sorted({b.source for b in BINDINGS})
    lines = [
        "# Published figure inventory",
        "",
        "Generated by `tests/test_readme_figures.py`. Do not edit by hand.",
        "",
        "Every quantitative figure `README.md` publishes, the committed artifact it is",
        "derived from, the key or locator inside that artifact, and the value as the",
        "artifact has it. Each row is bound by a test: editing the figure in the README",
        "fails CI, and `python tools/mutate_guards.py --figures` proves the binding by",
        "falsifying the figure in place and requiring the suite to go red.",
        "",
        "This file exists so that a claim ledger has a machine-generated source to copy",
        "from rather than re-deriving each number by hand, which is how a ledger row",
        "comes to assert a count that is stale by 77 under a VERIFIED stamp.",
        "",
        f"- figures bound: **{len(BINDINGS)}**",
        f"- sources: {', '.join(f'`{s}`' for s in sources)}",
        "",
        "| figure | source | key | value |",
        "| --- | --- | --- | --- |",
    ]
    for binding in BINDINGS:
        lines.append(
            f"| {binding.label} | `{binding.source}` | `{binding.key}` | `{binding.value}` |"
        )
    lines.append("")
    return "\n".join(lines)


@pytest.mark.pristine
def test_the_figure_inventory_is_generated_and_current():
    """Emit the inventory, and fail if the committed copy had drifted.

    Writing it from the test run is the point: an inventory assembled by hand is
    one more document that can go stale, which is the defect it exists to
    remove. Marked ``pristine`` because a mutation run has the tree deliberately
    wrong and must not stamp a wrong value into a published file.
    """
    text = inventory()
    assert "—" not in text, "the generated inventory contains an em dash"
    before = INVENTORY.read_text(encoding="utf-8") if INVENTORY.exists() else None
    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY.write_text(text, encoding="utf-8")
    if INVENTORY_MIRROR.parent.exists():
        INVENTORY_MIRROR.write_text(text, encoding="utf-8")
    assert before is None or before == text, (
        f"{INVENTORY.relative_to(ROOT).as_posix()} was out of date and has been "
        "regenerated; commit the new copy"
    )
