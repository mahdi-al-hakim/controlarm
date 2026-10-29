"""Self-consistency tests for the CVE study.

These do not re-run the probes. Executing 110 subprocesses against two pinned
versions of eleven distributions is what
``python benchmarks/cve_study/run_study.py --check`` is for, and that command
**cannot run in CI**: it refuses to measure against pins whose bytes it has not
verified, and those bytes are the 187MB gitignored ``.cache/``. ``GAPS.md`` G7
records that, with the route to closing it. Nothing in this file or in CI used
to say so, and an earlier version of this docstring claimed CI ran it.

What these tests pin is everything that can be checked offline, with only what
is committed:

* the registry is completely labelled and the selection rule was applied rather
  than merely written down;
* **every field the study derives is what the live code produces** from the
  probe reports committed beside it -- see
  ``test_every_committed_run_re_derives_from_the_arm_reports_beside_it``. The
  four facts per run that executing the probe establishes are read from the
  committed record; everything downstream of them is recomputed;
* the published measurement is what the scorer produces from those re-derived
  runs, not from the results file's own conclusions about them;
* and neither check is vacuous. A scorer that agrees with its own output proves
  nothing, so ``test_a_broken_scorer_is_caught`` breaks the scoring rule and
  ``test_a_tampered_arm_report_breaks_the_re_derivation`` breaks an arm report;
  both assert the committed numbers then stop reproducing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from benchmarks.cve_study import targets as registry
from benchmarks.cve_study.breakage import MODES
from benchmarks.cve_study.runner import CONFIGS, SENSITIVITY, ProbeRun, readjudicate
from benchmarks.cve_study.score import measure
from benchmarks.cve_study.stats import clopper_pearson, fisher_two_sided

ROOT = Path(__file__).resolve().parent.parent
STUDY = ROOT / "benchmarks" / "cve_study"
RESULTS_JSON = STUDY / "results" / "cve_study.json"
RESULTS_MD = STUDY / "results" / "cve_study.md"


@pytest.fixture(scope="module")
def committed() -> dict:
    assert RESULTS_JSON.exists(), (
        "benchmarks/cve_study/results/cve_study.json is missing; run "
        "`python benchmarks/cve_study/run_study.py` to produce it"
    )
    return json.loads(RESULTS_JSON.read_text(encoding="utf-8"))


def _runs_from(committed: dict) -> list[ProbeRun]:
    return [
        ProbeRun(
            cve=r["cve"],
            package=r["package"],
            version=r["version"],
            phase=r["phase"],
            breakage=r["breakage"],
            verdict=r["lattice_verdict"],
            verdict_reason=r["lattice_reason"],
            arms=r["arms"],
            predictions=r["predictions"],
            verdicts=r["verdicts"],
            rules=r["rules"],
            fair_agrees_with_reviewer=r["fair_agrees_with_reviewer"],
            exploit_reached_target=r["exploit_reached_target"],
        )
        for r in committed["runs"]
    ]


# ------------------------------------------------------------------- registry


def test_every_cve_has_two_distinct_versions():
    for target in registry.TARGETS:
        assert target.pre, f"{target.cve} has no pre-fix version"
        assert target.post, f"{target.cve} has no post-fix version"
        assert target.pre != target.post, (
            f"{target.cve} names the same version twice, so it cannot supply "
            "pre-fix/post-fix ground truth"
        )
        assert len(target.pins) == 2


def test_no_case_is_unlabelled():
    """Every field that a reader would need is present on every target."""
    required = (
        "cve",
        "package",
        "vuln_class",
        "advisory_url",
        "fix_release_url",
        "fix_evidence",
        "oracle",
        "reachability",
        "status",
    )
    for target in registry.TARGETS:
        for field in required:
            value = getattr(target, field)
            assert isinstance(value, str) and value.strip(), (
                f"{target.cve} has an empty {field!r}; an unlabelled case is exactly the "
                "defect this study was built to remove"
            )
        assert target.status in registry.STATUSES, f"{target.cve} has status {target.status!r}"
        assert target.vuln_class in registry.CLASSES, (
            f"{target.cve} has class {target.vuln_class!r}, which is not in the admissible set"
        )


def test_no_target_is_a_memory_safety_cve():
    """Rule X1, enforced rather than trusted.

    A sanitizer is already a mechanical oracle for memory safety, so including
    such a CVE would measure a problem this project explicitly does not claim to
    address. The README says so; this test makes the README binding.
    """
    for target in registry.TARGETS:
        assert target.vuln_class not in registry.MEMORY_SAFETY_CLASSES, (
            f"{target.cve} is classed {target.vuln_class!r}, which rule X1 excludes"
        )
    assert not set(registry.CLASSES) & set(registry.MEMORY_SAFETY_CLASSES), (
        "the admissible and excluded class lists overlap, so the exclusion is not an exclusion"
    )


def test_every_reached_target_has_a_probe_and_every_other_one_does_not():
    for target in registry.TARGETS:
        if target.status == "REACHED":
            assert target.probe, f"{target.cve} is REACHED but names no probe"
            assert (STUDY / "probes" / f"{target.probe}.py").exists(), (
                f"{target.cve} names probe {target.probe!r}, which does not exist"
            )
        else:
            assert not target.probe, (
                f"{target.cve} is {target.status} but names a probe; a target excluded from "
                "the headline must not look like one that was measured"
            )


def test_unreached_and_rejected_targets_say_why():
    """A status with no stated reason is a guess wearing a label."""
    for target in registry.TARGETS:
        if target.status == "UNREACHED":
            assert "NOT ESTABLISHED" in target.reachability, (
                f"{target.cve} is UNREACHED without saying so in its reachability note"
            )
        if target.status == "REJECTED":
            assert "Rejected under rule" in target.reachability, (
                f"{target.cve} is REJECTED without naming the rule that rejected it"
            )


def test_every_probe_exposes_the_arm_contract():
    import importlib

    for target in registry.reached():
        module = importlib.import_module(f"benchmarks.cve_study.probes.{target.probe}")
        for arm in ("liveness", "control", "exploit"):
            assert callable(getattr(module, arm, None)), (
                f"{target.probe} does not expose a callable {arm}()"
            )


def test_the_selection_rule_was_committed_and_is_referenced():
    rule = STUDY / "SELECTION_RULE.md"
    assert rule.exists()
    text = rule.read_text(encoding="utf-8")
    for clause in ("C1", "C2", "C3", "C4", "C5", "C6", "X1", "X2", "X3"):
        assert clause in text, f"the selection rule does not state {clause}"
    assert "before any CVE was selected" in text


# ------------------------------------------------------------------ the numbers


def test_the_committed_results_cover_every_reached_target(committed):
    runs = _runs_from(committed)
    expected = len(registry.reached()) * (2 + len(MODES))
    assert len(runs) == expected, (
        f"{len(runs)} runs committed but {expected} expected from "
        f"{len(registry.reached())} CVEs x (2 clean + {len(MODES)} breakage modes)"
    )
    for target in registry.reached():
        phases = {(r.phase, r.breakage) for r in runs if r.cve == target.cve}
        assert ("pre", "none") in phases, f"{target.cve} has no clean pre-fix run"
        assert ("post", "none") in phases, f"{target.cve} has no clean post-fix run"
        for mode in MODES:
            assert ("pre", mode.name) in phases, (
                f"{target.cve} was never run under breakage mode {mode.name}"
            )


def test_every_run_is_classified_under_every_configuration(committed):
    for run in _runs_from(committed):
        for config in (*CONFIGS, *SENSITIVITY):
            assert run.predictions.get(config) in (
                "FINDING",
                "NO_BUG",
                "UNINTERPRETABLE",
            ), f"{run.key} has no usable prediction for {config!r}"


def test_the_scorer_reproduces_the_committed_results_exactly(committed):
    """The committed numbers are the ones the scorer produces. Byte for byte."""
    recomputed = measure(_runs_from(committed)).as_dict()
    assert recomputed == committed["measurement"]


#: Every field of a committed run that the study derives rather than observes.
#: The complement -- each arm's ``outcome``/``detail`` and
#: ``exploit_reached_target`` -- is what executing the probe establishes, and
#: that is the half no CI job can regenerate. See ``GAPS.md`` G7.
DERIVED_FIELDS = (
    "lattice_verdict",
    "lattice_reason",
    "predictions",
    "verdicts",
    "rules",
    "fair_agrees_with_reviewer",
    "arms",
)


def test_every_committed_run_re_derives_from_the_arm_reports_beside_it(committed):
    """A committed result that no longer matches what the code produces fails here.

    The test above pins the *scorer* against the committed per-run verdicts,
    which leaves those verdicts themselves asserted by a results file rather
    than produced by anything: edit ``lattice_verdict`` and ``predictions``
    together and the measurement still reproduces. This closes that by feeding
    each run's committed probe report -- the three ``(executed, detail)`` pairs
    and whether the exploit reached the target -- back through the live
    pipeline, and asserting every field the study *derives* comes out
    unchanged. It therefore pins ``classify_failure``'s pattern table,
    ``Run.decide``, the lattice, the reviewer's frozen baseline and the
    sensitivity arm, offline and with no fixture cache.
    """
    for record in committed["runs"]:
        fresh = readjudicate(record).as_dict()
        for field in DERIVED_FIELDS:
            assert fresh[field] == record[field], (
                f"{record['cve']} ({record['phase']}, breakage={record['breakage']}): the "
                f"committed {field!r} is not what the code produces from the arm reports "
                f"committed beside it. Either the code changed and "
                f"benchmarks/cve_study/results/ was not regenerated, or the results file was "
                f"edited by hand.\n  committed: {record[field]!r}\n  recomputed: {fresh[field]!r}"
            )


def test_the_published_measurement_comes_out_of_the_re_derived_runs(committed):
    """The whole loop, end to end, from committed evidence to published number.

    ``_runs_from`` trusts the committed verdicts; this re-derives them first and
    only then scores. So the published measurement is pinned to the probe
    reports rather than to the study's own conclusions about them.
    """
    recomputed = measure([readjudicate(r) for r in committed["runs"]]).as_dict()
    assert recomputed == committed["measurement"], (
        "the committed measurement is not what the code produces from the committed arm "
        "reports; re-run `python benchmarks/cve_study/run_study.py` with the fixture cache "
        "populated"
    )


def test_a_tampered_arm_report_breaks_the_re_derivation(committed):
    """Without this, the two tests above would pass for a re-derivation that
    copied its input instead of recomputing it. Flip the one arm the lattice
    keys on and the committed verdict must stop reproducing."""
    record = next(r for r in committed["runs"] if r["lattice_verdict"] == "CANDIDATE")
    tampered = json.loads(json.dumps(record))
    for arm in tampered["arms"]:
        if arm["role"] == "test":
            arm["outcome"] = "refused"
    fresh = readjudicate(tampered).as_dict()
    assert fresh["lattice_verdict"] != record["lattice_verdict"], (
        "an executed treatment arm was re-reported as refused and the lattice still returned "
        f"{record['lattice_verdict']}, so the re-derivation is not reading the arm reports"
    )


def test_a_broken_scorer_is_caught(committed, monkeypatch):
    """Break the scoring rule and the committed numbers must stop reproducing.

    Without this, ``test_the_scorer_reproduces_the_committed_results_exactly``
    would pass for a scorer that returned a constant.
    """
    from benchmarks.cve_study import score

    # The defect under test: counting a refusal as a negative. That is precisely
    # the collapse this repository exists to argue against, so it is the right
    # thing to break.
    monkeypatch.setattr(score, "NO_BUG", "UNINTERPRETABLE")
    broken = score.measure(_runs_from(committed)).as_dict()
    assert broken != committed["measurement"], (
        "a scorer that files every refusal as a negative still reproduced the committed "
        "numbers, so the reproduction test is not testing the scorer"
    )


def test_ground_truth_is_external_not_a_label(committed):
    """Every reached target points at a vendor artefact rather than a verdict."""
    for target in registry.reached():
        assert target.advisory_url.startswith("https://"), target.cve
        assert target.fix_release_url.startswith("https://"), target.cve
        assert target.cve in target.advisory_url, (
            f"{target.cve}'s advisory URL does not name the CVE"
        )


def test_the_lock_pins_every_version_the_study_measured(committed):
    lock = committed["fixtures_lock"]
    for target in registry.reached():
        for package, version in target.pins:
            key = f"{package}=={version}"
            assert key in lock, f"{key} was measured but is not pinned in fixtures.lock.json"
            assert len(lock[key]["sha256"]) == 64, f"{key} has no usable digest"


def test_the_markdown_report_exists_and_quotes_the_headline(committed):
    assert RESULTS_MD.exists()
    text = RESULTS_MD.read_text(encoding="utf-8")
    reached = committed["selection"]["reached"]
    assert f"**{reached} of {committed['selection']['targets_considered']}" in text
    for heading in ("false-negative rate", "false-positive rate", "Seeded rig breakage"):
        assert heading in text, f"the report does not report {heading}"


def test_the_naive_arm_is_never_presented_as_a_comparison():
    text = RESULTS_MD.read_text(encoding="utf-8")
    assert "naive (provenance, not a comparison)" in text
    payload = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
    assert "NOT a comparison" in payload["configurations"]["naive"]


# -------------------------------------------------------------------- statistics


@pytest.mark.parametrize(
    ("successes", "total", "low", "high"),
    [
        (0, 11, 0.0, 0.2849),
        (54, 55, 0.9028, 0.9995),
        (1, 10, 0.0025, 0.4450),
        (5, 10, 0.1871, 0.8129),
        (10, 10, 0.6915, 1.0),
    ],
)
def test_clopper_pearson_matches_published_values(successes, total, low, high):
    """Published textbook values, because an interval nobody checked is decoration.

    An earlier version of this function inverted the wrong tail and reported
    54/55 as [1.00, 1.00], an interval that excludes its own point estimate.
    These five rows are what caught it.
    """
    got_low, got_high = clopper_pearson(successes, total)
    assert got_low == pytest.approx(low, abs=5e-4)
    assert got_high == pytest.approx(high, abs=5e-4)


def test_clopper_pearson_contains_the_point_estimate():
    for total in (5, 11, 33, 55, 88):
        for successes in range(total + 1):
            low, high = clopper_pearson(successes, total)
            assert low <= successes / total <= high, (
                f"the interval for {successes}/{total} excludes its own point estimate"
            )


def test_this_fisher_agrees_with_the_existing_one():
    """The study must not quietly use a friendlier statistic than the benchmark."""
    from benchmarks.run_benchmark import fisher_two_sided as theirs

    for a in range(0, 7, 2):
        for b in range(0, 7, 2):
            for c in range(0, 7, 2):
                for d in range(0, 7, 2):
                    assert fisher_two_sided(a, b, c, d) == pytest.approx(theirs(a, b, c, d))


# ------------------------------------------------------------------ end to end


@pytest.mark.pristine
def test_one_probe_runs_end_to_end_if_the_cache_is_populated():
    """Exercise the real pipeline on a single target, when the pins are present.

    Marked ``pristine`` because it invokes the live gates: under a guard mutation
    the tree is deliberately wrong and this test would go red for every mutation,
    masking whichever guard actually caught it.
    """
    from benchmarks.cve_study import acquire
    from benchmarks.cve_study.runner import execute

    target = registry.by_cve("CVE-2024-22195")
    if not acquire.pin_dir(target.package, target.pre).exists():
        pytest.skip("fixture cache is empty; run run_study.py --acquire first")

    pre = execute(target, target.pre, "pre", None)
    assert pre.predictions["gated"] == "FINDING", (
        f"the pre-fix pin should exhibit {target.cve}; got {pre.verdict}: {pre.verdict_reason}"
    )
    post = execute(target, target.post, "post", None)
    assert post.predictions["gated"] == "NO_BUG", (
        f"the post-fix pin should be clean; got {post.verdict}: {post.verdict_reason}"
    )
