"""Tests for the dedup benchmark: its arithmetic, its labels, its recordings.

The published duplicate rate is a number about this repository, so the things
that could make it a lie are what get tested: an interval computed wrongly, a
label that does not follow the pre-registered rule, a recording that was
hand-written rather than received, and a results file that no longer matches the
recordings it claims to come from.

Nothing here reaches the network. The end-to-end test replays the committed
cassettes, which is also what makes it able to catch a guard being removed: a
mutation to the as-of filter or the pagination accounting moves the headline
number, and the headline number is asserted against the published one.
"""

from __future__ import annotations

import datetime as dt
import difflib
import json
import pathlib
import re

import pytest
from benchmarks.dedup import run_dedup
from benchmarks.dedup.interval import MAX_N, clopper_pearson, rate

from controlarm.gates.priorart import PriorArtVerdict
from controlarm.gates.sources import CassetteStore, Fetcher, FetchMode, parse_subject

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEDUP = ROOT / "benchmarks" / "dedup"
CASSETTES = DEDUP / "cassettes"
MANIFEST = DEDUP / "manifest.json"
RESULTS = DEDUP / "results" / "dedup.md"

#: A fixed point to evaluate the replay at. Far enough ahead of any
#: recording that the freshness window has certainly closed, so the
#: admissibility assertions do not depend on when the suite runs.
SCORED_AT = dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


# ------------------------------------------------------- Clopper-Pearson


@pytest.mark.parametrize(
    ("successes", "total", "low", "high"),
    [
        # Published Clopper-Pearson values, to four places.
        (1, 10, 0.0025, 0.4450),
        (0, 10, 0.0000, 0.3085),
        (10, 10, 0.6915, 1.0000),
        (7, 10, 0.3475, 0.9333),
    ],
)
def test_the_interval_matches_the_published_clopper_pearson_values(successes, total, low, high):
    got_low, got_high = clopper_pearson(successes, total)
    assert round(got_low, 4) == low
    assert round(got_high, 4) == high


def test_a_boundary_interval_is_one_sided_not_zero_width():
    """Failure mode 2. Wald gives [0, 0] at 0/n, which is where a small
    benchmark lands."""
    low, high = clopper_pearson(0, 20)
    assert low == 0.0
    assert high > 0.1


def test_a_rate_with_no_denominator_is_none_rather_than_zero():
    """Failure mode 3. "Nothing was measured" and "the rate is zero" are
    opposite claims."""
    assert rate(0, 0) is None


def test_a_rate_formats_itself_with_its_interval_and_its_n():
    """Failure mode 1: the point estimate cannot be printed on its own."""
    text = str(rate(18, 20))
    assert "90.0%" in text and "18/20" in text and "95% CI" in text


def test_an_n_too_large_for_the_exact_tail_is_refused_not_approximated():
    with pytest.raises(ValueError, match="MAX_N"):
        clopper_pearson(1, MAX_N + 1)


@pytest.mark.parametrize(("successes", "total"), [(-1, 10), (11, 10), (1, 0)])
def test_an_impossible_proportion_is_refused(successes, total):
    with pytest.raises(ValueError):
        clopper_pearson(successes, total)


# --------------------------------------------------------------- scoring


@pytest.mark.parametrize(
    ("label", "verdict", "expected"),
    [
        ("duplicate", PriorArtVerdict.CROWDED, "tp"),
        ("duplicate", PriorArtVerdict.SATURATED, "tp"),
        ("duplicate", PriorArtVerdict.CLEAR, "fn"),
        ("duplicate", PriorArtVerdict.UNGATED, "ungated-positive"),
        ("novel", PriorArtVerdict.CLEAR, "tn"),
        ("novel", PriorArtVerdict.CROWDED, "fp"),
        ("novel", PriorArtVerdict.UNGATED, "ungated-negative"),
    ],
)
def test_every_verdict_and_label_pair_has_one_outcome(label, verdict, expected):
    assert run_dedup.classify(label, verdict) == expected


def test_an_ungated_duplicate_counts_against_recall():
    """The headline metric's conservative direction. A dedup pass that did not
    happen caught nothing."""
    scored = run_dedup.score(["tp", "ungated-positive"])
    assert scored["recall"].successes == 1
    assert scored["recall"].total == 2


def test_an_ungated_novel_is_not_counted_as_a_false_positive():
    """It made no claim, so it cannot be a wrong one. It is still printed."""
    scored = run_dedup.score(["tp", "ungated-negative"])
    assert scored["precision"].total == 1
    assert scored["counts"]["ungated-negative"] == 1


def test_a_run_that_measured_nothing_reports_nothing_rather_than_zero():
    scored = run_dedup.score(["ungated-positive", "ungated-negative"])
    assert scored["precision"] is None
    assert run_dedup.fmt(scored["precision"]).startswith("not measured")


# ---------------------------------------------------- the labelled set


@pytest.mark.pristine
def test_every_label_follows_the_pre_registered_date_rule(manifest):
    """The labels are a date comparison on a field GitHub publishes, not a
    judgement. This test is that sentence, executed."""
    cutoff = dt.datetime.fromisoformat(manifest["cutoff"])
    wrong = []
    for entry in manifest["items"]:
        published = dt.datetime.fromisoformat(entry["published_at"].replace("Z", "+00:00"))
        expected = "duplicate" if published < cutoff else "novel"
        if entry["label"] != expected:
            wrong.append(f"{entry['id']}: published {published} labelled {entry['label']}")
    assert not wrong, "labels disagreeing with the cutoff:\n" + "\n".join(wrong)


@pytest.mark.pristine
def test_the_two_classes_are_balanced_so_the_base_rate_is_half(manifest):
    counts: dict[tuple[str, str], int] = {}
    for entry in manifest["items"]:
        key = (entry["label"], entry["family"])
        counts[key] = counts.get(key, 0) + 1
    assert len(set(counts.values())) == 1, f"unbalanced: {counts}"
    assert set(counts) == {
        ("duplicate", "identifier"),
        ("duplicate", "coordinate"),
        ("novel", "identifier"),
        ("novel", "coordinate"),
    }


@pytest.mark.pristine
def test_every_subject_parses_back_into_what_the_manifest_says_it_is(manifest):
    """A subject the parser reads differently from the manifest would be
    measured against the wrong label."""
    wrong = []
    for entry in manifest["items"]:
        parsed = parse_subject(entry["subject"])
        if entry["family"] == "coordinate":
            got = (parsed.ecosystem, parsed.package, parsed.version)
            want = (entry["ecosystem"], entry["package"], entry["version"])
        else:
            got = set(parsed.advisory_ids)
            want = {entry["ghsa"].upper()} | {c.upper() for c in entry["cves"]}
        if got != want:
            wrong.append(f"{entry['id']}: parsed {got}, manifest says {want}")
    assert not wrong, "\n".join(wrong)


@pytest.mark.pristine
def test_the_attrition_from_the_admissibility_conditions_is_recorded(manifest):
    """Advisories dropped before any gate ran have to be visible, or the set
    looks cleaner than the corpus is."""
    assert "dropped" in manifest
    for drop in manifest["dropped"]:
        assert drop.get("reason"), f"a drop with no reason: {drop}"


# ----------------------------------------------------- the recordings


@pytest.mark.pristine
def test_every_committed_recording_was_received_rather_than_written():
    """The rule that keeps a fabricated response out of a published number."""
    offenders = []
    for path in sorted(CASSETTES.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("provenance") != "recorded":
            offenders.append(f"{path.name}: provenance={raw.get('provenance')!r}")
    assert not offenders, "\n".join(offenders)
    assert len(list(CASSETTES.glob("*.json"))) > 0, "no recordings are committed"


@pytest.mark.pristine
def test_no_committed_recording_contains_a_token_shaped_string():
    shapes = [
        re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    ]
    offenders = []
    for path in sorted(CASSETTES.glob("*.json")):
        text = path.read_text(encoding="utf-8")
        for shape in shapes:
            if shape.search(text):
                offenders.append(f"{path.name}: matches {shape.pattern}")
    assert not offenders, "\n".join(offenders)


@pytest.mark.pristine
def test_every_recorded_request_went_to_an_https_named_host():
    offenders = []
    for path in sorted(CASSETTES.glob("*.json")):
        url = json.loads(path.read_text(encoding="utf-8"))["request"]["url"]
        if not url.startswith("https://"):
            offenders.append(f"{path.name}: {url}")
        if re.match(r"https://(\d+\.|\[)", url):
            offenders.append(f"{path.name}: IP literal in {url}")
    assert not offenders, "\n".join(offenders)


@pytest.mark.pristine
def test_every_recorded_request_carries_a_rerun_command(manifest):
    """A recording a reader cannot re-issue is not evidence."""
    for path in sorted(CASSETTES.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw.get("rerun"), f"{path.name} has no rerun command"
        assert raw["rerun"].startswith(("curl ", "gh api ")), raw["rerun"][:60]


# ------------------------------------------------------------ end to end


#: Memoised so the 80-item replay runs once per session rather than per test.
#: Deliberately *not* a pytest fixture: when a source refuses -- which is what
#: a neutered guard makes it do -- a fixture raising is reported as an ERROR,
#: and `pytest -rf` prints no line for an error, so the mutation sweep could
#: only say "red, but no FAILED line could be parsed" and not which test
#: caught it. Called from inside each test body, the same refusal is a named
#: failure.
_REPLAY: dict[str, list[dict]] = {}


def replayed_rows(manifest: dict) -> list[dict]:
    """The whole benchmark, replayed from the committed recordings."""
    if "rows" not in _REPLAY:
        cutoff = dt.datetime.fromisoformat(manifest["cutoff"])
        sources = run_dedup.build_sources(FetchMode.REPLAY, cutoff, use_nvd=True)
        # A fixed stamp, not the wall clock: the verdicts do not depend on it
        # at all, and the admissibility assertions must mean the same thing on
        # every run. See tests/test_clock.py for why this is a house rule.
        rows = run_dedup.run(manifest, sources, SCORED_AT)
        for source in sources:
            assert source.fetcher.network_calls == 0, f"{source.name} went to the network"
        _REPLAY["rows"] = rows
    return _REPLAY["rows"]


def test_the_replay_answers_every_item(manifest):
    assert len(replayed_rows(manifest)) == len(manifest["items"])


def test_the_published_headline_matches_a_replay_of_the_committed_recordings(manifest):
    """The published number and the committed evidence cannot drift apart.

    This is also the test that makes a mutation to the as-of filter, the
    pagination accounting or the verdict thresholds visible: any of them moves
    this number.
    """
    scored = run_dedup.score([r["outcome"] for r in replayed_rows(manifest)])
    published = RESULTS.read_text(encoding="utf-8")
    recall = re.search(r"\*\*Recall: (.+?)\*\*", published)
    assert recall, "no headline recall in the published results"
    assert recall.group(1) == str(scored["recall"]), (
        "benchmarks/dedup/results/dedup.md no longer matches a replay of the cassettes; "
        "re-run `python benchmarks/dedup/run_dedup.py`"
    )


def _time_independent(text: str) -> list[str]:
    """The published report minus the parts that legitimately move with the clock.

    Two of them, and nothing else. ``scored at`` is a timestamp. The
    admissibility section compares each recording's own retrieval stamp against
    the freshness window, so it depends on when the report was rendered rather
    than on anything measured -- the two tests below it pin that section
    directly instead. ``network calls`` is provenance: a ``--record``
    regeneration writes the warming pass's call count there, and a replay's
    verdicts do not depend on it.

    Everything else is a measurement: every count in the counts table, every
    rate, every per-family number, and every item the gate flagged or missed.
    """
    kept, skipping = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            skipping = line.startswith("## Admissibility")
        if skipping or line.startswith(("- scored at:", "- network calls")):
            continue
        kept.append(line)
    return kept


def test_the_whole_published_report_reproduces_from_the_committed_recordings(manifest):
    """Not just the headline: every number the results file publishes.

    ``test_the_published_headline_matches_a_replay_of_the_committed_recordings``
    pins one figure, recall, and ``run_dedup.py --check`` pins the same one. So
    a change that moved precision, specificity, a per-family rate, or any cell
    of the counts table without moving recall reproduced perfectly and nothing
    noticed -- and a hand-edit to any of those cells was equally invisible.
    This re-renders the report from a replay and asserts it comes out
    character-identical outside the two clock-dependent parts.
    """
    cutoff = dt.datetime.fromisoformat(manifest["cutoff"])
    sources = run_dedup.build_sources(FetchMode.REPLAY, cutoff, use_nvd=True)
    rows = run_dedup.run(manifest, sources, SCORED_AT)
    for source in sources:
        assert source.fetcher.network_calls == 0, f"{source.name} went to the network"
    # `+ "\n"` because that is what `run_dedup.main` writes, and the committed
    # file is what it wrote. Comparing against anything else tests the test.
    fresh = run_dedup.report(manifest, rows, sources, 0, SCORED_AT) + "\n"
    published = RESULTS.read_text(encoding="utf-8")
    diff = list(
        difflib.unified_diff(
            _time_independent(published),
            _time_independent(fresh),
            "benchmarks/dedup/results/dedup.md (committed)",
            "a replay of benchmarks/dedup/cassettes/ (recomputed)",
            lineterm="",
            n=1,
        )
    )
    assert not diff, (
        "the committed dedup results are not what the code produces from the committed "
        "recordings; re-run `python benchmarks/dedup/run_dedup.py`\n" + "\n".join(diff[:40])
    )


def test_the_committed_labelled_set_rebuilds_from_the_committed_recordings(manifest):
    """``build_manifest.py`` is the selection rule's mechanical execution.

    ``SELECTION_RULE.md`` is pre-registered prose and every label in the
    benchmark descends from it, but nothing re-executed it: the manifest was
    committed once and then read as given by every test and by the measurement
    itself. A change to the cutoff, to an admissibility condition, to the
    version rule in ``coordinate()`` or to the purl mapping would have left the
    committed labelled set and the published number perfectly consistent with
    each other and both wrong. This replays the recordings the build consumed
    and asserts the manifest comes back identical.

    ``built_at`` is the one field excluded, and it is a timestamp.
    """
    from benchmarks.dedup import build_manifest

    fetcher = Fetcher(store=CassetteStore(build_manifest.CASSETTES), mode=FetchMode.REPLAY)
    rebuilt = build_manifest.build(fetcher)
    assert fetcher.network_calls == 0, "rebuilding the manifest went to the network"
    assert {k: v for k, v in rebuilt.items() if k != "built_at"} == {
        k: v for k, v in manifest.items() if k != "built_at"
    }, (
        "benchmarks/dedup/manifest.json is not what benchmarks/dedup/build_manifest.py "
        "produces from benchmarks/dedup/cassettes/; either the selection rule's "
        "implementation changed and the manifest was not rebuilt, or the manifest was "
        "edited by hand"
    )


def test_the_published_results_state_what_a_clear_verdict_does_not_license():
    """The one sentence this gate must never be read without."""
    published = RESULTS.read_text(encoding="utf-8")
    assert "is evidence that any finding is novel" in published
    assert "coverage_confidence" in published
    assert "Threats to validity" in published


@pytest.mark.pristine
def test_the_generated_results_file_carries_no_em_dash():
    """The house wording rule applies to generated prose too, and a generator
    is the one place a stray character would come back after every run."""
    assert "—" not in RESULTS.read_text(encoding="utf-8")


def test_admissibility_is_reported_rather_than_assumed(manifest):
    """Replayed evidence ages, so whether these assessments would clear a
    promotion depends on how old the recordings are. The benchmark therefore
    reports the count instead of asserting an outcome, and every inadmissible
    assessment carries its reasons.
    """
    assert "## Admissibility at promotion time" in RESULTS.read_text(encoding="utf-8")
    for row in replayed_rows(manifest):
        assert row["admissible"] == (not row["invalid_because"])


def test_a_replay_is_never_admissible_once_the_recordings_are_old(manifest):
    """The same rule, pinned without depending on today's date: evaluated far
    enough in the future, every one of these verdicts is refused."""
    cutoff = dt.datetime.fromisoformat(manifest["cutoff"])
    sources = run_dedup.build_sources(FetchMode.REPLAY, cutoff, use_nvd=True)
    rows = run_dedup.run(manifest, sources, SCORED_AT)
    assert all(not row["admissible"] for row in rows)
    assert all(row["invalid_because"] for row in rows)


def test_the_check_mode_verifies_the_recordings_and_reproduces_the_headline(capsys):
    """`--check` is the offline reproduction path: it reads the committed
    digests and the committed results, recomputes from the cassettes, and exits
    non-zero on any difference. It writes nothing."""
    code = run_dedup.main(["--check"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "OK" in out
