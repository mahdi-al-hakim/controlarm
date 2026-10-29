"""Tests for the dedup / prior-art gate.

The gate's whole job is to stop one sentence being said: *nobody has published
this, so it is new.* Every test below pins one way that sentence gets said
anyway -- an estimated count, a single source, a stale answer, or no answer at
all read as a clean one.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from controlarm.gates.priorart import (
    COVERAGE_CONFIDENCE_CAP,
    DEFAULT_FRESHNESS,
    CountBasis,
    PriorArtAssessment,
    PriorArtError,
    PriorArtQuery,
    PriorArtThresholds,
    PriorArtVerdict,
    StaticSource,
    assert_gated,
    gate,
)

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)


def q(
    row_count: int = 0,
    source: str = "advisories",
    *,
    retrieved: dt.datetime | None = None,
    basis: CountBasis = CountBasis.MEASURED,
) -> PriorArtQuery:
    return PriorArtQuery(
        query="component AND class",
        source=source,
        retrieved=retrieved or NOW,
        row_count=row_count,
        url="https://example.invalid/search?q=component+AND+class",
        basis=basis,
    )


class FailingSource:
    """A source that cannot answer. Implements the protocol and raises."""

    name = "offline-index"

    def search(self, subject: str) -> list[PriorArtQuery]:
        raise RuntimeError("index unreachable")


class SilentSource:
    """A source that returns no query records at all.

    Distinct from one that returns a record saying zero: this one produced
    nothing to audit, so it has not answered.
    """

    name = "silent-index"

    def search(self, subject: str) -> list[PriorArtQuery]:
        return []


# ------------------------------------------------------------------ the record


def test_a_query_record_carries_the_five_things_that_make_it_auditable():
    record = q(3)
    assert record.query and record.source and record.url
    assert record.row_count == 3
    assert record.retrieved.tzinfo is not None
    assert record.basis is CountBasis.MEASURED


def test_a_query_record_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        q(3).row_count = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"query": ""},
        {"source": ""},
        {"url": ""},
        {"row_count": -1},
        {"retrieved": dt.datetime(2026, 10, 25, 12, 0)},  # naive
    ],
)
def test_an_unauditable_query_record_cannot_be_constructed(kwargs):
    """A row with no URL cannot be re-run, and a naive timestamp cannot be aged."""
    base = {
        "query": "component AND class",
        "source": "advisories",
        "retrieved": NOW,
        "row_count": 0,
        "url": "https://example.invalid/search",
    }
    with pytest.raises(PriorArtError):
        PriorArtQuery(**{**base, **kwargs})


# ------------------------------------------------------------------ the ladder


def test_no_rows_from_an_answering_source_is_clear():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert assessment.verdict is PriorArtVerdict.CLEAR
    assert assessment.row_total == 0


def test_any_public_prior_art_at_all_is_crowded():
    assessment = gate("subject", [StaticSource("advisories", [q(1)])], now=NOW)
    assert assessment.verdict is PriorArtVerdict.CROWDED


def test_enough_public_prior_art_is_saturated():
    assessment = gate("subject", [StaticSource("advisories", [q(9)])], now=NOW)
    assert assessment.verdict is PriorArtVerdict.SATURATED


def test_the_saturation_threshold_is_configurable():
    sources = [StaticSource("advisories", [q(4)])]
    assert gate("s", sources, now=NOW).verdict is PriorArtVerdict.CROWDED
    tight = PriorArtThresholds(saturated_at=4)
    assert gate("s", sources, now=NOW, thresholds=tight).verdict is PriorArtVerdict.SATURATED


def test_rows_are_summed_across_sources():
    assessment = gate(
        "subject",
        [
            StaticSource("advisories", [q(2, "advisories")]),
            StaticSource("issues", [q(3, "issues")]),
        ],
        now=NOW,
    )
    assert assessment.row_total == 5
    assert assessment.verdict is PriorArtVerdict.SATURATED


@pytest.mark.parametrize("bad", [0, -1])
def test_a_nonsense_threshold_fails_loudly(bad):
    with pytest.raises(PriorArtError):
        PriorArtThresholds(saturated_at=bad)


# ----------------------------------------------------------------- UNGATED


def test_no_source_answering_is_ungated_not_clear():
    """Failure mode 5, and the one the whole module exists for.

    Zero sources answered and zero rows found are the same number and opposite
    claims. A gate that returns CLEAR here converts a broken pipeline into a
    novelty argument.
    """
    assessment = gate("subject", [FailingSource()], now=NOW)
    assert assessment.verdict is PriorArtVerdict.UNGATED
    assert assessment.row_total == 0
    assert assessment.verdict is not PriorArtVerdict.CLEAR
    assert not assessment.is_clear


def test_a_source_that_returns_no_records_has_not_answered():
    assessment = gate("subject", [SilentSource()], now=NOW)
    assert assessment.verdict is PriorArtVerdict.UNGATED


def test_a_source_that_returns_a_zero_record_has_answered():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert assessment.verdict is PriorArtVerdict.CLEAR


def test_an_ungated_assessment_never_clears_promotion():
    assessment = gate("subject", [FailingSource()], now=NOW)
    assert not assessment.clears_promotion(NOW)
    with pytest.raises(PriorArtError) as exc:
        assert_gated(assessment, now=NOW)
    assert "UNGATED" in str(exc.value)


def test_a_crowded_verdict_is_refused_for_being_crowded_not_for_being_stale():
    """The two refusal paths in ``assert_gated`` are different refusals.

    A CROWDED verdict is admissible and still refused; a stale CLEAR verdict is
    CLEAR and still refused. Collapsing them would let one of the two guards be
    deleted without any test noticing.
    """
    crowded = gate("subject", [StaticSource("advisories", [q(3)])], now=NOW)
    assert crowded.validity(NOW).valid
    with pytest.raises(PriorArtError) as exc:
        assert_gated(crowded, now=NOW)
    assert "not CLEAR" in str(exc.value)
    assert "CROWDED" in str(exc.value)


def test_a_stale_clear_verdict_is_refused_for_being_stale():
    clear = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert clear.is_clear
    with pytest.raises(PriorArtError) as exc:
        assert_gated(clear, now=NOW + dt.timedelta(hours=25))
    assert "not admissible" in str(exc.value)
    assert "older than" in str(exc.value)


def test_a_failure_is_recorded_with_its_reason():
    assessment = gate("subject", [FailingSource()], now=NOW)
    assert assessment.sources_asked == ("offline-index",)
    assert assessment.sources_answered == ()
    assert len(assessment.failures) == 1
    source, why = assessment.failures[0]
    assert source == "offline-index"
    assert "RuntimeError" in why and "unreachable" in why


def test_one_working_source_among_failures_still_gates():
    assessment = gate(
        "subject",
        [FailingSource(), StaticSource("advisories", [q(0)])],
        now=NOW,
    )
    assert assessment.verdict is PriorArtVerdict.CLEAR
    assert assessment.sources_answered == ("advisories",)
    assert assessment.failures


def test_only_clear_clears_promotion():
    """The one-line statement of the gate, checked across the whole enum."""
    for verdict in PriorArtVerdict:
        assessment = dataclasses.replace(
            gate("subject", [StaticSource("advisories", [q(0)])], now=NOW), verdict=verdict
        )
        assert assessment.clears_promotion(NOW) is (verdict is PriorArtVerdict.CLEAR)


# ---------------------------------------------------------------- freshness


def test_a_verdict_inside_the_window_is_valid():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert assessment.validity(NOW + dt.timedelta(hours=23)).valid


def test_a_verdict_older_than_the_window_is_invalid_at_promotion():
    """Failure mode 4. A fix landing mid-flight turns a finding into a duplicate."""
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    later = NOW + dt.timedelta(hours=25)
    validity = assessment.validity(later)
    assert not validity.valid
    assert any("older than" in r for r in validity.reasons)
    assert not assessment.clears_promotion(later)


def test_the_freshness_window_is_configurable():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    later = NOW + dt.timedelta(hours=25)
    assert assessment.clears_promotion(later, window=dt.timedelta(days=7))
    assert dt.timedelta(hours=24) == DEFAULT_FRESHNESS


def test_a_fresh_stamp_over_stale_queries_is_invalid():
    """Failure mode 7. Re-stamping is not re-running.

    An assessment assembled today out of last week's query records is as wrong
    as a week-old assessment, and it looks fresh, which is worse.
    """
    stale = q(0, retrieved=NOW - dt.timedelta(days=7))
    assessment = gate("subject", [StaticSource("advisories", [stale])], now=NOW)
    validity = assessment.validity(NOW)
    assert not validity.valid
    assert any("retrieved" in r for r in validity.reasons)


def test_a_query_retrieved_after_the_assessment_is_invalid():
    """A record cannot have been consulted after the conclusion was drawn."""
    ahead = q(0, retrieved=NOW + dt.timedelta(hours=1))
    assessment = gate("subject", [StaticSource("advisories", [ahead])], now=NOW)
    assert not assessment.validity(NOW).valid


def test_a_clock_that_reads_backwards_is_invalid_rather_than_fresh():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert not assessment.validity(NOW - dt.timedelta(hours=1)).valid


def test_an_ungated_verdict_is_invalid_on_its_own_grounds():
    """Not merely "not CLEAR" -- positively inadmissible, and said so.

    ``is_clear`` already keeps UNGATED out of a promotion, so this clause looks
    redundant until the day somebody reads ``validity`` on its own and takes a
    valid-looking record as a dedup pass. The reason has to be in the record.
    """
    assessment = gate("subject", [FailingSource()], now=NOW)
    validity = assessment.validity(NOW)
    assert not validity.valid
    assert any("UNGATED is not CLEAR" in r for r in validity.reasons)


def test_a_query_consulted_after_the_conclusion_is_invalid_on_ordering_alone():
    """Separated from the in-the-future clause on purpose.

    Here the query is fresh and in the past relative to ``now``, so only the
    ordering against ``assessed_at`` is wrong: the record was assembled after
    the conclusion was drawn.
    """
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    later_query = dataclasses.replace(
        assessment,
        queries=(q(0, retrieved=NOW + dt.timedelta(minutes=30)),),
    )
    validity = later_query.validity(NOW + dt.timedelta(hours=1))
    assert not validity.valid
    assert any("out of order" in r for r in validity.reasons)


def test_an_assessment_stamped_in_the_future_is_invalid_on_its_own():
    """Separated from the stale-query clause for the same reason: with the
    queries themselves fresh and correctly ordered, only the assessment's own
    forward timestamp is wrong, and that must be enough."""
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    ahead = dataclasses.replace(
        assessment,
        assessed_at=NOW + dt.timedelta(hours=2),
        queries=(q(0, retrieved=NOW - dt.timedelta(hours=1)),),
    )
    validity = ahead.validity(NOW)
    assert not validity.valid
    assert any("future" in r for r in validity.reasons)


def test_validity_requires_a_timezone_aware_now():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    with pytest.raises(PriorArtError):
        assessment.validity(dt.datetime(2026, 10, 25, 12, 0))


# -------------------------------------------------------- measured vs estimated


def test_an_estimated_count_invalidates_the_verdict():
    """Failure mode 3. "About 200 results" is not a row count.

    A search interface that reports an approximate total is reporting its own
    pagination, and a dedup argument built on it cannot be re-derived by a
    reader. The verdict is still computed and recorded -- it is just not
    admissible at promotion.
    """
    assessment = gate(
        "subject",
        [StaticSource("advisories", [q(0, basis=CountBasis.ESTIMATED)])],
        now=NOW,
    )
    validity = assessment.validity(NOW)
    assert not validity.valid
    assert any("estimated" in r for r in validity.reasons)
    assert "advisories" in " ".join(validity.reasons)
    assert not assessment.clears_promotion(NOW)


def test_one_estimated_count_among_measured_ones_still_invalidates():
    assessment = gate(
        "subject",
        [
            StaticSource("advisories", [q(0, "advisories")]),
            StaticSource("issues", [q(0, "issues", basis=CountBasis.ESTIMATED)]),
        ],
        now=NOW,
    )
    assert not assessment.validity(NOW).valid


def test_every_count_measured_is_valid():
    assessment = gate(
        "subject",
        [
            StaticSource("advisories", [q(0, "advisories")]),
            StaticSource("issues", [q(0, "issues")]),
        ],
        now=NOW,
    )
    assert assessment.validity(NOW).valid


# ------------------------------------------------------- coverage confidence


def test_coverage_confidence_is_capped_below_one():
    """Failure mode 6. Nothing public can measure the crowd, let alone the
    vendor's own internal sweep, so the number is not allowed to approach 1."""
    sources = [StaticSource(f"s{i}", [q(0, f"s{i}")]) for i in range(12)]
    assessment = gate("subject", sources, now=NOW)
    assert assessment.coverage_confidence <= COVERAGE_CONFIDENCE_CAP
    assert COVERAGE_CONFIDENCE_CAP < 1.0


def test_coverage_confidence_rises_with_the_sources_that_answered():
    one = gate("s", [StaticSource("a", [q(0, "a")]), FailingSource()], now=NOW)
    two = gate("s", [StaticSource("a", [q(0, "a")]), StaticSource("b", [q(0, "b")])], now=NOW)
    assert 0 < one.coverage_confidence < two.coverage_confidence


def test_an_ungated_assessment_has_no_coverage_confidence():
    assert gate("s", [FailingSource()], now=NOW).coverage_confidence == 0.0


def test_coverage_confidence_carries_its_own_disclaimer():
    """Failure modes 1 and 6, in one string that travels with the number."""
    note = gate("s", [StaticSource("a", [q(0, "a")])], now=NOW).coverage_note
    assert "public activity" in note
    assert "not" in note and "coverage" in note


def test_a_single_source_assessment_says_so():
    """Failure mode 2: never trust a single-source zero."""
    validity = gate("s", [StaticSource("a", [q(0, "a")])], now=NOW).validity(NOW)
    assert validity.valid
    assert any("single source" in w for w in validity.warnings)


def test_two_sources_do_not_raise_the_single_source_warning():
    validity = gate(
        "s", [StaticSource("a", [q(0, "a")]), StaticSource("b", [q(0, "b")])], now=NOW
    ).validity(NOW)
    assert not any("single source" in w for w in validity.warnings)


# ------------------------------------------------------------------ the record


def test_the_assessment_keeps_every_query_it_was_built_from():
    rows = [q(1, "advisories"), q(2, "advisories")]
    assessment = gate("subject", [StaticSource("advisories", rows)], now=NOW)
    assert assessment.queries == tuple(rows)


def test_the_assessment_is_immutable():
    assessment = gate("subject", [StaticSource("advisories", [q(0)])], now=NOW)
    assert isinstance(assessment, PriorArtAssessment)
    with pytest.raises(dataclasses.FrozenInstanceError):
        assessment.verdict = PriorArtVerdict.CLEAR  # type: ignore[misc]


def test_the_assessment_serialises_without_losing_a_field():
    import json

    assessment = gate("subject", [StaticSource("advisories", [q(2)])], now=NOW)
    text = json.dumps(assessment.as_dict())
    for needle in ["CROWDED", "advisories", "component AND class", "public activity"]:
        assert needle in text


def test_the_core_makes_no_network_call():
    """A gate that reaches the network cannot be run in CI, and a dedup gate
    that cannot be run in CI is a gate nobody runs."""
    import controlarm.gates.priorart as module

    source = module.__loader__.get_source(module.__name__) or ""
    for forbidden in ["urllib.request", "http.client", "socket", "requests", "subprocess"]:
        assert forbidden not in source


def test_gate_requires_a_timezone_aware_now():
    with pytest.raises(PriorArtError):
        gate("subject", [StaticSource("advisories", [q(0)])], now=dt.datetime(2026, 10, 25))


def test_a_registered_source_may_be_any_object_with_the_protocol():
    class Custom:
        name = "custom"

        def search(self, subject: str) -> list[PriorArtQuery]:
            return [q(7, "custom")]

    assessment = gate("subject", [Custom()], now=NOW)
    assert assessment.verdict is PriorArtVerdict.SATURATED
    assert assessment.sources_answered == ("custom",)


def test_a_source_whose_records_name_a_different_source_fails_loudly():
    """A record's ``source`` field is what a reader audits. If it disagrees with
    the source that produced it, the audit trail is wrong."""
    with pytest.raises(PriorArtError):
        gate("subject", [StaticSource("advisories", [q(0, "something-else")])], now=NOW)


def test_an_empty_source_list_is_ungated():
    assessment = gate("subject", [], now=NOW)
    assert assessment.verdict is PriorArtVerdict.UNGATED
    assert assessment.sources_asked == ()
