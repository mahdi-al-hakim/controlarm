"""The dedup / prior-art gate.

A candidate finding is not a result until somebody has asked whether it is
already known, and the asking has to be auditable or it is just a feeling. This
module turns "I searched and found nothing" into a record a reader can re-run:
what was searched, which source answered, when, how many rows came back, and
whether that number was counted or guessed.

The core makes **no network calls**. A `Source` is a protocol a caller
registers, so the network lives in the caller and the gate stays runnable in CI.
``StaticSource`` covers tests, examples and the offline case.

This module is new rather than ported, so the numbered items below are the
wrong verdicts it exists to prevent rather than defects in an earlier version.
Each is a failure recorded in the method it implements:

  1  public silence read as novelty             -> "Nobody has published this,
     so it is new." Public search measures the crowd term only; it cannot see a
     vendor's own internal sweep, which is where duplicates actually come from.
     The gate therefore never emits a *novelty* verdict, only a crowding one,
     and says so in ``coverage_note``.
  2  a single-source zero read as a zero        -> one index's advisories page
     said "no published advisories" for a repository that another database
     carried seven entries for. A one-source answer is valid and carries a
     warning saying it is one source.
  3  an estimated count read as a measurement   -> "about 200 results" is a
     report of a search engine's pagination, not a row count, and a reader
     cannot re-derive it. An estimated basis anywhere invalidates the verdict.
  4  a stale verdict reused at promotion        -> a fix landing between the
     search and the submission converts a finding into a duplicate. A verdict
     older than the freshness window is inadmissible.
  5  UNGATED read as CLEAR                      -> "no source answered" and "no
     prior art found" are the same row count and opposite claims. ``UNGATED``
     is a distinct verdict, ``is_clear`` is false for it, and it never clears
     promotion.
  6  coverage confidence read as crowd coverage -> the number measures how many
     of the sources asked actually answered. It is capped well below 1 and
     carries its disclaimer as a field, so the number cannot travel without it.
  7  a fresh stamp over stale queries           -> re-stamping is not re-running.
     Every query's own retrieval time is aged, not just the assessment's.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

__all__ = [
    "COVERAGE_CONFIDENCE_CAP",
    "COVERAGE_NOTE",
    "DEFAULT_FRESHNESS",
    "CountBasis",
    "PriorArtAssessment",
    "PriorArtError",
    "PriorArtQuery",
    "PriorArtThresholds",
    "PriorArtVerdict",
    "Source",
    "StaticSource",
    "Validity",
    "assert_gated",
    "gate",
]

#: Twenty-four hours. Short enough that a fix landing mid-flight is caught, long
#: enough that a dedup pass survives a night's sleep.
DEFAULT_FRESHNESS = dt.timedelta(hours=24)

#: The ceiling on ``coverage_confidence``. Deliberately not 0.9 and certainly not
#: 1.0: the dominant duplicate source is a vendor's own internal review, which no
#: public query can observe at all, so the measurable part of coverage is a
#: minority of the thing being estimated.
COVERAGE_CONFIDENCE_CAP = 0.6

COVERAGE_NOTE = (
    "coverage_confidence measures how many of the sources asked actually answered. "
    "It measures public activity, not crowd coverage, and it cannot see a vendor's "
    "internal review -- which is where duplicates predominantly come from. It is "
    f"capped at {COVERAGE_CONFIDENCE_CAP} for that reason. A CLEAR verdict means no "
    "public prior art was found, never that the finding is novel."
)


class PriorArtError(Exception):
    """Raised on an unauditable record, and when a gate refuses a promotion."""


class CountBasis(str, Enum):
    """Where a row count came from. Only one of these is admissible."""

    MEASURED = "measured"
    """The rows were enumerated and counted."""

    ESTIMATED = "estimated"
    """The count is the source's own approximation. Invalidates the verdict."""


class PriorArtVerdict(str, Enum):
    """Four verdicts, and only the first one lets a candidate through."""

    CLEAR = "CLEAR"
    """At least one source answered and no public prior art was found. Not a
    claim of novelty: see ``COVERAGE_NOTE``."""

    CROWDED = "CROWDED"
    """Public prior art exists. Submit only with a stated difference."""

    SATURATED = "SATURATED"
    """Enough public prior art that the region is not worth the budget."""

    UNGATED = "UNGATED"
    """No source answered. Nothing was measured, so nothing was gated. This is
    the absence of a dedup pass, not the result of one."""


@dataclass(frozen=True)
class PriorArtQuery:
    """One search, recorded so a reader can re-run it.

    All five fields are load-bearing. A record with no URL cannot be re-run; a
    record with a naive timestamp cannot be aged; a record with no source cannot
    be attributed. Each is refused at construction rather than later.
    """

    query: str
    source: str
    retrieved: dt.datetime
    row_count: int
    url: str
    basis: CountBasis = CountBasis.MEASURED

    def __post_init__(self) -> None:
        for name in ("query", "source", "url"):
            if not str(getattr(self, name) or "").strip():
                raise PriorArtError(
                    f"PriorArtQuery.{name} is empty. A query record exists so a reader can "
                    "re-derive the count; a record missing any of query, source or url cannot "
                    "be re-derived and is therefore not evidence."
                )
        if not isinstance(self.row_count, int) or isinstance(self.row_count, bool):
            raise PriorArtError(f"row_count must be an int, got {type(self.row_count).__name__}")
        if self.row_count < 0:
            raise PriorArtError(f"row_count must not be negative, got {self.row_count}")
        _require_aware(self.retrieved, "PriorArtQuery.retrieved")

    def as_dict(self) -> dict:
        return {
            "query": self.query,
            "source": self.source,
            "retrieved": self.retrieved.isoformat(),
            "row_count": self.row_count,
            "url": self.url,
            "basis": self.basis.value,
        }


@dataclass(frozen=True)
class PriorArtThresholds:
    """Where CROWDED becomes SATURATED. CLEAR is exactly zero rows, always."""

    saturated_at: int = 5

    def __post_init__(self) -> None:
        if not isinstance(self.saturated_at, int) or self.saturated_at < 1:
            raise PriorArtError(
                f"saturated_at must be a positive integer, got {self.saturated_at!r}. "
                "A threshold of zero would make every answer SATURATED, including a clean one."
            )


@dataclass(frozen=True)
class Validity:
    """Whether an assessment may be used at promotion time.

    ``warnings`` are things a reader must know that do not by themselves
    disqualify the verdict -- a single-source answer being the main one.
    """

    valid: bool
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@runtime_checkable
class Source(Protocol):
    """A prior-art source. Implement this to put the network in the caller.

    ``search`` returns one ``PriorArtQuery`` per query actually run. Returning an
    empty sequence means "I did not answer", which is not the same as returning
    one record whose ``row_count`` is zero. Raising also means "I did not
    answer"; the exception is recorded, never swallowed.
    """

    name: str

    def search(self, subject: str) -> Sequence[PriorArtQuery]: ...


@dataclass(frozen=True)
class StaticSource:
    """An offline source with a fixed answer, for tests, examples and replay."""

    name: str
    queries: Sequence[PriorArtQuery] = ()

    def search(self, subject: str) -> Sequence[PriorArtQuery]:
        return tuple(self.queries)


@dataclass(frozen=True)
class PriorArtAssessment:
    """The gate's output: a verdict plus everything needed to audit it."""

    subject: str
    verdict: PriorArtVerdict
    reason: str
    assessed_at: dt.datetime
    queries: tuple[PriorArtQuery, ...] = ()
    sources_asked: tuple[str, ...] = ()
    sources_answered: tuple[str, ...] = ()
    failures: tuple[tuple[str, str], ...] = ()
    thresholds: PriorArtThresholds = field(default_factory=PriorArtThresholds)

    # ------------------------------------------------------------------ readings

    @property
    def row_total(self) -> int:
        return sum(q.row_count for q in self.queries)

    @property
    def is_clear(self) -> bool:
        """True only for ``CLEAR``. Failure mode 5 lives on this one line."""
        return self.verdict is PriorArtVerdict.CLEAR

    @property
    def coverage_confidence(self) -> float:
        """The answered fraction of the sources asked, scaled to the cap."""
        if not self.sources_asked:
            return 0.0
        answered = len(self.sources_answered) / len(self.sources_asked)
        return min(COVERAGE_CONFIDENCE_CAP, answered * COVERAGE_CONFIDENCE_CAP)

    @property
    def coverage_note(self) -> str:
        return COVERAGE_NOTE

    # ------------------------------------------------------------------ validity

    def validity(self, now: dt.datetime, window: dt.timedelta = DEFAULT_FRESHNESS) -> Validity:
        """Is this assessment admissible at ``now``?

        Every clause here is one of the numbered failure modes. None of them
        changes the verdict: a stale CROWDED is still CROWDED, it is just not
        usable as a gate. Rewriting the verdict would destroy the record.
        """
        _require_aware(now, "now")
        reasons: list[str] = []
        warnings: list[str] = []

        if self.verdict is PriorArtVerdict.UNGATED:
            reasons.append(
                "the verdict is UNGATED: no source answered, so no prior-art count exists. "
                "UNGATED is not CLEAR."
            )

        age = now - self.assessed_at
        if age < dt.timedelta(0):
            reasons.append(
                f"the assessment is stamped {-age} in the future, so the clock on one side of "
                "this comparison is wrong. A future timestamp is a broken instrument."
            )
        elif age > window:
            reasons.append(
                f"the assessment is {age} old, which is older than the {window} freshness "
                "window. Prior art accumulates; re-run the sources."
            )

        estimated = sorted({q.source for q in self.queries if q.basis is CountBasis.ESTIMATED})
        if estimated:
            reasons.append(
                f"the count from {estimated} is estimated rather than measured, so a reader "
                "cannot re-derive it. An estimated count is a report of the source's own "
                "pagination, not of the prior art."
            )

        for q in self.queries:
            query_age = now - q.retrieved
            if query_age < dt.timedelta(0):
                reasons.append(
                    f"a query against {q.source} is marked retrieved in the future "
                    f"({q.retrieved.isoformat()})"
                )
            elif query_age > window:
                reasons.append(
                    f"a query against {q.source} was retrieved {query_age} ago, outside the "
                    f"{window} window. Re-stamping an assessment is not re-running it."
                )
            if q.retrieved > self.assessed_at:
                reasons.append(
                    f"a query against {q.source} is marked retrieved after the assessment was "
                    "made, so the record was assembled out of order and cannot be trusted."
                )

        if self.queries and not self.sources_answered:
            reasons.append("query records exist but no source is recorded as having answered")

        if len(self.sources_answered) == 1:
            warnings.append(
                f"this verdict rests on a single source ({self.sources_answered[0]}). Never "
                "treat a single-source zero as a zero: indexes disagree, and a repository-level "
                "advisory is invisible to a package-level database."
            )

        return Validity(not reasons, tuple(reasons), tuple(warnings))

    def clears_promotion(self, now: dt.datetime, window: dt.timedelta = DEFAULT_FRESHNESS) -> bool:
        """CLEAR and admissible. Nothing else, and there is no override."""
        return self.is_clear and self.validity(now, window).valid

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "assessed_at": self.assessed_at.isoformat(),
            "row_total": self.row_total,
            "sources_asked": list(self.sources_asked),
            "sources_answered": list(self.sources_answered),
            "failures": [list(f) for f in self.failures],
            "coverage_confidence": self.coverage_confidence,
            "coverage_note": self.coverage_note,
            "saturated_at": self.thresholds.saturated_at,
            "queries": [q.as_dict() for q in self.queries],
        }


# -------------------------------------------------------------------- the gate


def gate(
    subject: str,
    sources: Iterable[Source],
    *,
    now: dt.datetime,
    thresholds: PriorArtThresholds | None = None,
) -> PriorArtAssessment:
    """Ask every source about ``subject`` and classify what came back.

    A source that raises has not answered: the exception is recorded in
    ``failures`` and the source is absent from ``sources_answered``. If nothing
    answered the verdict is ``UNGATED``, which is the one outcome that must never
    be mistaken for a clean result.
    """
    _require_aware(now, "now")
    limits = thresholds or PriorArtThresholds()

    asked: list[str] = []
    answered: list[str] = []
    failures: list[tuple[str, str]] = []
    rows: list[PriorArtQuery] = []

    for source in sources:
        name = getattr(source, "name", None) or type(source).__name__
        asked.append(name)
        try:
            produced = tuple(source.search(subject))
        except Exception as exc:
            # Recorded, never swallowed: a source that failed silently is
            # indistinguishable from a source that found nothing.
            failures.append((name, f"{type(exc).__name__}: {exc}"))
            continue
        if not produced:
            failures.append((name, "returned no query records, so it reported nothing to audit"))
            continue
        for record in produced:
            if record.source != name:
                raise PriorArtError(
                    f"source {name!r} produced a record attributed to {record.source!r}. "
                    "The attribution is what a reader audits, so a mismatch is fatal."
                )
        answered.append(name)
        rows.extend(produced)

    total = sum(r.row_count for r in rows)
    if not answered:
        verdict = PriorArtVerdict.UNGATED
        reason = (
            f"no source answered out of {len(asked)} asked ({asked or 'none registered'}). "
            "Nothing was measured, so nothing was gated. This is not a CLEAR result and it "
            "must not be recorded as one."
        )
    elif total == 0:
        verdict = PriorArtVerdict.CLEAR
        reason = (
            f"{len(answered)} of {len(asked)} source(s) answered with zero rows across "
            f"{len(rows)} query record(s). No PUBLIC prior art was found. This is not a "
            "novelty claim: public search cannot see a vendor's internal review."
        )
    elif total < limits.saturated_at:
        verdict = PriorArtVerdict.CROWDED
        reason = (
            f"{total} public prior-art row(s) across {len(rows)} query record(s), below the "
            f"saturation threshold of {limits.saturated_at}. Submit only with a stated, "
            "specific difference from each row."
        )
    else:
        verdict = PriorArtVerdict.SATURATED
        reason = (
            f"{total} public prior-art row(s), at or above the saturation threshold of "
            f"{limits.saturated_at}. Spend the budget on a region with less public activity."
        )

    return PriorArtAssessment(
        subject=subject,
        verdict=verdict,
        reason=reason,
        assessed_at=now,
        queries=tuple(rows),
        sources_asked=tuple(asked),
        sources_answered=tuple(answered),
        failures=tuple(failures),
        thresholds=limits,
    )


def assert_gated(
    assessment: PriorArtAssessment,
    *,
    now: dt.datetime,
    window: dt.timedelta = DEFAULT_FRESHNESS,
) -> PriorArtAssessment:
    """Raise unless the assessment is CLEAR and admissible.

    There is no override parameter. A CROWDED verdict is not an error -- it is
    the normal outcome -- so this is the call a promotion step makes, not one a
    dedup run makes.
    """
    validity = assessment.validity(now, window)
    if not assessment.is_clear:
        raise PriorArtError(
            f"prior-art gate refused: verdict is {assessment.verdict.value}, not CLEAR. "
            f"{assessment.reason}"
        )
    if not validity.valid:
        raise PriorArtError(
            "prior-art gate refused: the CLEAR verdict is not admissible because "
            + "; ".join(validity.reasons)
        )
    return assessment


def _require_aware(value: dt.datetime, label: str) -> None:
    if not isinstance(value, dt.datetime):
        raise PriorArtError(f"{label} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise PriorArtError(
            f"{label} must be timezone-aware. A naive timestamp cannot be aged against a "
            "freshness window without silently assuming a timezone, and the assumption is "
            "wrong on exactly the machines that matter."
        )
