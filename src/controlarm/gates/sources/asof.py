"""Asking a corpus what it knew on a particular day.

The novelty half of the dedup benchmark depends on this. "Is this finding
novel?" cannot be answered by judgement without the judgement being the thing
under test, so it is answered by chronology instead: take an advisory published
after a pinned cutoff, ask the corpus **as of that cutoff**, and a row count of
zero is then novelty established by the calendar rather than by an opinion.

No public corpus here offers an as-of parameter, so the filter is applied
client side on each record's own publication date. That has two consequences a
reader has to be told, and both are in ``docs/prior-art.md`` as threats to
validity:

  * A record published before the cutoff but **amended** afterwards is counted
    as it stands today, not as it stood then. The bias is toward counting prior
    art that did not yet exist in that form, which inflates CROWDED.
  * A record carrying no publication date at all cannot be placed in time. It
    is counted, not dropped -- the conservative direction -- and the count says
    so, so the reader can see how much of the answer rests on undated rows.

Numbered failure modes:

  1  an as-of filter applied to the wrong field -> ``modified`` is later than
     ``published`` for most advisories, so filtering on ``modified`` discards
     real pre-cutoff prior art and manufactures novelty. Only ``published`` is
     read, and the field name is recorded in the query text.
  2  an undated row silently dropped           -> dropping it is the direction
     that invents novelty. It is counted, and counted separately.
  3  a naive cutoff compared to an aware stamp -> raises in Python, but only on
     the first record that happens to carry a date. The cutoff is required
     aware at construction.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from controlarm.gates.priorart import PriorArtError

__all__ = ["AsOf", "Tally", "parse_timestamp"]


def parse_timestamp(raw: object) -> dt.datetime | None:
    """Parse an advisory timestamp, or ``None`` if there is not one to parse.

    Accepts the RFC3339 spellings these corpora actually emit, including the
    trailing ``Z`` that ``fromisoformat`` rejects before Python 3.11 and the
    no-offset form NVD uses.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # NVD stamps ``2022-04-12T05:15:06.927`` with no offset and documents
        # the values as UTC. Assuming UTC is recorded in the query text rather
        # than hidden, because the assumption is only wrong by hours and the
        # alternative is discarding the field.
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


@dataclass(frozen=True)
class Tally:
    """How an as-of filter went: kept, dropped, and undated-but-kept."""

    kept: int = 0
    dropped: int = 0
    undated: int = 0

    def note(self) -> str:
        bits = [f"kept={self.kept}", f"dropped-after-cutoff={self.dropped}"]
        if self.undated:
            bits.append(f"undated-and-counted={self.undated}")
        return " ".join(bits)


@dataclass(frozen=True)
class AsOf:
    """A cutoff, or no cutoff at all."""

    cutoff: dt.datetime | None = None

    def __post_init__(self) -> None:
        if self.cutoff is None:
            return
        if not isinstance(self.cutoff, dt.datetime):
            raise PriorArtError(
                f"as-of cutoff must be a datetime, got {type(self.cutoff).__name__}"
            )
        if self.cutoff.tzinfo is None or self.cutoff.tzinfo.utcoffset(self.cutoff) is None:
            raise PriorArtError(
                "as-of cutoff must be timezone-aware. A naive cutoff compared against an "
                "advisory's aware timestamp raises on the first dated record and silently "
                "works on every undated one, which is the worst available ordering."
            )

    @property
    def label(self) -> str:
        return "as-of=none (current corpus)" if self.cutoff is None else f"as-of={self.iso}"

    @property
    def iso(self) -> str:
        return "" if self.cutoff is None else self.cutoff.isoformat()

    def admits(self, published: object) -> tuple[bool, bool]:
        """``(kept, undated)`` for one record's ``published`` value.

        Failure modes 1 and 2 are the two returns: the field read is the one
        passed in by the caller -- always ``published`` -- and an unparseable
        one is kept rather than dropped.
        """
        if self.cutoff is None:
            return True, False
        stamp = parse_timestamp(published)
        if stamp is None:
            return True, True
        return stamp <= self.cutoff, False

    def filter(self, records: list[dict], field: str = "published") -> tuple[list[dict], Tally]:
        """Keep the records that existed at the cutoff, and count the rest."""
        kept: list[dict] = []
        dropped = undated = 0
        for record in records:
            admitted, no_date = self.admits(record.get(field))
            if no_date:
                undated += 1
            if admitted:
                kept.append(record)
            else:
                dropped += 1
        return kept, Tally(len(kept), dropped, undated)
