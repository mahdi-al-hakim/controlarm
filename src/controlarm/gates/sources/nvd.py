"""NVD's CVE API 2.0 as a prior-art source.

Why a third source when two were the requirement: OSV and the GitHub Advisory
Database are both *package*-shaped. A CVE against a router's firmware, a
desktop application or a protocol has no package coordinate, so both of them
answer zero about it, and two zeros from two package databases look like
corroboration while being the same blind spot twice. NVD is the corpus that
sees those.

It is also the slowest. Without an API key NVD permits roughly five requests
per rolling thirty seconds, so ``MIN_INTERVAL_SECONDS`` is deliberately large
and this source is **not** in the default set; the dedup benchmark enables it
explicitly and pays the wall-clock cost.

What it covers: published CVE records, by identifier.

What it does not cover:

  * Any identifier that is not a CVE. A ``GHSA-`` with no CVE assigned is
    invisible here, and this source declines rather than answering zero.
  * Package coordinates. NVD's product matching goes through CPE names, and a
    package name is not a CPE name; guessing one would put a fabricated
    identifier into a row count. A package-only subject is declined.

Numbered failure modes:

  1  a GHSA answered as a zero            -> declined instead. See above.
  2  a rejected CVE subtracted           -> NVD marks duplicate and withdrawn
     identifiers ``vulnStatus: Rejected``, and a rejected record usually points
     at the CVE that superseded it. Dropping it moves the count toward CLEAR,
     which is the direction that invents novelty, so it is counted and the
     rejected tally is recorded beside it.
  3  a page counted as a total            -> ``totalResults`` can exceed
     ``startIndex + resultsPerPage``. When it does, the count is an estimate.
  4  an empty result set and a 404 conflated with an outage -> 404 and
     ``totalResults: 0`` are measured zeros; a 403 or a 503 is not an answer
     and raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from controlarm.gates.priorart import CountBasis, PriorArtQuery
from controlarm.gates.sources.asof import AsOf
from controlarm.gates.sources.cassette import Fetcher, Recording, Request
from controlarm.gates.sources.subject import parse_subject

__all__ = ["MIN_INTERVAL_SECONDS", "NVD_CVE_URL", "NvdSource"]

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: Seconds between calls. NVD documents roughly five requests per rolling
#: thirty seconds without an API key; this leaves headroom on purpose.
MIN_INTERVAL_SECONDS = 7.0


@dataclass
class NvdSource:
    """A ``Source`` over NVD's CVE API 2.0. Identifier lookups only."""

    fetcher: Fetcher
    name: str = "nvd"
    as_of: AsOf = field(default_factory=AsOf)

    def search(self, subject: str) -> tuple[PriorArtQuery, ...]:
        parsed = parse_subject(subject)
        cves = [i for i in parsed.advisory_ids if i.upper().startswith("CVE-")]
        if not cves:
            # Failure mode 1. A GHSA or a bare package is not a question NVD
            # can be asked, so NVD does not answer it.
            return ()
        return tuple(self._by_cve(cve) for cve in cves)

    def _by_cve(self, cve: str) -> PriorArtQuery:
        url = f"{NVD_CVE_URL}?cveId={cve}"
        recording = self.fetcher.fetch(Request("http", url, "GET"))
        if recording.status == 404:
            return self._query(
                f"NVD cveId={cve} -> 404 not found; {self.as_of.label}", url, 0, recording
            )
        payload = recording.json()
        rows = []
        rejected = 0
        for entry in payload.get("vulnerabilities") or []:
            record = (entry or {}).get("cve") or {}
            if not record.get("id"):
                continue
            if str(record.get("vulnStatus", "")).lower() == "rejected":
                rejected += 1  # failure mode 2: counted, not subtracted
            rows.append({"id": record["id"], "published": record.get("published")})
        kept, tally = self.as_of.filter(rows)

        total = payload.get("totalResults")
        start = payload.get("startIndex") or 0
        per_page = payload.get("resultsPerPage") or 0
        truncated = isinstance(total, int) and total > start + per_page
        note = (
            f"; TRUNCATED: totalResults={total} exceeds startIndex+resultsPerPage="
            f"{start + per_page}, so this count is an estimate and invalidates the verdict"
            if truncated
            else ""
        )
        return self._query(
            f"NVD cveId={cve}; totalResults={total}; {self.as_of.label}; {tally.note()}; "
            f"rejected-and-counted={rejected}; ids={[r['id'] for r in kept]}{note}",
            url,
            len(kept),
            recording,
            CountBasis.ESTIMATED if truncated else CountBasis.MEASURED,
        )

    def _query(
        self,
        text: str,
        url: str,
        row_count: int,
        recording: Recording,
        basis: CountBasis = CountBasis.MEASURED,
    ) -> PriorArtQuery:
        return PriorArtQuery(
            query=f"{text} | rerun: {recording.request.rerun()}",
            source=self.name,
            retrieved=recording.recorded_at,
            row_count=row_count,
            url=url,
            basis=basis,
        )
