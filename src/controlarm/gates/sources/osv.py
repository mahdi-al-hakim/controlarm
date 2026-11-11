"""OSV.dev as a prior-art source.

OSV aggregates GitHub Security Advisories, PyPA, RustSec, Go, Debian, Alpine,
OSS-Fuzz and others into one schema, and its query endpoint matches *version
ranges* server side, which is the part no other free corpus here does. It takes
no key and no account.

What it covers: an advisory that somebody published about a package in one of
its supported ecosystems, or about a commit in a tracked repository.

What it does not cover, and what a ``CLEAR`` from it therefore cannot mean:

  * A finding with no package coordinate and no advisory identifier. OSV has no
    full-text endpoint in this implementation, so such a subject is **declined**
    rather than answered with a zero.
  * Anything not yet published. The dominant real duplicate -- a finding
    already sitting in a vendor's own triage queue -- is invisible to OSV by
    construction, which is why ``coverage_confidence`` is capped.
  * An advisory in an ecosystem OSV does not track.

Numbered failure modes:

  1  a 404 read as an error, or an error read as a 404 -> ``/v1/vulns/<id>``
     answers 404 for "no such advisory", which is a measured zero, and 5xx for
     "ask again later", which is not an answer at all. They are distinguished;
     anything that is neither raises, and a raising source has not answered.
  2  a truncated page counted as a total -> the query endpoint pages with
     ``next_page_token``. Stopping early and reporting the rows seen is an
     estimate of the total, not a measurement, so an unexhausted token sets
     ``CountBasis.ESTIMATED``, which invalidates the verdict.
  3  an unqueryable subject answered anyway -> see the module docstring: a
     prose subject is declined, because a zero from a question the corpus could
     not parse reads as CLEAR.
  4  the same advisory counted twice -> an advisory can arrive on two pages, or
     once per matching version range. Rows are deduplicated by OSV id before
     counting, so a row count is a count of distinct prior art.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from controlarm.gates.priorart import CountBasis, PriorArtQuery
from controlarm.gates.sources.asof import AsOf
from controlarm.gates.sources.cassette import Fetcher, Recording, Request, TransportError
from controlarm.gates.sources.subject import Subject, parse_subject

__all__ = ["OSV_QUERY_URL", "OSV_VULN_URL", "OsvSource"]

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

#: Pages to follow before giving up and reporting an estimate. Five pages is
#: well past any real package; a package that needs more is already SATURATED.
MAX_PAGES = 5


@dataclass
class OsvSource:
    """A ``Source`` over OSV.dev. Offline unless its fetcher says otherwise."""

    fetcher: Fetcher
    name: str = "osv.dev"
    as_of: AsOf = field(default_factory=AsOf)
    max_pages: int = MAX_PAGES

    def search(self, subject: str) -> tuple[PriorArtQuery, ...]:
        parsed = parse_subject(subject)
        if not parsed.is_queryable:
            # Failure mode 3. Declining is recorded by gate() as a non-answer.
            return ()
        records: list[PriorArtQuery] = []
        for advisory_id in parsed.advisory_ids:
            records.append(self._by_id(advisory_id))
        if parsed.package:
            records.append(self._by_package(parsed))
        return tuple(records)

    # ------------------------------------------------------------ by advisory

    def _by_id(self, advisory_id: str) -> PriorArtQuery:
        url = OSV_VULN_URL + advisory_id
        recording = self.fetcher.fetch(Request("http", url, "GET"))
        if recording.status == 404:
            # Failure mode 1: a measured zero, and the only status other than
            # 2xx that means anything here.
            return self._query(
                f"OSV advisory lookup {advisory_id} -> not found ({self.as_of.label})",
                url,
                0,
                recording,
            )
        body = recording.json()
        kept, tally = self.as_of.filter([body])
        return self._query(
            f"OSV advisory lookup {advisory_id} -> found; {self.as_of.label}; {tally.note()}; "
            f"ids={[v.get('id') for v in kept]}",
            url,
            len(kept),
            recording,
        )

    # ------------------------------------------------------------- by package

    def _by_package(self, parsed: Subject) -> PriorArtQuery:
        package: dict = {"name": parsed.package, "ecosystem": parsed.ecosystem}
        base: dict = {"package": package}
        if parsed.version:
            base["version"] = parsed.version

        seen: dict[str, dict] = {}
        token: str | None = None
        pages = 0
        last: Recording | None = None
        while pages < self.max_pages:
            body = dict(base)
            if token:
                body["page_token"] = token
            last = self.fetcher.fetch(Request("http", OSV_QUERY_URL, "POST", body))
            payload = last.json()
            for vuln in payload.get("vulns") or []:
                if isinstance(vuln, dict) and vuln.get("id"):
                    seen.setdefault(str(vuln["id"]), vuln)  # failure mode 4
            pages += 1
            token = payload.get("next_page_token") or None
            if not token:
                break

        if last is None:  # pragma: no cover - max_pages is validated positive
            raise TransportError("max_pages must be at least 1 for a package query to run")

        kept, tally = self.as_of.filter(list(seen.values()))
        # Failure mode 2: a page token still outstanding means the total was
        # not enumerated, so the count is the source's pagination, not the rows.
        basis = CountBasis.ESTIMATED if token else CountBasis.MEASURED
        truncated = (
            f"; TRUNCATED after {pages} page(s) with a page token outstanding, so this count is "
            "an estimate and invalidates the verdict"
            if token
            else ""
        )
        scope = "version-matched" if parsed.version else "package-wide (no version given)"
        return self._query(
            f"OSV query {parsed.ecosystem}/{parsed.package}"
            + (f"@{parsed.version}" if parsed.version else "")
            + f" [{scope}]; {self.as_of.label}; {tally.note()}; pages={pages}{truncated}",
            OSV_QUERY_URL,
            len(kept),
            last,
            basis,
        )

    # --------------------------------------------------------------- plumbing

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
