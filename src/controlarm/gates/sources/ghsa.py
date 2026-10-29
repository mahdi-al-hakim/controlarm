"""The GitHub Advisory Database as a prior-art source, via the ``gh`` CLI.

Independence from OSV is the reason this exists. OSV *ingests* GitHub
advisories, so the two are not independent about a GHSA that OSV has already
imported -- but they disagree routinely about everything else: ingestion lag,
withdrawn advisories, ecosystems one tracks and the other does not, and
repository-scoped advisories that never acquire a package coordinate. A
disagreement between them is visible in the assessment because each source's
rows are recorded separately, which is the entire reason the gate asks more
than one.

Authentication: none of ours. The query runs through ``gh api graphql``, so the
credential stays in the user's ``gh`` configuration; this process never reads
it, never puts it on a command line, and the transport withholds ``gh``'s
stderr from the recording because an authentication failure names the account.

What it covers: advisories GitHub has reviewed or mirrored, by identifier
(``GHSA-`` or ``CVE-``) or by package.

What it does not cover, stated because a ``CLEAR`` from it is otherwise read as
novelty:

  * **Version ranges.** ``securityVulnerabilities`` returns one node per
    affected range and offers no version predicate, and parsing twelve
    ecosystems' version grammars to filter client side would put a silent
    wrongness inside a row count. So a package+version subject is answered at
    **package granularity**, the query text says so in those words, and the
    count over-states prior art for a specific version. The direction of that
    bias is toward CROWDED, never toward CLEAR.
  * Anything unpublished, and anything GitHub has not ingested.

Numbered failure modes:

  1  a GraphQL error read as zero rows  -> ``{"data": null, "errors": [...]}``
     has no nodes, and ``len(nodes)`` of a missing list is zero. An ``errors``
     key raises, and a raising source has not answered.
  2  a truncated connection counted as a total -> ``totalCount`` is the
     server's own number and the nodes are a page of it. The rows are counted,
     and an outstanding ``hasNextPage`` sets ``ESTIMATED``.
  3  one advisory counted once per affected range -> deduplicated by ``ghsaId``.
  4  a package name interpolated into a query -> a name containing a quote
     would change the query's meaning. Every string reaching the query goes
     through ``json.dumps``.
  5  a withdrawn advisory silently dropped -> GitHub withdraws advisories, and
     a withdrawn one is still evidence that somebody published this before you.
     It is counted, and the count of withdrawn rows is recorded separately so a
     reader can subtract it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from controlarm.gates.priorart import CountBasis, PriorArtQuery
from controlarm.gates.sources.asof import AsOf
from controlarm.gates.sources.cassette import Fetcher, Recording, Request, TransportError
from controlarm.gates.sources.subject import GITHUB_ECOSYSTEM_ENUM, Subject, parse_subject

__all__ = ["GITHUB_GRAPHQL_URL", "GitHubAdvisorySource"]

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

#: GraphQL pages to follow before reporting an estimate rather than a count.
MAX_PAGES = 5

#: Nodes per page. The maximum the GitHub GraphQL API allows.
PAGE_SIZE = 100


@dataclass
class GitHubAdvisorySource:
    """A ``Source`` over the GitHub Advisory Database."""

    fetcher: Fetcher
    name: str = "github-advisory-database"
    as_of: AsOf = field(default_factory=AsOf)
    max_pages: int = MAX_PAGES

    def search(self, subject: str) -> tuple[PriorArtQuery, ...]:
        parsed = parse_subject(subject)
        if not parsed.is_queryable:
            return ()
        records: list[PriorArtQuery] = []
        for advisory_id in parsed.advisory_ids:
            record = self._by_id(advisory_id)
            if record is not None:
                records.append(record)
        if parsed.package:
            record = self._by_package(parsed)
            if record is not None:
                records.append(record)
        return tuple(records)

    # ------------------------------------------------------------ by advisory

    def _by_id(self, advisory_id: str) -> PriorArtQuery | None:
        if advisory_id.upper().startswith("CVE-"):
            kind = "CVE"
        elif advisory_id.upper().startswith("GHSA-"):
            kind = "GHSA"
        else:
            return None  # an identifier namespace GitHub cannot be asked about
        # Concatenated rather than formatted: a GraphQL document is mostly
        # braces, and every interpolated string goes through json.dumps so a
        # package name containing a quote cannot change the query's meaning
        # (failure mode 4).
        graphql = (
            "query{securityAdvisories(first:"
            + str(PAGE_SIZE)
            + ", identifier:{type:"
            + kind
            + ", value:"
            + json.dumps(advisory_id)
            + "}){totalCount pageInfo{hasNextPage} "
            + "nodes{ghsaId publishedAt withdrawnAt}}}"
        )
        recording = self.fetcher.fetch(
            Request("gh-graphql", GITHUB_GRAPHQL_URL, "POST", {"query": graphql})
        )
        payload = _data(recording)
        connection = payload["securityAdvisories"]
        nodes = [n for n in (connection.get("nodes") or []) if isinstance(n, dict)]
        rows = [{"id": n.get("ghsaId"), "published": n.get("publishedAt"), **n} for n in nodes]
        kept, tally = self.as_of.filter(rows)
        withdrawn = sum(1 for n in kept if n.get("withdrawnAt"))
        truncated = _truncation(connection, len(nodes), 1, self.max_pages)
        return self._query(
            f"GitHub securityAdvisories identifier {kind}={advisory_id}; "
            f"totalCount={connection.get('totalCount')}; {self.as_of.label}; {tally.note()}; "
            f"withdrawn-and-counted={withdrawn}; ids={[n.get('ghsaId') for n in kept]}"
            f"{truncated}",
            len(kept),
            recording,
            CountBasis.ESTIMATED if truncated else CountBasis.MEASURED,
        )

    # ------------------------------------------------------------- by package

    def _by_package(self, parsed: Subject) -> PriorArtQuery | None:
        enum = GITHUB_ECOSYSTEM_ENUM.get(parsed.ecosystem or "")
        if enum is None:
            return None  # an ecosystem this corpus does not carry: declined
        seen: dict[str, dict] = {}
        cursor: str | None = None
        pages = 0
        last: Recording | None = None
        has_next = False
        total: object = None
        while pages < self.max_pages:
            after = f", after:{json.dumps(cursor)}" if cursor else ""
            graphql = (
                "query{securityVulnerabilities(first:"
                + str(PAGE_SIZE)
                + ", ecosystem:"
                + enum
                + ", package:"
                + json.dumps(parsed.package)
                + after
                + "){totalCount pageInfo{hasNextPage endCursor} "
                + "nodes{advisory{ghsaId publishedAt withdrawnAt}}}}"
            )
            last = self.fetcher.fetch(
                Request("gh-graphql", GITHUB_GRAPHQL_URL, "POST", {"query": graphql})
            )
            connection = _data(last)["securityVulnerabilities"]
            total = connection.get("totalCount")
            for node in connection.get("nodes") or []:
                advisory = (node or {}).get("advisory") or {}
                ghsa = advisory.get("ghsaId")
                if ghsa:
                    seen.setdefault(
                        str(ghsa),
                        {
                            "id": ghsa,
                            "published": advisory.get("publishedAt"),
                            "withdrawnAt": advisory.get("withdrawnAt"),
                        },
                    )
            pages += 1
            info = connection.get("pageInfo") or {}
            has_next = bool(info.get("hasNextPage"))
            cursor = info.get("endCursor") if has_next else None
            if not has_next:
                break

        if last is None:  # pragma: no cover - max_pages is validated positive
            raise TransportError("max_pages must be at least 1 for a package query to run")

        kept, tally = self.as_of.filter(list(seen.values()))
        withdrawn = sum(1 for n in kept if n.get("withdrawnAt"))
        truncated = (
            f"; TRUNCATED after {pages} page(s) with more pages outstanding, so this count is "
            "an estimate and invalidates the verdict"
            if has_next
            else ""
        )
        granularity = (
            f"PACKAGE GRANULARITY: version {parsed.version} was NOT matched by this source, so "
            "this row count is for the whole package and over-states prior art for that version"
            if parsed.version
            else "package-wide (no version given)"
        )
        return self._query(
            f"GitHub securityVulnerabilities ecosystem={enum} package={parsed.package}; "
            f"{granularity}; totalCount={total} (one node per affected range); "
            f"distinct-advisories={len(seen)}; {self.as_of.label}; {tally.note()}; "
            f"withdrawn-and-counted={withdrawn}; pages={pages}{truncated}",
            len(kept),
            last,
            CountBasis.ESTIMATED if has_next else CountBasis.MEASURED,
        )

    # --------------------------------------------------------------- plumbing

    def _query(
        self,
        text: str,
        row_count: int,
        recording: Recording,
        basis: CountBasis,
    ) -> PriorArtQuery:
        return PriorArtQuery(
            query=f"{text} | rerun: {recording.request.rerun()}",
            source=self.name,
            retrieved=recording.recorded_at,
            row_count=row_count,
            url=GITHUB_GRAPHQL_URL,
            basis=basis,
        )


def _data(recording: Recording) -> dict:
    """The ``data`` object, or raise. Failure mode 1."""
    payload = recording.json()
    if payload.get("errors"):
        raise TransportError(
            "the GitHub GraphQL API returned errors, which is not a row count of zero: "
            + json.dumps(payload["errors"])[:400]
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise TransportError("the GitHub GraphQL response carried no 'data' object")
    return data


def _truncation(connection: dict, seen: int, pages: int, max_pages: int) -> str:
    """Failure mode 2, for the single-page identifier lookup."""
    info = connection.get("pageInfo") or {}
    if not info.get("hasNextPage"):
        return ""
    return (
        f"; TRUNCATED at {seen} node(s) over {pages} of at most {max_pages} page(s) with more "
        "outstanding, so this count is an estimate and invalidates the verdict"
    )
