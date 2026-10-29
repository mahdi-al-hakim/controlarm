"""Generate the dedup benchmark's labelled set from the pinned selection rule.

Read ``SELECTION_RULE.md`` first. That file is the pre-registration; this file is
its mechanical execution and has no choices of its own in it.

    python benchmarks/dedup/build_manifest.py            # replay recordings
    python benchmarks/dedup/build_manifest.py --record   # go to the network

The manifest is committed. Re-running this script against a later corpus will
produce a different set -- advisories keep being published -- which is why the
committed one is the artefact and this script is only how it was made. Re-build
it only to extend the benchmark deliberately, never to improve a score.

Every response the build consumed is written to ``cassettes/`` beside the
measurement's own recordings, so the labels are auditable too: a reader can see
the exact GitHub response the ``publishedAt`` of every item was read from.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from controlarm.gates.sources import (  # noqa: E402 - path set above
    GITHUB_ECOSYSTEM_ENUM,
    CassetteStore,
    Fetcher,
    FetchMode,
    Request,
)
from controlarm.gates.sources.ghsa import GITHUB_GRAPHQL_URL, PAGE_SIZE  # noqa: E402
from controlarm.gates.sources.osv import OSV_VULN_URL  # noqa: E402

#: The pinned cutoff. Changing this invalidates the manifest and the results.
CUTOFF = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc)

#: ``publishedSince`` for the pre-cutoff pool. One month before the cutoff, so
#: the pool is adjacent to it rather than drawn from a different era of the
#: corpus's own conventions.
PRE_SINCE = dt.datetime(2025, 5, 1, tzinfo=dt.timezone.utc)

#: Advisories per pool. Deliberately equal, so the base rate is 50%.
PER_POOL = 20

#: Candidates to pull per pool before the admissibility conditions thin them.
POOL_SIZE = 100

CASSETTES = HERE / "cassettes"
MANIFEST = HERE / "manifest.json"

#: GitHub's ecosystem enum back to OSV's name, for forming a purl.
OSV_ECOSYSTEM = {enum: osv for osv, enum in GITHUB_ECOSYSTEM_ENUM.items()}

#: purl type for each OSV ecosystem name. Only the ones this harness can parse
#: back out again; an ecosystem absent here disqualifies the advisory.
PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "Maven": "maven",
    "crates.io": "cargo",
    "NuGet": "nuget",
    "Packagist": "composer",
    "RubyGems": "gem",
    "Hex": "hex",
    "Pub": "pub",
}


def pool_query(since: dt.datetime) -> str:
    """The pinned pool query, built by concatenation so the braces stay literal."""
    return (
        "query{securityAdvisories(first:"
        + str(POOL_SIZE)
        + ", orderBy:{field:PUBLISHED_AT, direction:ASC}, publishedSince:"
        + json.dumps(since.isoformat().replace("+00:00", "Z"))
        + ", classifications:GENERAL){totalCount nodes{ghsaId publishedAt withdrawnAt "
        + "identifiers{type value} vulnerabilities(first:"
        + str(PAGE_SIZE)
        + "){nodes{package{ecosystem name}}}}}}"
    )


def fetch_pool(fetcher: Fetcher, since: dt.datetime) -> tuple[list[dict], str]:
    graphql = pool_query(since)
    recording = fetcher.fetch(Request("gh-graphql", GITHUB_GRAPHQL_URL, "POST", {"query": graphql}))
    payload = recording.json()
    if payload.get("errors"):
        raise SystemExit("GitHub GraphQL returned errors: " + json.dumps(payload["errors"])[:400])
    nodes = payload["data"]["securityAdvisories"]["nodes"]
    return [n for n in nodes if isinstance(n, dict)], graphql


def osv_versions(fetcher: Fetcher, ghsa: str) -> list[dict]:
    """The OSV record's affected entries for a GHSA, or an empty list."""
    recording = fetcher.fetch(Request("http", OSV_VULN_URL + ghsa, "GET"))
    if recording.status == 404:
        return []
    return recording.json().get("affected") or []


def coordinate(affected: list[dict]) -> tuple[str, str, str] | None:
    """``(ecosystem, package, version)`` under the pinned version rule.

    The first affected package whose ecosystem is expressible, and the last
    version its OSV record enumerates. ``None`` when no entry qualifies, which
    is admissibility condition 3 and drops the advisory.
    """
    for entry in affected:
        package = entry.get("package") or {}
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        versions = entry.get("versions") or []
        # OSV suffixes some ecosystem names (``Alpine:v3.16``); the prefix is
        # the ecosystem and the suffix is a release, which does not change the
        # purl type.
        base = str(ecosystem or "").split(":")[0]
        if base in PURL_TYPE and name and versions:
            return base, str(name), str(versions[-1])
    return None


def build(fetcher: Fetcher) -> dict:
    dropped: list[dict] = []
    pools: dict[str, dict] = {}
    items: list[dict] = []

    for label, since, keep in (
        ("duplicate", PRE_SINCE, lambda stamp: stamp < CUTOFF),
        ("novel", CUTOFF, lambda stamp: stamp > CUTOFF),
    ):
        nodes, graphql = fetch_pool(fetcher, since)
        pools[label] = {"published_since": since.isoformat(), "graphql": graphql}
        taken = 0
        for node in nodes:
            if taken >= PER_POOL:
                break
            ghsa = node.get("ghsaId")
            published = node.get("publishedAt")
            if not ghsa or not published:
                dropped.append({"ghsa": ghsa, "reason": "no ghsaId or publishedAt"})
                continue
            stamp = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
            if not keep(stamp):
                continue  # on the wrong side of the cutoff for this pool
            if node.get("withdrawnAt"):
                dropped.append({"ghsa": ghsa, "reason": "withdrawn (condition 1)"})
                continue
            ecosystems = {
                (v.get("package") or {}).get("ecosystem")
                for v in (node.get("vulnerabilities") or {}).get("nodes") or []
            }
            if not ecosystems & set(OSV_ECOSYSTEM):
                dropped.append(
                    {"ghsa": ghsa, "reason": f"no expressible ecosystem in {sorted(ecosystems)}"}
                )
                continue
            coord = coordinate(osv_versions(fetcher, ghsa))
            if coord is None:
                dropped.append(
                    {"ghsa": ghsa, "reason": "OSV record enumerates no versions (condition 3)"}
                )
                continue
            ecosystem, package, version = coord
            cves = sorted(
                i["value"]
                for i in node.get("identifiers") or []
                if i.get("type") == "CVE" and i.get("value")
            )
            index = taken + 1
            common = {
                "label": label,
                "ghsa": ghsa,
                "published_at": published,
                "cves": cves,
                "ecosystem": ecosystem,
                "package": package,
                "version": version,
            }
            items.append(
                {
                    "id": f"{label[:3]}-id-{index:02d}",
                    "family": "identifier",
                    "subject": " ".join([ghsa, *cves]),
                    **common,
                }
            )
            items.append(
                {
                    "id": f"{label[:3]}-coord-{index:02d}",
                    "family": "coordinate",
                    "subject": f"pkg:{PURL_TYPE[ecosystem]}/{package}@{version}",
                    **common,
                }
            )
            taken += 1
        pools[label]["kept"] = taken

    return {
        "selection_rule": "benchmarks/dedup/SELECTION_RULE.md",
        "cutoff": CUTOFF.isoformat(),
        "built_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "per_pool_target": PER_POOL,
        "pools": pools,
        "dropped": dropped,
        "items": items,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--record",
        action="store_true",
        help="allow network requests and store them in cassettes/ (default: replay only)",
    )
    args = parser.parse_args(argv)

    fetcher = Fetcher(
        store=CassetteStore(CASSETTES),
        mode=FetchMode.RECORD if args.record else FetchMode.REPLAY,
    )
    manifest = build(fetcher)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    counts: dict[str, int] = {}
    for item in manifest["items"]:
        key = f"{item['label']}/{item['family']}"
        counts[key] = counts.get(key, 0) + 1
    print(f"wrote {MANIFEST.relative_to(ROOT)}")
    print(f"  cutoff            {manifest['cutoff']}")
    print(f"  network calls     {fetcher.network_calls}")
    print(f"  cassettes on disk {CassetteStore(CASSETTES).count()}")
    for key in sorted(counts):
        print(f"  {key:<24} {counts[key]}")
    print(f"  dropped           {len(manifest['dropped'])}")
    for drop in manifest["dropped"]:
        print(f"    {drop['ghsa']}: {drop['reason']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
