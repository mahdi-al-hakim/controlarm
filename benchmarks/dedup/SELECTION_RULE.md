# Selection rule for the dedup benchmark

This file is the pre-registration. It was written and committed **before**
`manifest.json` was generated and before any gate was run against it, for the
reason the rest of this repository exists: a corpus selected after seeing the
scores is not a measurement of anything.

Nothing in the labelled set may be removed, re-labelled or re-ordered after a
gate run. If the rule produces an item the gate gets wrong, the item stays and
the number moves.

## The pinned cutoff

```
C = 2025-06-01T00:00:00Z
```

Every query in the benchmark is asked **as of `C`**, meaning each corpus's rows
are filtered client side to those whose own `published` date is at or before
`C`. The sources do this; see `src/controlarm/gates/sources/asof.py`.

## Where the labels come from

Not from judgement. The label of every item is a **date comparison on a field
published by GitHub**, which is outside this repository and not under its
control:

| label | rule |
| --- | --- |
| `duplicate` | the GitHub advisory for this issue has `publishedAt < C` -- it was public prior art on the cutoff date |
| `novel` | the GitHub advisory for this issue has `publishedAt > C` -- it did not exist on the cutoff date |

`publishedAt` is read once, at manifest-build time, from the GitHub Advisory
Database, and frozen into `manifest.json` beside the item.

## How the advisories are drawn

Two pools, each from one pinned GraphQL query, taken **in the order the API
returns them**. No hand-picking, no skipping for taste.

Pre-cutoff pool (`duplicate`):

```graphql
securityAdvisories(
  first: 100,
  orderBy: {field: PUBLISHED_AT, direction: ASC},
  publishedSince: "2025-05-01T00:00:00Z",
  classifications: GENERAL
)
```

Post-cutoff pool (`novel`):

```graphql
securityAdvisories(
  first: 100,
  orderBy: {field: PUBLISHED_AT, direction: ASC},
  publishedSince: "2025-06-01T00:00:00Z",
  classifications: GENERAL
)
```

From the pre-cutoff pool keep advisories with `publishedAt < C`; from the
post-cutoff pool keep advisories with `publishedAt > C`. Then, walking each
pool in order, keep an advisory only if **all** of the following hold -- these
are mechanical admissibility conditions, applied before any gate runs:

1. It is not withdrawn (`withdrawnAt` is null). A withdrawn advisory's
   publication date no longer describes a standing claim.
2. It carries at least one package in an ecosystem this harness can express
   (see `ECOSYSTEMS` in `src/controlarm/gates/sources/subject.py`).
3. Its OSV record enumerates at least one concrete affected version, so a
   coordinate subject can be formed without guessing a version string.

Take the first **20** qualifying advisories from each pool. Advisories dropped
by conditions 1 to 3 are counted in `manifest.json` under `dropped`, with the
reason, so the attrition is visible rather than quiet.

## The two measurements, and the two subjects per advisory

Each selected advisory yields two benchmark items, because the gate is asked two
genuinely different questions and gets different answers to them:

**Identifier level.** Subject is the advisory's own identifiers, e.g.
`GHSA-jqq5-wc57-f8hj CVE-2025-46724`. This is the triage question: a candidate
finding cites an identifier, is it already published? A `duplicate` item should
come back `CROWDED`/`SATURATED`; a `novel` item should come back `CLEAR`.

**Coordinate level.** Subject is a Package URL with a concrete affected version,
e.g. `pkg:pypi/langroid@0.53.14`, taken as `affected[].versions[-1]` from the
OSV record -- the highest version the advisory itself names as vulnerable. This
is the harder question and the one with a real error rate: a genuinely new
finding in a package that already has advisories *will* come back `CROWDED`,
and that false positive is the honest cost of using a crowding verdict as a
dedup signal.

## The version rule

`affected[].versions[-1]` of the first affected package whose ecosystem is
expressible -- the last entry of the list OSV enumerates. Chosen because it is
deterministic and is a version the advisory names as affected. Advisories whose
OSV record enumerates no versions (common for Maven and Go, where ranges are
given without an enumeration) are dropped by condition 3 rather than having a
version invented for them.

## What this rule cannot establish

Stated here and not only in the results, because a pre-registration that omits
its own weaknesses is not one:

- **The `novel` label is about GitHub's publication date, not about the world.**
  An issue can be public as a CVE in NVD before GitHub mirrors it. Such an item
  is labelled `novel` by this rule and may legitimately come back `CROWDED`.
  Every negative item that comes back `CROWDED` is listed individually in the
  results with its cause, so a reader can separate a genuine false alarm from a
  corpus publishing earlier than GitHub did.
- **The coordinate-level `duplicate` label is near-tautological for OSV.** The
  version was taken from the advisory's own OSV record, so OSV matching it is
  close to a self-consistency check. What it does test is the as-of filter, the
  pagination accounting, and whether the second source agrees.
- **No corpus can be asked what it did not know.** The as-of filter uses each
  record's current content with its original date, so a pre-cutoff advisory
  whose affected ranges were widened after `C` is counted as it reads today.
  That direction inflates `CROWDED`.
- **n is small.** Forty advisories, eighty items. The Clopper-Pearson intervals
  in the results are wide and are reported rather than rounded away.
