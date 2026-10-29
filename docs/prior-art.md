# The prior-art gate

A candidate finding is not a result until somebody has asked whether it is
already known, and the asking has to be auditable or it is just a feeling.
This document is what the asking consists of here: which corpora are asked,
what each one covers, what it does not, how the freshness window and
`coverage_confidence` are computed, and what the resulting verdict does and
does not license.

**The one sentence to take away.** A `CLEAR` verdict from this gate is **not
evidence of novelty**. It is evidence that these specific corpora, asked these
specific questions, at a specific time, returned no rows. The duplicate that
dominates real triage is a finding already sitting in a vendor's own queue, and
no public corpus can see that at all.

That is not a disclaimer bolted on afterwards. It is why `coverage_confidence`
is capped at 0.6 and carries `COVERAGE_NOTE` as a field rather than as prose
somebody can drop, and why the gate emits a *crowding* verdict with four values
rather than a novelty flag with two.

## Why this gate exists at all

Duplicates, not hallucinations, are the dominant failure mode of automated
vulnerability finding:

- On its own open-source scanning pipeline Anthropic reports being
  *"bottlenecked on our human capacity to validate these findings"*, and that
  of the findings which did not qualify, *"only one was invalid, i.e. a 'false
  positive'"* while *"of the remaining 12, 11 were real but duplicated known
  issues or other findings from the scan"*.
- DARPA AIxCC counted duplicates as neutral rather than penalised, so roughly
  2,519 proof-of-vulnerability submissions collapsed to about 241 counted, and
  nobody had any reason to optimise for dedup.
- XBOW's top HackerOne run produced roughly 1,060 reports in 90 days: 130
  resolved and 208 duplicates, with human review before submission.

## The four verdicts

| verdict | meaning | promotes? |
| --- | --- | --- |
| `CLEAR` | at least one source answered, and the total row count was zero | yes, if admissible |
| `CROWDED` | public prior art exists, below the saturation threshold | no |
| `SATURATED` | enough public prior art that the region is not worth the budget | no |
| `UNGATED` | **no source answered** | no |

`UNGATED` is the load-bearing one. "No source answered" and "no prior art
found" are the same row count and opposite claims, so they are different
verdicts: `is_clear` is false for `UNGATED`, `clears_promotion` is false, and
`assert_gated` refuses it. A network failure, a rate limit, a GraphQL error, an
unparseable body and a missing recording all produce `UNGATED`. This is the
same rule the rest of the harness applies to a dead rig producing `VOID`.

## The sources

Three are implemented. Two are in the default set; the offline `StaticSource`
remains the default for tests, examples and the quickstart, and
`controlarm.gates.priorart` never imports the network package at all. The
sources are declared behind the `[dedup]` extra (see `pyproject.toml`), which
installs nothing because they are stdlib-only; the extra names the boundary.

### OSV.dev (`osv.dev`)

Free, no key, no account. `POST /v1/query` and `GET /v1/vulns/<id>`.

**Covers.** Advisories about a package in a tracked ecosystem, by package
coordinate or by advisory identifier. It is the only corpus here that matches
**version ranges server side**, so `pkg:pypi/django@3.2.0` is answered about
that version rather than about Django in general. It aggregates GitHub
advisories, PyPA, RustSec, the Go vulnerability database, Debian, Alpine and
others.

**Does not cover.** A finding with no package coordinate and no advisory
identifier: there is no full-text endpoint in this implementation, so such a
subject is **declined** rather than answered with a zero. Ecosystems OSV does
not track. Anything unpublished.

### GitHub Advisory Database (`github-advisory-database`)

Queried through `gh api graphql`, so the credential stays in the reader's own
`gh` configuration. This process never reads a token, never puts one on a
command line and never writes one anywhere, and the transport withholds `gh`'s
stderr from the recording because an authentication failure names the account.

**Covers.** Advisories GitHub has reviewed or mirrored, by `GHSA-` or `CVE-`
identifier, or by package.

**Does not cover.** **Version ranges.** `securityVulnerabilities` returns one
node per affected range and offers no version predicate, and parsing twelve
ecosystems' version grammars client side would put a silent wrongness inside a
row count. So a package+version subject is answered at **package
granularity**, the query text says so in those words, and the count
over-states prior art for one specific version. The direction of that bias is
toward `CROWDED`, never toward `CLEAR`. This single limitation accounts for
most of the measured false positives below.

**Independence from OSV.** Partial, and stated plainly: OSV ingests GitHub
advisories, so about a GHSA that OSV has already imported the two agree by
construction. They are genuinely independent about ingestion lag, withdrawn
advisories, ecosystems only one of them carries, and version granularity. Each
source's rows are recorded separately in the assessment, so a disagreement is
visible rather than averaged away.

### NVD CVE API 2.0 (`nvd`)

Free, rate-limited, works without a key at a lower rate. Not in the default
set: without a key NVD permits roughly five requests per rolling thirty
seconds, so `MIN_INTERVAL_SECONDS` is 7.0 and a run pays the wall-clock cost.

**Covers.** Published CVE records, by identifier. It is the corpus that sees a
CVE against a router's firmware, a desktop application or a protocol, which
has no package coordinate and about which both package databases answer zero.
Two zeros from two package databases look like corroboration while being the
same blind spot twice.

**Does not cover.** Any identifier that is not a CVE: a `GHSA-` with no CVE
assigned is invisible, and this source declines rather than answering zero.
Package coordinates: NVD matches products through CPE names, a package name is
not a CPE name, and guessing one would put a fabricated identifier into a row
count.

## Count basis: measured or estimated

Every `PriorArtQuery` records whether its row count was **measured** (the rows
were enumerated and counted) or **estimated** (the number is the source's own
approximation). An estimated count anywhere in an assessment makes the verdict
inadmissible, because a reader cannot re-derive it.

In practice an estimate arises from pagination: OSV leaves a
`next_page_token`, a GitHub connection reports `hasNextPage`, or NVD's
`totalResults` exceeds `startIndex + resultsPerPage`. Each source follows at
most five pages and then stops; if anything is still outstanding the count is
marked `ESTIMATED` and the query text says `TRUNCATED` in capitals.

## The freshness window, and why 24 hours

`DEFAULT_FRESHNESS` is 24 hours. Short enough that a fix landing mid-flight is
caught -- the specific failure is a finding that was novel when searched and a
duplicate when submitted -- and long enough that a dedup pass survives a
night's sleep.

Two things are aged, not one: the assessment's own `assessed_at`, and **every
individual query's** `retrieved` timestamp. Re-stamping an assessment is not
re-running it, so a fresh assessment built from day-old queries is
inadmissible. A query marked as retrieved *after* the assessment that cites it
is also refused: that record was assembled out of order.

Staleness never rewrites a verdict. A stale `CROWDED` is still `CROWDED`; it is
just not usable as a gate. Rewriting it would destroy the record.

**A replayed recording carries the time the corpus was asked, not the time it
was replayed.** That is deliberate, and it means replayed evidence ages exactly
as live evidence does. The dedup benchmark therefore scores verdicts and
reports admissibility separately rather than quietly scoring around it.

## How `coverage_confidence` is computed

```
answered = len(sources_answered) / len(sources_asked)
coverage_confidence = min(0.6, answered * 0.6)
```

So two of three sources answering gives 0.4, and three of three gives the cap
of 0.6. It can never reach 1.0.

**What the number measures:** how many of the sources asked actually answered.

**What it does not measure:** crowd coverage. It measures **public activity,
not crowd coverage**, and a quiet corpus is not an empty field. It cannot see a
vendor's internal review, which is where duplicates predominantly come from,
so the measurable part of coverage is a minority of the thing being estimated.
The cap is deliberately not 0.9 and certainly not 1.0 for that reason, and
`coverage_note` ships the disclaimer as a field so the number cannot travel
without it.

A verdict resting on a single answering source carries a warning: never treat a
single-source zero as a zero. Indexes disagree, and a repository-level advisory
is invisible to a package-level database.

## Record and replay

Every request goes through `cassette.py` and every response is written to disk
as a file containing both the request and the response, plus a `rerun` command
a reader can paste. Three consequences:

- CI never touches the network. The default mode is `REPLAY`.
- The published duplicate rate is auditable: the recordings are the primary
  evidence, and `benchmarks/dedup/cassettes.index.json` carries a sha256 of
  each one. `python benchmarks/dedup/run_dedup.py --check` verifies the digests
  and re-derives the headline offline, writing nothing and exiting non-zero on
  any difference.
- **A cassette miss raises.** It is never an empty result. "I have no recording
  of that question" and "the corpus answered zero" are the same row count and
  opposite claims, so a miss makes the source raise, which makes the verdict
  `UNGATED`. An empty cassette directory scores zero, not `CLEAR`.

Recordings carry a `provenance` field. Only `recorded` is admissible; a
`synthetic` one -- a fault-injection fixture, such as a truncated page or a
rejected CVE -- is refused unless a test opts in explicitly, so a hand-written
body cannot become a published number. No committed recording is synthetic,
and a test asserts that.

Politeness and secrets: calls are spaced per host (1s for OSV and GitHub, 7s
for NVD), non-2xx responses are never parsed into rows, only `https` with a
named host is fetched -- no plain HTTP, no IP literal, no credential in a URL
-- and every body and URL is scrubbed for token-shaped strings and for the
authenticated account's identity before it is written.

## The measured duplicate rate

Published in [`benchmarks/dedup/results/dedup.md`](../benchmarks/dedup/results/dedup.md),
from the pre-registered selection rule in
[`benchmarks/dedup/SELECTION_RULE.md`](../benchmarks/dedup/SELECTION_RULE.md).
Read the selection rule before the numbers.

Positive class is **duplicate**; the gate predicts positive on `CROWDED` or
`SATURATED`. `UNGATED` counts as a **miss for recall** (a dedup pass that did
not happen caught nothing) and is **excluded from precision** (it claimed
nothing, so it cannot have claimed wrongly). That asymmetry is the
conservative direction for the headline metric and it is stated everywhere the
numbers appear.

Labels come from outside this repository: a date comparison on GitHub's
`publishedAt` against a pinned cutoff of 2025-06-01, with every query asked
**as of** that cutoff. Novelty is therefore established by chronology, not by
anyone's judgement.

n is 80 items over 40 advisories, 20 per label per family. That is small, the
Clopper-Pearson intervals say so, and it has not been padded.

## Threats to validity

- The `novel` label is GitHub's publication date, not the world's. An issue can
  be public as a CVE in NVD before GitHub mirrors it. Every negative item that
  came back `CROWDED` is listed individually in the results with its cause, so
  a reader can separate a genuine false alarm from a corpus that published
  earlier than the label's source did.
- The coordinate-level `duplicate` label takes the version from the advisory's
  own OSV record, so OSV agreeing with it is close to a self-consistency check.
  What that family does test is the as-of filter, the pagination accounting,
  and whether the second source agrees.
- OSV and the GitHub Advisory Database are only partially independent. See
  above.
- The as-of filter is applied client side on each record's own `published`
  date, because no corpus here offers an as-of parameter. A record published
  before the cutoff but amended afterwards is counted as it reads today, not as
  it read then. That direction inflates `CROWDED`. A record with no publication
  date cannot be placed in time at all; it is counted rather than dropped,
  which is the conservative direction, and the query text reports how many
  such rows there were.
- The GitHub source's package granularity over-states prior art for a specific
  version, and that accounts for most of the measured false positives. It is
  not hidden in a footnote: the words `PACKAGE GRANULARITY` are in the query
  text of every row it produces for a versioned subject.
- The benchmark measures these corpora on these questions. It says nothing
  about duplicates inside a vendor's private queue, which is the population
  that actually dominates. Nothing here can.
- n is small.

## What to do with each verdict

- `CLEAR` and admissible: proceed, and write down that the dedup pass covered
  public corpora only. Do not write down that the finding is novel.
- `CROWDED`: submit only with a stated, specific difference from each row.
- `SATURATED`: spend the budget on a region with less public activity.
- `UNGATED`: you have not run a dedup pass. Run one.

## Every guard here is proven load-bearing

`tools/mutate_guards.py` removes each guard in this module and its sources one
at a time and runs the suite. A guard whose removal leaves the suite green is
reported as unpinned, because a control nobody notices the absence of is not a
control. The targets are `priorart`, `pa_cassette`, `pa_subject`, `pa_asof`,
`pa_osv`, `pa_ghsa`, `pa_nvd`, `dedup_interval` and `dedup_run`.

Never run `pytest` at the same time as `tools/mutate_guards.py`: tests marked
`pristine` assert properties of the unmutated source tree.
