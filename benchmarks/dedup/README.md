# Dedup benchmark

Measures what the prior-art gate actually catches, against a labelled set whose
labels come from outside this repository.

Read in this order:

1. [`SELECTION_RULE.md`](SELECTION_RULE.md) -- the pre-registration. Written and
   committed before `manifest.json` was generated and before any gate ran
   against it. It also states what the rule cannot establish.
2. [`results/dedup.md`](results/dedup.md) -- the numbers, with Clopper-Pearson
   intervals, the n, every false positive listed individually, and the threats
   to validity.
3. [`../../docs/prior-art.md`](../../docs/prior-art.md) -- the sources, their
   coverage gaps, and what a `CLEAR` verdict does and does not license.

## Running it

```sh
python benchmarks/dedup/run_dedup.py            # replay the recordings, offline
python benchmarks/dedup/run_dedup.py --check    # verify digests, reproduce, write nothing
python benchmarks/dedup/run_dedup.py --record   # refresh from the network, then score
python benchmarks/dedup/run_dedup.py --no-nvd   # skip the slow corpus
```

The default is offline. `--check` is the reproduction path a reader wants: it
verifies every recording against `cassettes.index.json`, replays them, and
exits non-zero if the headline in `results/dedup.md` no longer matches what the
recordings give.

The score is **always** taken from a replay, even on a recording run. A run
that scored its own recording pass would stamp every retrieval after the
assessment citing it, and the gate rightly refuses a record assembled out of
order -- so `--record` warms the cassettes and the measurement reads them back.

To rebuild the labelled set itself (which changes it, and therefore changes the
published numbers):

```sh
python benchmarks/dedup/build_manifest.py --record
```

Do that only to extend the benchmark deliberately. Never to improve a score.

## What is committed, and why

| path | what it is |
| --- | --- |
| `SELECTION_RULE.md` | the pre-registration |
| `manifest.json` | the 80 labelled items, with each one's GitHub `publishedAt` frozen in |
| `cassettes/` | every API response the measurement consumed, request included |
| `cassettes.index.json` | sha256 and size of each recording |
| `results/dedup.md` | generated; do not edit by hand |
| `interval.py` | Clopper-Pearson, stdlib only |
| `run_dedup.py` | the measurement |
| `build_manifest.py` | how `manifest.json` was made |

Both are re-executed against the committed recordings on every CI run, not just
kept as provenance. `tests/test_priorart_benchmark.py` re-renders the whole of
`results/dedup.md` from a replay and diffs it, so every cell of the counts table
and every per-family rate has to reproduce rather than only the headline recall;
and it rebuilds `manifest.json` by running `build_manifest.py` in replay mode, so
the pre-registered selection rule's implementation is pinned to the labelled set
it is supposed to have produced. Both assert zero network calls.

The recordings are committed on purpose. They are about 5MB of JSON across some
360 files, they are this repository's own queries against free public APIs
rather than a vendored third-party corpus, and they are the primary evidence
for a number published about this repository. Without them the CI run would
have to reach the network, the published rate would be unreproducible, and a
reader would have to take the number on trust. Each file carries its own
request and a `rerun` command, so any one of them can be checked against the
live API.

No recording is hand-written. Every file carries `"provenance": "recorded"`,
and `tests/test_priorart_benchmark.py` fails if one does not. Fault-injection
fixtures -- a truncated page, a rejected CVE, a GraphQL error -- are built
inside the tests that need them and marked `synthetic`, which the transport
refuses to serve unless a test opts in explicitly.

## What the numbers mean

Positive class is **duplicate**. The gate predicts positive on `CROWDED` or
`SATURATED`, negative on `CLEAR`. `UNGATED` counts as a miss for recall and is
excluded from precision: a dedup pass that did not happen caught nothing and
claimed nothing.

Recall is the headline because the cost structure is asymmetric. A missed
duplicate is a report that wastes a maintainer's time and a reviewer's
credibility; a false `CROWDED` costs the finder one manual check against the
rows the gate printed.

The two families answer different questions and get very different answers:

- **identifier** -- a candidate cites a `GHSA-` or `CVE-`. This is the triage
  question, and it is the easy one.
- **coordinate** -- a candidate names a package and version. This is the one
  with a real error rate, and nearly all of it comes from the GitHub source
  matching at package rather than version granularity, which is documented in
  the query text of every row it returns.

## Honest limitations

All of them are in `SELECTION_RULE.md` and in the generated results. The short
version: n is 80, the `novel` label is GitHub's publication date rather than the
world's, OSV and GitHub are only partially independent because OSV ingests
GitHub, the as-of filter cannot undo an amendment made after the cutoff, and
none of this says anything about duplicates inside a vendor's private queue --
which is the population that actually dominates real triage.
