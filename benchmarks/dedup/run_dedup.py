"""Measure the prior-art gate's duplicate rate against the labelled set.

    python benchmarks/dedup/run_dedup.py              # replay recordings only
    python benchmarks/dedup/run_dedup.py --record     # refresh them from the network
    python benchmarks/dedup/run_dedup.py --check      # verify, offline, write nothing
    python benchmarks/dedup/run_dedup.py --no-nvd     # skip the slow corpus

Positive class is **duplicate**. The gate predicts positive when its verdict is
``CROWDED`` or ``SATURATED``, and negative when it is ``CLEAR``. ``UNGATED`` is
neither, and it is accounted for deliberately rather than dropped:

  * **Recall** -- the headline -- is ``TP / (all known duplicates)``. An
    ``UNGATED`` on a known duplicate counts as a miss. A dedup pass that did not
    happen did not catch anything, which is the same rule
    ``UNGATED``-is-not-``CLEAR`` applies everywhere else in this harness.
  * **Precision** is ``TP / (TP + FP)`` over the items where the gate actually
    asserted something. An ``UNGATED`` makes no claim, so it cannot be a false
    positive; it is counted and printed separately so the reader can see how
    much of the set the gate declined to answer about.

That asymmetry is the conservative direction for the headline number. It is
stated here, in the results file, and in ``docs/prior-art.md``.

The score is **always** taken from a replay, even on a recording run: a run that
scored its own recording pass would stamp every retrieval after the assessment
citing it, which the gate rightly refuses as a record assembled out of order.
So `--record` warms the cassettes and the measurement reads them back.

Because a replayed row count carries the timestamp of the *recording*, these
assessments age. Fresh recordings are admissible at promotion time; recordings
older than the freshness window are not, and the gate is right about that. The
benchmark scores the verdict, which staleness never changes -- ``validity()``
does not rewrite a verdict -- and reports the admissible count separately so
the distinction is visible rather than quietly ignored.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.dedup.interval import Rate, rate  # noqa: E402
from controlarm.gates.priorart import (  # noqa: E402
    DEFAULT_FRESHNESS,
    PriorArtVerdict,
    gate,
)
from controlarm.gates.sources import (  # noqa: E402
    AsOf,
    CassetteStore,
    Fetcher,
    FetchMode,
    GitHubAdvisorySource,
    NvdSource,
    OsvSource,
)
from controlarm.gates.sources.nvd import MIN_INTERVAL_SECONDS  # noqa: E402

CASSETTES = HERE / "cassettes"
MANIFEST = HERE / "manifest.json"
RESULTS = HERE / "results" / "dedup.md"
#: Kept beside the cassette directory rather than inside it, so that every
#: file under cassettes/ is a recording and nothing else.
INDEX = HERE / "cassettes.index.json"

FLAGGED = (PriorArtVerdict.CROWDED, PriorArtVerdict.SATURATED)


def build_sources(mode: FetchMode, cutoff: dt.datetime, use_nvd: bool) -> list:
    """One fetcher per corpus, because the polite interval differs per host."""
    as_of = AsOf(cutoff)
    store = CassetteStore(CASSETTES)
    sources = [
        OsvSource(Fetcher(store=store, mode=mode, min_interval=1.0), as_of=as_of),
        GitHubAdvisorySource(Fetcher(store=store, mode=mode, min_interval=1.0), as_of=as_of),
    ]
    if use_nvd:
        sources.append(
            NvdSource(
                Fetcher(store=store, mode=mode, min_interval=MIN_INTERVAL_SECONDS), as_of=as_of
            )
        )
    return sources


def classify(label: str, verdict: PriorArtVerdict) -> str:
    """One of tp, fn, fp, tn, ungated-positive, ungated-negative."""
    if verdict is PriorArtVerdict.UNGATED:
        return "ungated-positive" if label == "duplicate" else "ungated-negative"
    flagged = verdict in FLAGGED
    if label == "duplicate":
        return "tp" if flagged else "fn"
    return "fp" if flagged else "tn"


def score(outcomes: list[str]) -> dict[str, object]:
    counts = {k: outcomes.count(k) for k in ("tp", "fn", "fp", "tn")}
    counts["ungated-positive"] = outcomes.count("ungated-positive")
    counts["ungated-negative"] = outcomes.count("ungated-negative")
    positives = counts["tp"] + counts["fn"] + counts["ungated-positive"]
    asserted_positive = counts["tp"] + counts["fp"]
    negatives = counts["fp"] + counts["tn"] + counts["ungated-negative"]
    return {
        "counts": counts,
        "n": len(outcomes),
        "positives": positives,
        "negatives": negatives,
        "recall": rate(counts["tp"], positives),
        "precision": rate(counts["tp"], asserted_positive),
        "specificity": rate(counts["tn"], counts["fp"] + counts["tn"]),
    }


def fmt(value: Rate | None) -> str:
    return "not measured (no denominator)" if value is None else str(value)


def run(manifest: dict, sources: list, now: dt.datetime) -> list[dict]:
    rows: list[dict] = []
    for item in manifest["items"]:
        assessment = gate(item["subject"], sources, now=now)
        validity = assessment.validity(now, DEFAULT_FRESHNESS)
        rows.append(
            {
                "item": item,
                "verdict": assessment.verdict.value,
                "outcome": classify(item["label"], assessment.verdict),
                "row_total": assessment.row_total,
                "sources_answered": list(assessment.sources_answered),
                "failures": [list(f) for f in assessment.failures],
                "coverage_confidence": assessment.coverage_confidence,
                "admissible": validity.valid,
                "invalid_because": list(validity.reasons),
                "warnings": list(validity.warnings),
                "per_source": [
                    {"source": q.source, "rows": q.row_count, "basis": q.basis.value, "q": q.query}
                    for q in assessment.queries
                ],
            }
        )
    return rows


def report(
    manifest: dict,
    rows: list[dict],
    sources: list,
    recorded_calls: int,
    now: dt.datetime,
) -> str:
    overall = score([r["outcome"] for r in rows])
    families = {}
    for family in sorted({r["item"]["family"] for r in rows}):
        families[family] = score([r["outcome"] for r in rows if r["item"]["family"] == family])

    out: list[str] = []
    w = out.append
    w("# Dedup benchmark: measured duplicate rate")
    w("")
    w("Generated by `benchmarks/dedup/run_dedup.py`. Do not edit by hand.")
    w("")
    w(f"- scored at: `{now.isoformat()}`")
    w("- scored from: a **replay** of the committed recordings, always. A recording run")
    w("  warms the cassettes first and the score is then taken from them, so every")
    w("  retrieval timestamp precedes the assessment it belongs to.")
    w(f"- network calls made by this run: {recorded_calls}")
    w(f"- cutoff (as-of for every query): `{manifest['cutoff']}`")
    w(f"- labelled set: `benchmarks/dedup/manifest.json`, built `{manifest['built_at']}`")
    w("- selection rule: [`SELECTION_RULE.md`](../SELECTION_RULE.md), pre-registered")
    w(f"- sources asked: {', '.join(s.name for s in sources)}")
    w(
        f"- recordings replayed from: `benchmarks/dedup/cassettes/` "
        f"({CassetteStore(CASSETTES).count()} files)"
    )
    w("")
    w("## Headline")
    w("")
    w("Positive class is **duplicate**; the gate predicts positive on `CROWDED` or")
    w("`SATURATED`. `UNGATED` counts as a miss for recall and is excluded from")
    w("precision, because a dedup pass that did not happen caught nothing and claimed")
    w("nothing. n is stated and not padded.")
    w("")
    w(f"**Recall: {fmt(overall['recall'])}**")
    w("")
    w(f"Precision: {fmt(overall['precision'])}")
    w("")
    w(f"Specificity (known-novel items correctly left `CLEAR`): {fmt(overall['specificity'])}")
    w("")
    w("Intervals are 95% Clopper-Pearson, computed by `benchmarks/dedup/interval.py`")
    w("with no dependency on SciPy.")
    w("")
    w("## Counts")
    w("")
    w("| | n | TP | FN | FP | TN | UNGATED on a duplicate | UNGATED on a novel |")
    w("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, s in [("all items", overall), *families.items()]:
        c = s["counts"]
        w(
            f"| {name} | {s['n']} | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | "
            f"{c['ungated-positive']} | {c['ungated-negative']} |"
        )
    w("")
    w("## Per family")
    w("")
    for name, s in families.items():
        w(f"### {name}")
        w("")
        w(f"- recall: {fmt(s['recall'])}")
        w(f"- precision: {fmt(s['precision'])}")
        w(f"- specificity: {fmt(s['specificity'])}")
        w("")

    w("## Admissibility at promotion time")
    w("")
    admissible = sum(1 for r in rows if r["admissible"])
    w(f"{admissible} of {len(rows)} assessments were admissible at the time of this run")
    w(f"(freshness window {DEFAULT_FRESHNESS}).")
    if admissible < len(rows):
        w("")
        w("That is expected and correct in `replay` mode: a replayed row count carries the")
        w("timestamp of the recording, and the gate refuses evidence older than its")
        w("freshness window. The verdicts scored above are unaffected by staleness --")
        w("`validity()` never rewrites a verdict -- but none of these assessments would")
        w("clear a promotion, and the gate is right about that.")
        reasons: dict[str, int] = {}
        for row in rows:
            for reason in row["invalid_because"]:
                # Strip the timestamps and durations so the same rule does not
                # appear eighty times under eighty different headings.
                key = re.sub(r"\d[\d:.+\-T]*", "N", reason).split(".")[0][:120]
                reasons[key] = reasons.get(key, 0) + 1
        w("")
        w("Reasons given, by frequency:")
        w("")
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            w(f"- {count}x {reason}")
    w("")

    w("## Every known-novel item the gate flagged")
    w("")
    w("Listed individually because the selection rule's `novel` label is a date")
    w("comparison on GitHub's `publishedAt`, and an issue can be public in another")
    w("corpus before GitHub mirrors it. A reader can therefore separate a genuine")
    w("false alarm from a corpus that published earlier than the label's source did.")
    w("")
    flagged_negatives = [r for r in rows if r["outcome"] == "fp"]
    if not flagged_negatives:
        w("None.")
    else:
        for row in flagged_negatives:
            item = row["item"]
            w(
                f"- **{item['id']}** `{item['subject']}` -> {row['verdict']} "
                f"({row['row_total']} row(s)), GitHub publishedAt `{item['published_at']}`"
            )
            for per in row["per_source"]:
                if per["rows"]:
                    asked = per["q"].split(" | rerun")[0]
                    w(f"  - {per['source']}: {per['rows']} row(s) -- {asked}")
    w("")

    w("## Every known-duplicate item the gate missed")
    w("")
    missed = [r for r in rows if r["outcome"] in ("fn", "ungated-positive")]
    if not missed:
        w("None.")
    else:
        for row in missed:
            item = row["item"]
            w(
                f"- **{item['id']}** `{item['subject']}` -> {row['verdict']}, "
                f"sources answered: {row['sources_answered'] or 'none'}"
            )
            for name, why in row["failures"]:
                w(f"  - {name} did not answer: {why[:200]}")
    w("")

    w("## Threats to validity")
    w("")
    w("Carried over from the pre-registration, which states them in full:")
    w("")
    w("- The `novel` label is GitHub's publication date, not the world's. See the list")
    w("  above for every item where that mattered.")
    w("- The coordinate-level `duplicate` label takes the version from the advisory's")
    w("  own OSV record, so OSV agreeing is close to a self-consistency check. What it")
    w("  does test is the as-of filter, the pagination accounting, and whether the")
    w("  second source agrees.")
    w("- OSV ingests GitHub advisories, so the two sources are not independent about a")
    w("  GHSA that OSV has already imported. They are independent about ingestion lag,")
    w("  withdrawals, and ecosystems only one of them carries.")
    w("- The as-of filter uses each record's current content with its original date, so")
    w("  an advisory amended after the cutoff is counted as it reads today. That")
    w("  direction inflates `CROWDED`.")
    w("- n is small. The intervals say so.")
    w("")
    w("## What a CLEAR verdict here does not license")
    w("")
    w("Nothing in this file is evidence that any finding is novel. A `CLEAR` verdict")
    w("means these specific corpora, asked these specific questions, at this specific")
    w("time, returned no rows. The duplicate that dominates real triage -- a finding")
    w("already sitting in the vendor's own queue -- is invisible to every corpus here.")
    w("That is why `coverage_confidence` is capped at 0.6 and carries its disclaimer as")
    w("a field rather than as prose somebody can drop.")
    w("")
    return "\n".join(out)


def digest_index() -> dict:
    """sha256 and size of every committed recording.

    The recordings are the primary evidence for the published number, so the
    index is what makes tampering with one of them detectable without reading
    4MB of JSON. ``--check`` verifies it and re-derives the headline offline.
    """
    files = {}
    for path in sorted(CASSETTES.glob("*.json")):
        raw = path.read_bytes()
        files[path.name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    return {
        "note": (
            "sha256 of every recording under benchmarks/dedup/cassettes/. Written by "
            "run_dedup.py; verified by `run_dedup.py --check`."
        ),
        "count": len(files),
        "total_bytes": sum(f["bytes"] for f in files.values()),
        "files": files,
    }


def check_index() -> list[str]:
    """Differences between the committed index and the recordings on disk."""
    if not INDEX.exists():
        return [f"{INDEX.name} is missing, so the recordings cannot be verified"]
    committed = json.loads(INDEX.read_text(encoding="utf-8"))["files"]
    current = digest_index()["files"]
    problems = []
    for name in sorted(set(committed) | set(current)):
        if name not in current:
            problems.append(f"{name}: in the index but not on disk")
        elif name not in committed:
            problems.append(f"{name}: on disk but not in the index")
        elif committed[name]["sha256"] != current[name]["sha256"]:
            problems.append(f"{name}: sha256 differs from the committed index")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--record",
        action="store_true",
        help="warm the cassettes from the network first, then score from the replay",
    )
    parser.add_argument("--no-nvd", action="store_true", help="skip NVD (the slow corpus)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the recordings against INDEX.json and reproduce the published "
        "headline offline; write nothing and exit non-zero on any difference",
    )
    parser.add_argument("--json", type=pathlib.Path, help="also write the raw rows here")
    args = parser.parse_args(argv)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cutoff = dt.datetime.fromisoformat(manifest["cutoff"])
    use_nvd = not args.no_nvd

    # A recording run warms the cassettes and then scores from them. Scoring
    # the recording pass directly would stamp every retrieval *after* the
    # assessment that cites it, which the gate rightly calls an out-of-order
    # record -- so the measurement is always taken from a replay.
    recorded_calls = 0
    if args.record:
        warming = build_sources(FetchMode.RECORD, cutoff, use_nvd)
        run(manifest, warming, dt.datetime.now(dt.timezone.utc))
        recorded_calls = sum(s.fetcher.network_calls for s in warming)

    sources = build_sources(FetchMode.REPLAY, cutoff, use_nvd)
    now = dt.datetime.now(dt.timezone.utc)
    rows = run(manifest, sources, now)
    replay_calls = sum(s.fetcher.network_calls for s in sources)
    if replay_calls:  # pragma: no cover - the transport makes this impossible
        raise SystemExit(f"a replay made {replay_calls} network call(s), which it must not")
    overall = score([r["outcome"] for r in rows])

    if args.check:
        problems = check_index()
        published = RESULTS.read_text(encoding="utf-8") if RESULTS.exists() else ""
        headline = re.search(r"\*\*Recall: (.+?)\*\*", published)
        if headline is None:
            problems.append("the published results carry no headline recall")
        elif headline.group(1) != str(overall["recall"]):
            problems.append(
                f"the published recall {headline.group(1)!r} does not match a replay of the "
                f"recordings, which gives {str(overall['recall'])!r}"
            )
        for problem in problems:
            print(f"  MISMATCH {problem}")
        print(
            f"checked {CassetteStore(CASSETTES).count()} recording(s): "
            f"{'OK' if not problems else str(len(problems)) + ' problem(s)'}"
        )
        return 1 if problems else 0

    text = report(manifest, rows, sources, recorded_calls, now)
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" on every committed artefact. The index hashes cassette
    # bytes, so a file written with CRLF on Windows and normalised to LF by
    # git hashes differently on the next machine to check it.
    RESULTS.write_text(text + "\n", encoding="utf-8", newline="\n")
    INDEX.write_text(json.dumps(digest_index(), indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.json:
        args.json.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {RESULTS.relative_to(ROOT)}")
    print(f"  scored from       replay of {CassetteStore(CASSETTES).count()} recording(s)")
    print(f"  network calls     {recorded_calls}")
    print(f"  items             {overall['n']}")
    print(f"  recall (headline) {fmt(overall['recall'])}")
    print(f"  precision         {fmt(overall['precision'])}")
    print(f"  specificity       {fmt(overall['specificity'])}")
    print(f"  counts            {overall['counts']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
