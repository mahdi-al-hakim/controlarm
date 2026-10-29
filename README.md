# controlarm

**A harness that refuses to call a security test negative unless the rig was shown to work.**

An autonomous security agent that reports "no vulnerability found" is making two claims at once: that it
looked, and that looking would have worked. The second is almost never checked. `controlarm` checks it,
and when it cannot, it says so instead of reporting a clean result. If you have used a clinical trial's
control arm, this is that idea applied to adversarial testing. A control arm does not look for the effect.
It shows the instrument could have detected one.

- **Six verdicts instead of two.** `VOID`, `CONFOUNDED`, `INCONCLUSIVE`, `NO-TESTS`, `KILL`, `CANDIDATE`.
  A run whose instrument failed is `VOID`. A run whose test never reached the check is `CONFOUNDED`.
  Neither one means "no bug", and the three refusal states call for three different next actions. The
  order they are applied in is a precedence rule: the most severe refusal that applies wins. The code and
  the committed results call that rule the lattice.
- **A negative needs a positive.** A run is `VOID` unless a liveness arm executed and a positive control
  was refused *by the boundary itself*, and not by an expired credential or a rate limit. The code and the
  committed results label this arm `honest-control`; the term for it is positive control.
- **A named reason for every failure.** Mutually exclusive confound patterns, so "no such tool" is never
  filed as a missing precondition.
- **Prior-art gating.** A candidate finding with a stale or unmeasured dedup verdict does not promote.
- **An exit-code contract, so the refusal is scriptable.** `0` believe the verdict, `2` the rig broke,
  `3` a gate refused, `4` not promoted. A wrapper can tell "the instrument broke" from "the instrument
  refused" without parsing text, because those two call for opposite actions. [`docs/cli.md`](docs/cli.md).

## Install

Nothing outside the standard library is needed to use it. The `dev` extra adds `pytest` and `ruff` for the
tests and the benchmarks.

```bash
git clone https://github.com/mahdi-al-hakim/controlarm && cd controlarm
pip install -e ".[dev]"
pytest
```

> **`pytest` and `tools/mutate_guards.py` must never run at the same time.** The mutation tool edits a
> source file in place and restores it, and tests marked `pristine` assert properties of the unmutated
> tree. Running both concurrently produces failures that are not real **and, worse, passes that are not
> real**, because a mutation that was never applied looks exactly like a guard that is pinned. Run them
> sequentially. CI keeps them in separate jobs for this reason.

## Sixty seconds

This runs as pasted, against the deliberately flawed local target. No credentials, no network.

```python
import json
from controlarm import Run
from examples.local_target.app import ALLOWLIST, Target

target = Target(mode="flawed")


def ask(url):
    r = target.respond("POST", "/v1/fetch", body=json.dumps({"url": url}).encode())
    return r, r.body.get("final_host")


def reached_off_list(url):
    # The oracle is the host the fetcher actually reached, not the echoed URL.
    # The response echoes the submitted URL, so a substring check for the
    # off-list host would fire on the correctly-blocked requests too.
    r, host = ask(url)
    return (
        r.status == 200 and host is not None and host not in ALLOWLIST,
        f"{r.status} final_host={host!r}",
    )


def route_works(url):
    # Liveness asks a different question: does the route function at all.
    r, host = ask(url)
    return r.status == 200, f"{r.status} final_host={host!r}"


run = Run("the fetch allowlist cannot be reached past")
run.liveness(lambda: route_works("https://allowed.example/ok"))  # must work
run.honest_control(lambda: reached_off_list("https://listener.invalid/c"))  # must be refused
run.arm(
    "off-list host behind a backslash authority",
    lambda: reached_off_list(r"https://allowed.example\@listener.invalid/c"),
)

verdict, why = run.decide()
print(verdict.value, "-", why)
```

Prints `CANDIDATE`. Change `mode` to `"patched"` and it prints `KILL`; change it to `"unauthorized-all"`,
where every request returns 401, and it prints `VOID` instead of pretending the boundary held. That third
mode is why the library exists.

```bash
python examples/run_controls.py              # VOID, KILL and CANDIDATE, with the reason for each
python benchmarks/run_benchmark.py           # reproduces every number below
python benchmarks/run_benchmark.py --check   # exits non-zero if any number moved
python tools/mutate_guards.py                # neuters each guard; all must break a test
```

## The one finding: keep the record of whether your test reached the target

Measured against **11 real public CVEs**, each at a pre-fix and a post-fix pinned version, where the
vendor's patch is the ground truth and nothing in this repository gets a vote. Eight vulnerability
classes, nine distributions, 110 runs. Memory safety is excluded by rule and by test, because a sanitizer
is already a mechanical oracle there.

A competent baseline that reads its own positive control and is allowed to abstain refuses a broken rig
because it is handed one derived record: *did the treatment arm reach the target at all.* Deny it only
that record, change nothing else, and **2 of the 5 real rig-failure modes tested turn into "no bug"
instead of a refusal.**

The unit is the breakage mode, not the run. Seven of the eight modes produce exactly one outcome across
all eleven CVEs, so a run-level denominator counts the same deterministic result eleven times.

| set | unit | lattice wrong | fair baseline, reachability denied | two-sided Fisher |
|---|---|---|---|---|
| real breakage modes | **mode** | 0 of 5 | **2 of 5** | **p = 0.4444** |
| all breakage modes | mode | 0 of 8 | 4 of 8 | p = 0.0769 |
| real breakage modes | run (not independent) | 0 of 55 | 22 of 55 | p = 3.4e-08 |

**At five modes that difference is not statistically distinguishable from chance.** The mechanism is
visible; the rate is not measured. The run-level p-values are arithmetically correct and substantively
meaningless, and they are shown so the inflation stays visible.

Two qualifications, both in the unflattering direction. On the three real modes where the reachability
record is denied and the baseline still refuses correctly, it refuses for an unrelated reason that happens
to fire, which was not predicted: so 2 of 5 is a floor on how often the record matters. It is not an
estimate of it. And the record was handed to the baseline deliberately, because withholding it would have
flattered the gates by deleting data.

So the claim here is narrow. It is not "use this library", and it is not a rate. Keep that record. Design, selection rule, per-CVE table and remaining threats in
[`docs/cve-study.md`](docs/cve-study.md) and
[`benchmarks/cve_study/results/cve_study.md`](benchmarks/cve_study/results/cve_study.md).

> [!IMPORTANT]
> **Alpha, and the effect is not demonstrated.** The finding above is a localisation, not a win. Every
> head-to-head comparison between enforcing these rules and not enforcing them has come out null, on both
> corpora, and the one effect that does reach significance does not survive its own unit of analysis. All
> three are stated below. The corpora are small and most of them were built by one person, so read
> [`GAPS.md`](GAPS.md) before citing anything here.

## How the honesty is instrumented

The discipline is enforced on this repository by the same kind of machinery it asks you to apply to a
target. This is the part worth copying even if nothing else here is.

- **180 guards, each one neutered in CI.** `python tools/mutate_guards.py` removes every guard in turn and
  fails the build if any removal leaves the test suite green. A guard no test notices is not a control.
- **The README is an input to the test suite.** The snippet above is extracted and executed in all three
  target modes, and every figure quoted below is pulled out by pattern and asserted against the committed
  results JSON. A number edited by hand fails CI. `tests/test_readme.py`,
  `tests/test_readme_figures.py`.
- **A retracted number may be discussed, never re-asserted.** Every figure this project has withdrawn is
  in a registry, and a test fails if one reappears without its retraction nearby.
- **`controlarm audit rules` refuses to print a ratio and exits 2.** [`GAPS.md`](GAPS.md) G6 asks for a
  declared-to-enforced rule ratio. The denominator is prose and the two candidate mappings disagree by an
  order of magnitude, so the command prints all three counts with their provenance, prints both candidate
  ratios labelled unusable, names what would have to exist for the ratio to be computable, and exits 2.
  An instrument that cannot measure has not measured a low number.
- **A refusal never exits 2 and a crash never exits 3.** Both are pinned by tests, over every refusal the
  subcommands can reach and six injected exception types.

## What is measured, and where it came out null

Reproduce with `python benchmarks/run_benchmark.py`. Full output, the per-case post-mortems and the
retraction history are in [`benchmarks/results/fp_corpus.md`](benchmarks/results/fp_corpus.md).

**Null 1: the false-negative corpus.** Six corpus cases have an untrustworthy negative as their ground
truth. The guarded configuration called none of them "no bug". A fair unguarded baseline, one that reads
its own positive control and is allowed to abstain, called one of them "no bug".

| arm | called "no bug" | refused to call | false-negative rate |
|---|---|---|---|
| gates enforced | 0 | 6 | 0.00 |
| **fair unguarded baseline (the primary comparison)** | **1** | 5 | **0.17** |
| the check that produced each catalogued error (provenance, not a comparison) | 6 | 0 | 1.00 |

That margin is a two-sided **Fisher exact p = 1.00**: not distinguishable from no effect, and not close.
Against the third arm the same test gives **p = 0.0022**, but that arm cannot emit a refusal verdict at
all, so the figure measures its output alphabet rather than its judgement. It is kept for provenance and
is not a comparison. Both the denominator and the fixtures behind this table were corrected after an
external critique, and the margin got smaller: the full correction is [`GAPS.md`](GAPS.md) G2b, and the
critique, its runner and its fair baseline are in `benchmarks/fp_corpus/critic/`.

**Null 2: the CVE study, with the rig intact.** On the pre-fix set the gated configuration and the fair
baseline both score a false-negative rate of **0/11 = 0.00 [0.00, 0.28]**, two-sided Fisher **p = 1.00**.
On the post-fix set both score 0/11 false positives. On real seeded rig-breakage, both called "no bug" 0
times out of 55. With n = 11 and two distributions contributing two CVEs each, 0/11 cannot distinguish a
true rate of 0.00 from one of 0.25.

**Null 3, partial: the magnitude of the oracle effect.** 12 probes across 2 target modes, same precedence rule in
both arms, so the only variable is which grader read the response. The interpretive arm is an
LLM-as-judge; the mechanical arm reads a status code or a byte.

| oracle | probes | false verdicts | rate | 95% CI (Clopper-Pearson) |
|---|---|---|---|---|
| mechanical (strength 3-4) | 24 | 1 | 0.042 | [0.001, 0.211] |
| interpretive (strength 0-1) | 24 | 12 | 0.500 | [0.291, 0.709] |

The direction survives; the magnitude does not. The two target modes share one oracle function, so the
probe is the correct unit of analysis: that gives 1 of 12 versus 7 of 12, **p = 0.027**, with overlapping
intervals, and dropping the single probe no interpretive callable can match brings it to **p = 0.063**.
Treat it as evidence of direction on one target, not as a rate. It also refutes the strong form of the
claim, because the one mechanical error is a real flaw whose only observable is a status code.

**The discipline also has a measured price.** It is over-conservative on one breakage mode, and that
costs it 11 correct findings that the baseline reports. Its confound table also cannot distinguish a
target that refuses by not finding something from a rig that fails the same way. Both are priced in
[`GAPS.md`](GAPS.md) G11. Neither was tuned away.

### Gate precision and recall, on the held-out sets

On the catalogue corpus the gates score 1.00/1.00, and that number is **near-circular and should be
ignored**: the corpus and the gates derive from the same 16-item catalogue, so it measures whether the
implementation is correct. It says nothing about generalisation. The two held-out sets are the ones worth quoting, and both were
written against the gates as implemented, not against the rules they encode.

| set | author | cases | recall | precision | accuracy |
|---|---|---|---|---|---|
| adversarial holdout | the gates' author, after writing them | 6 | 0.67 | 0.67 | 0.67 |
| external critique set, **as the reviewer found it** | an independent reviewer | 12 | 0.83 | 0.50 | 0.50 |
| **external critique set, after repair** | **an independent reviewer** | **12** | **0.83** | **0.83** | **0.83** |

As the reviewer found it, the gates got **6 of 12 wrong**: five false positives and one false negative.
Four were the gate failing its own documented rule, which is an implementation defect and not a
finding about the rule, so they are fixed and the reviewer's cases are the regression tests that pin each
fix. Two are published unfixed because they are limits of the rules: rule A6 cannot be stated mechanically
over vendor prose, and rule A5's provenance question is not expressible in this fixture schema. The
holdout's own two failures stay unfixed for the same reason, and one of its two passes turned out to be an
accident, through a different gate than its label claimed. Post-repair accuracy of 0.83 on twelve cases is
[0.52, 0.98] at 95%. Every failure, its cause and its disposition: [`GAPS.md`](GAPS.md) G2c.

### Prior-art dedup, the one gate with a measured rate

Scored against 80 labelled items over 40 advisories, where the labels are a date comparison on a field
GitHub publishes against a pinned cutoff, pre-registered in
[`benchmarks/dedup/SELECTION_RULE.md`](benchmarks/dedup/SELECTION_RULE.md). Three real sources over free
public corpora (OSV.dev, the GitHub Advisory Database, NVD's CVE API 2.0). CI never touches the network:
the measurement replays about 360 committed recordings, each carrying its own request and a command to
re-issue it.

Recall is **100.0% (40/40; 95% CI 91.2%-100.0%)**, precision **75.5% (40/53; 95% CI 61.7%-86.2%)**, and
specificity **67.5% (27/40; 95% CI 50.9%-81.4%)**.

**Read the specificity first, and read it per family.** Recall is the flattering half, and the
pre-registered selection rule says so before the results: the identifier-family label is near-tautological
for OSV, and that family scores 100% on all three metrics. The coordinate family is the real question, and
there the gate scores precision 60.6% and **specificity 35.0% (7/20; 95% CI 15.4%-59.2%)**, flagging 13 of
20 genuinely novel items as prior art. Nearly all 13 come from one documented coverage gap: the GitHub
source cannot filter by version, so it answers a package-plus-version question at package granularity and
over-states prior art for that version. All 13 are listed individually with their causes in
[`benchmarks/dedup/results/dedup.md`](benchmarks/dedup/results/dedup.md).

A `CLEAR` verdict from that gate is **not evidence of novelty**, only evidence that these specific corpora
did not answer. What each source covers, what it does not, and the threats to validity:
[`docs/prior-art.md`](docs/prior-art.md).

## Scope, and what this is not

- **Not a vulnerability scanner.** It finds nothing. It gates what you may call a result.
- **Not for memory safety.** A crash under ASan is a verdict, not an interpretation, so in that domain the
  problem is largely solved by tooling that predates this. `controlarm` is for the domains with no such
  oracle: agent security, authorization, business logic, semantic correctness.
- **Not exploit confirmation.** That problem is well served already; see Prior art.
- **Not evidence that the method finds more bugs.** Nothing here measures yield. See [`GAPS.md`](GAPS.md).

## Responsible use

- **Scope is deny-by-default.** An empty allowlist denies everything, out-of-scope beats in-scope, and the
  scope file expires so a stale authorisation cannot silently keep granting access.
- **The payload guard is inverted.** Any URL handed to a remote fetcher must resolve, *in any encoding*,
  to infrastructure you have declared as your own. Dotted, decimal, hex, octal, zero-padded, IPv6 and
  IPv4-mapped forms are all decoded before the check, and private, loopback, link-local, reserved and
  multicast ranges are refused. It fails closed, and the error says what evidence to gather instead.
- **A blocked test is `BLOCKED`, never a negative.** Scope denial is not evidence about the target.
- **The example target binds to loopback only** and raises if asked to bind anywhere else.

Use it on systems you are authorised to test. The rails make accidents harder; they do not make
authorisation unnecessary.

## Prior art

This idea is not new, and the repo would be dishonest to imply otherwise. What this repository adds is
enforcement, not insight: the rules are mechanically checked, each check is proven load-bearing by
removing it in CI, and the failures are published.

- **Google Project Zero, Naptime (2024)** named it: design principle 4, "Perfect Verification", that
  vulnerability discovery "can be structured so that potential solutions can be verified automatically
  with absolute certainty". https://projectzero.google/2024/06/project-naptime.html
- **DARPA AIxCC (2025)** scored it. Proofs-of-Vulnerability were mandatory, and per the competition's
  scoring guide an accuracy multiplier penalised inaccurate submissions; the SoK's first key finding is
  *"Stability and accuracy were deciding factors in CRS performance."* It also quantifies the gap this
  project is aimed at: *"a significant fraction of generated patches pass all automatic validation, yet
  contain semantic issues caught only by manual review (CC: 20/53, 37.7%, MR: 26/57, 45.6%)."*
  https://arxiv.org/html/2602.07666v1
- **XBOW (2026-06)** published the coverage argument: "it found something real, but it did not tell you
  what it missed". https://xbow.com/blog/mythos-gpt-5-5-ai-vulnerability-detection-security
- **Strix** ships a `confirmed` / `ruled_out` / `open_proof_gap` trichotomy, including an explicit
  proof-gap state, at a scale this project will not reach.
- **garak** and **PyRIT** already report scorer quality against human-labelled sets. Publishing precision
  and recall for a detector is not itself novel, and this repository has merged code in PyRIT, so it would
  be a poor place to claim otherwise.
- **`red-team-blue-team-agent-fabric`** states the same position in almost the same words: "a test that
  did not reach the target is not a passing security test", and ships INCONCLUSIVE verdicts and sentinel
  controls. Which of us wrote it down first is not something either of us can demonstrate, so the claim
  here is only that the idea was not ours alone.
  https://github.com/msaleme/red-team-blue-team-agent-fabric
- **OpenSSF (2026-10-20)** published "separate finding from validating" as ecosystem guidance.
- **ATOBench** studies where autonomous offensive agents stop searching, which is the saturation question
  this repository does not address.
- **Anthropic's open-source scanning pipeline** reports that *"only one was invalid, i.e. a 'false
  positive'"* among the findings that did not qualify, while *"of the remaining 12, 11 were real but
  duplicated known issues"*. Duplicates, not hallucinations, are the dominant failure mode, which is why
  the dedup gate is the one with a measured rate.
  https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source

## Contributing

The most useful contribution is a case the gates get wrong, because it is the only thing that can break
the circularity described above. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Citation

See [`CITATION.cff`](CITATION.cff).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
