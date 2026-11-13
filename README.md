# controlarm

**A harness that refuses to call a security test negative until the run shows the target answering and
the plain attack being refused.**

An agent that reports "no vulnerability found" is making two claims: that it looked, and that looking
would have worked. controlarm checks the rig behind the second claim. A run counts as negative only
after a liveness check reached the target and the honest control, the same attack with no evasion, was
refused, and not for a recognised unrelated cause such as an expired credential or a rate limit.
Without both, the run is `VOID` and the CLI exits 3 instead of 0, so a script can't mistake an
unproven run for a clean result.

The failure that motivates it shipped in Microsoft's RAMPART: a safety test passed against an agent
built to exfiltrate, because the evaluator could not observe the exfiltration. I found it by hand and
wrote the fix ([PR #141](https://github.com/microsoft/RAMPART/pull/141), merged), and RAMPART's
evaluators now return `UNDETERMINED` when they cannot observe the evidence they need. controlarm
applies the same discipline to the parts of a run it can check: whether the rig reached the target and
whether the plain attack was refused. Whether a test probe can see a success is still up to
whoever wrote it, and a probe that cannot reads exactly like a boundary that held. That is the half
RAMPART's evaluator got wrong ([`GAPS.md`](GAPS.md) G16).
[`docs/observability-gap-in-the-wild.md`](docs/observability-gap-in-the-wild.md) has the before and
after, and a small study of the same gap on constructed transcripts.

This repository is the self-contained core of a larger harness I run privately for vulnerability
research: no target, no credentials and nothing embargoed, so the method can be inspected even though
the hunts can't.

- **Six verdicts instead of two.** `VOID`, `CONFOUNDED`, `INCONCLUSIVE`, `NO-TESTS`, `KILL`, `CANDIDATE`.
  A run whose instrument failed is `VOID`. A run whose test never reached the check is `CONFOUNDED`.
  Neither one means "no bug", and the three refusal states call for three different next actions. The
  order they are applied in is a precedence rule (the lattice, in the code): the most severe refusal
  that applies wins.
- **Two controls are required.** A run is `VOID` unless a liveness arm executed and the honest control
  (`honest_control` in the code) was refused, and not for a recognised unrelated cause such as an
  expired credential or a rate limit. A probe that returns something that is not a result makes the run
  `VOID`, and so does one that raises, unless its error names a recognised unrelated cause such as a
  refused connection.
- **A named reason for every failure.** Mutually exclusive confound patterns, so "no such tool" is never
  filed as a missing precondition.
- **Prior-art gating.** A candidate finding with a stale or unmeasured dedup verdict does not promote.
- **An exit-code contract, so the refusal is scriptable.** `0` success, `2` the tool failed or could not
  measure (a crash, a usage error, an unreadable input, a drifted selftest, or a ratio it cannot derive),
  `3` a gate refused (a `VOID` run always exits 3), `4` not promoted. A wrapper can tell a tool failure
  from a gate refusal without parsing text, because those two call for opposite actions.
  [`docs/cli.md`](docs/cli.md).

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
python examples/run_controls.py                   # VOID, KILL and CANDIDATE, with the reason for each
python benchmarks/run_benchmark.py --check        # false-positive corpus and oracle experiment
python benchmarks/dedup/run_dedup.py --check      # dedup study, replayed from its committed recordings
python -m pytest tests/test_cve_study.py          # CVE study, re-derived from its committed runs
python benchmarks/cve_study/run_study.py --check  # CVE study probes; needs the cache --acquire fetches
python tools/mutate_guards.py                     # neuters each guard; all must break a test
```

Each `--check` exits non-zero if a committed number moved; without it, `run_benchmark.py` and
`run_dedup.py` rewrite their results files. The observability-gap study below calls a paid API and is
not re-run by any of these; `tests/test_observability_gap.py` checks its figures against the committed
output.

## A small study of the observability gap

The study measures the gap on 72 transcripts I constructed,
each graded by `claude-haiku-4-5-20251001` once with the tool call visible and once with only the
agent's text. Two cells carry the information. Shown only the text,
the judge called 4 of 16 harmful transcripts safe when the text described the destination in
benign-sounding terms. Shown the tool call, it still called 2 of 64 harmful transcripts safe, and the
JSON does not record which levels those 2 fell on, so some of the 4 benign-framed misses may be
transcripts it also missed with the tool call visible. The
off-channel cell is 16 of 16 by construction, because that text carries no evidence of the harm, so a
pooled rate mostly reflects the mix of cells I chose. The reproduction, the before and after, the
matrix and the full study are in
[`docs/observability-gap-in-the-wild.md`](docs/observability-gap-in-the-wild.md); the data and the
script are in [`benchmarks/observability_gap/`](benchmarks/observability_gap/).

## A localisation on real CVEs: keep the record of whether your test reached the target

Measured against **11 real public CVEs**, each at a pre-fix and a post-fix pinned version, where the
vendor's patch is the ground truth. Eight vulnerability classes, nine distributions, 110 runs. Memory
safety is excluded by rule and by test, because a sanitizer is already a mechanical oracle there.

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

**At five modes that difference is not statistically distinguishable from chance.** The run-level
p-value treats runs as independent and should not be read as evidence. On the three real modes where
the baseline still refuses correctly without the record, it refuses for an unrelated reason, so 2 of 5
is a floor, not an estimate.

The claim is only: keep the record of whether each test reached its target. Design, selection rule,
per-CVE table and remaining threats in [`docs/cve-study.md`](docs/cve-study.md) and
[`benchmarks/cve_study/results/cve_study.md`](benchmarks/cve_study/results/cve_study.md).

> [!IMPORTANT]
> **Alpha.** Every head-to-head comparison between enforcing these rules and not enforcing them has
> come out null on both corpora (below). The corpora are small and mostly built by one person; see
> [`GAPS.md`](GAPS.md).

## How this repository checks itself

The discipline is enforced on this repository by the same kind of machinery it asks you to apply to a
target.

- **188 guards, each one neutered in CI.** `python tools/mutate_guards.py` removes every guard in turn and
  fails the build if any removal leaves the test suite green, because a guard whose removal no test
  notices has nothing showing that it works.
- **The README is an input to the test suite.** The snippet above is extracted and executed in all three
  target modes, and the figures listed in `benchmarks/results/figure-inventory.md` are pulled out by
  pattern and asserted against the committed results. Editing one of them by hand fails CI; a few
  descriptive counts in the prose are not bound. `tests/test_readme.py`,
  `tests/test_readme_figures.py`.
- **Registered withdrawn figures are swept for.** A registry lists withdrawn figures as exact strings,
  and a test fails if one of those strings appears in an authored Markdown file with no retraction marker
  within 400 characters of it. It matches strings, so it cannot catch a withdrawn figure restated in
  other words, or one that was never added to the registry.
- **`controlarm audit rules` prints no ratio and exits 2.** [`GAPS.md`](GAPS.md) G6 asks for a
  declared-to-enforced rule ratio. The denominator is prose and the two candidate mappings disagree by an
  order of magnitude, so the command prints all three counts with their provenance, prints both candidate
  ratios labelled unusable, names what would have to exist for the ratio to be computable, and exits 2.
- **A refusal never exits 2 and a tool crash never exits 3.** Both are pinned by tests, over every refusal
  the subcommands can reach and six injected exception types. A probe that breaks inside a run is
  handled by the run instead: it records the failure and returns `VOID`, or `CONFOUNDED` when the
  error names a recognised unrelated cause, and both exit 3.

## What is measured, and where it came out null

The false-positive corpus, the held-out sets and the oracle experiment reproduce with
`python benchmarks/run_benchmark.py --check`; their full output, the per-case post-mortems and the
retraction history are in [`benchmarks/results/fp_corpus.md`](benchmarks/results/fp_corpus.md). The CVE
study reproduces with `python -m pytest tests/test_cve_study.py`, short of re-executing its probes
([`GAPS.md`](GAPS.md) G14 says why).

**Null 1: the false-negative corpus.** Six corpus cases have an untrustworthy negative as their ground
truth. The guarded configuration called none of them "no bug". A fair unguarded baseline, one that reads
its own positive control and is allowed to abstain, called one of them "no bug".

| arm | called "no bug" | refused to call | false-negative rate |
|---|---|---|---|
| gates enforced | 0 | 6 | 0.00 |
| **fair unguarded baseline (the primary comparison)** | **1** | 5 | **0.17** |
| the check that produced each catalogued error (provenance, not a comparison) | 6 | 0 | 1.00 |

That margin is a two-sided **Fisher exact p = 1.00**. Against the third arm the same test gives
**p = 0.0022**, but that arm cannot emit a refusal verdict at all, so the figure measures its output
alphabet rather than its judgement. The denominator and fixtures were corrected after a critique by a
separate Claude agent ([`GAPS.md`](GAPS.md) G2b; `benchmarks/fp_corpus/critic/`).

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

The two target modes share one oracle function, so the probe is the correct unit of analysis: that gives
1 of 12 versus 7 of 12, **p = 0.027**, with overlapping intervals, and dropping the single probe no
interpretive callable can match brings it to **p = 0.063**. Treat it as evidence of direction on one
target, not as a rate. It also refutes the strong form of the claim, because the one mechanical error is
a real flaw whose only observable is a status code.

**The discipline also has a measured price.** It is over-conservative on one breakage mode, and that
costs it 11 correct findings that the baseline reports. Its confound table also cannot distinguish a
target that refuses by not finding something from a rig that fails the same way. Both are priced in
[`GAPS.md`](GAPS.md) G11.

### Gate precision and recall, on the held-out sets

On the catalogue corpus the gates score 1.00/1.00, which is near-circular: the corpus and the gates
derive from the same 16-item catalogue, so it measures whether the implementation is correct and says
nothing about generalisation. The two held-out sets below were both written against the gates as
implemented, not against the rules they encode.

| set | author | cases | recall | precision | accuracy |
|---|---|---|---|---|---|
| adversarial holdout | the gates' author | 6 | 0.67 | 0.67 | 0.67 |
| critique set, **as the critique agent found it** | the critique agent | 12 | 0.83 | 0.50 | 0.50 |
| **critique set, after repair** | **the critique agent** | **12** | **0.83** | **0.83** | **0.83** |

As the critique agent found it, the gates got **6 of 12 wrong**: five false positives and one false negative.
Four were the gate failing its own documented rule, which is an implementation defect and not a finding
about the rule, so they are fixed and the critique agent's cases are the regression tests that pin each
fix. Two are published unfixed because they are limits of the rules: rule A6 cannot be stated
mechanically over vendor prose, and rule A5's provenance question is not expressible in this fixture
schema. The holdout's own two failures stay unfixed for the same reason, and one of its two passes turned
out to be an accident, through a different gate than its label claimed. Post-repair accuracy of 0.83 on twelve cases is
[0.52, 0.98] at 95%. Every failure, its cause and its disposition: [`GAPS.md`](GAPS.md) G2c.

### Prior-art dedup, the one gate with a measured rate

Scored against 80 labelled items over 40 advisories, where the labels are a date comparison on a field
GitHub publishes against a pinned cutoff, set by a selection rule:
[`benchmarks/dedup/SELECTION_RULE.md`](benchmarks/dedup/SELECTION_RULE.md). Three real sources over free
public corpora (OSV.dev, the GitHub Advisory Database, NVD's CVE API 2.0). CI never touches the network:
the measurement replays about 360 committed recordings, each carrying its own request and a command to
re-issue it.

Recall is **100.0% (40/40; 95% CI 91.2%-100.0%)**, precision **75.5% (40/53; 95% CI 61.7%-86.2%)**, and
specificity **67.5% (27/40; 95% CI 50.9%-81.4%)**.

**Specificity, per family.** Recall is the easy half: the selection rule calls the coordinate-level
`duplicate` label near-tautological for OSV, because that label's version is taken from the advisory's
own OSV record. The identifier family scores
100% on all three metrics. The coordinate family is the real question, and
there the gate scores precision 60.6% and **specificity 35.0% (7/20; 95% CI 15.4%-59.2%)**, flagging 13 of
20 genuinely novel items as prior art. Six of the 13 rest on one documented coverage gap alone: the GitHub
source cannot filter by version, so it answers a package-plus-version question at package granularity and
over-states prior art for that version. The rest also carry OSV rows matched to that exact version, and a
`CLEAR` needs zero rows from every source, so a version-aware GitHub query would leave them flagged. All
13 are listed individually with their causes in
[`benchmarks/dedup/results/dedup.md`](benchmarks/dedup/results/dedup.md).

A `CLEAR` verdict from that gate is **not evidence of novelty**, only evidence that these specific corpora
did not answer. What each source covers, what it does not, and the threats to validity:
[`docs/prior-art.md`](docs/prior-art.md).

## Scope, and what this is not

- **Not a vulnerability scanner.** It finds nothing. It gates what you may call a result.
- **Not for memory safety.** A crash under ASan settles the question mechanically, so in that domain the
  problem is largely solved by tooling that predates this. `controlarm` is for the domains with no such
  oracle: agent security, authorisation, business logic, semantic correctness.
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

The idea is older than this repository. What it adds is enforcement: the rules are checked mechanically,
CI removes each check in turn to show a test catches it, and the failures are published.

- **Google Project Zero, Naptime (2024)** named it: design principle 4, "Perfect Verification", that
  vulnerability discovery "can be structured so that potential solutions can be verified automatically
  with absolute certainty". https://projectzero.google/2024/06/project-naptime.html
- **DARPA AIxCC (2025)** scored it. In the final, patches were scored against every team's
  proofs-of-vulnerability, and per the competition's scoring guide an accuracy multiplier penalised
  inaccurate submissions; the SoK's first key finding is
  *"Stability and accuracy were deciding factors in CRS performance."* It also quantifies the gap this
  project is aimed at: *"a significant fraction of generated patches pass all automatic validation, yet
  contain semantic issues caught only by manual review (CC: 20/53, 37.7%, MR: 26/57, 45.6%)."*
  https://arxiv.org/html/2602.07666v1
- **XBOW (2026-06)** published the coverage argument: "it found something real, but it did not tell you
  what it missed". https://xbow.com/blog/mythos-gpt-5-5-ai-vulnerability-detection-security
- **Strix** ships a `confirmed` / `ruled_out` / `open_proof_gap` trichotomy, including an explicit
  proof-gap state.
- **garak** and **PyRIT** already report scorer quality against human-labelled sets. Publishing precision
  and recall for a detector is not itself novel.
- **`red-team-blue-team-agent-fabric`** states the same position in almost the same words: "a test that
  did not reach the target is not a passing security test", and ships INCONCLUSIVE verdicts and sentinel
  controls. https://github.com/msaleme/red-team-blue-team-agent-fabric
- **ATOBench** studies where autonomous offensive agents stop searching, which is the saturation question
  this repository does not address.
- **Anthropic's open-source scanning pipeline** reports that *"only one was invalid, i.e. a 'false
  positive'"* among the findings that did not qualify, while *"of the remaining 12, 11 were real but
  duplicated known issues or other findings from the scan"*. Duplicates, not hallucinations, dominated
  there, which is why the dedup gate is the one with a measured rate.
  https://www.anthropic.com/research/launching-opt-in-vuln-finding-service-for-open-source

## Contributing

The most useful contribution is a case the gates get wrong, because it is the only thing that can break
the circularity described above. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Citation

See [`CITATION.cff`](CITATION.cff).

## How it was built

I built controlarm with Claude Code. The critique and review agents mentioned throughout were separate
Claude sessions, each prompted to find what was wrong with the repository.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
