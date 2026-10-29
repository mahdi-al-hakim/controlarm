# What is not known about this project

A harness whose thesis is "do not report what you have not shown" has to publish its own unknowns, or it
refutes itself. This file is that list. Read it before quoting any number out of the README.

Every gap below names the measurement that would close it. A limitation with no route to being resolved
is just an excuse.

---

## G2b. The central comparison was not a measurement, and correcting it left no effect

Added after an external critique, which is also why it is numbered out of order: the original C1 claim
reported a 0.64 false-negative rate for the unguarded configuration over 11 cases. Three things were
wrong, and all three have been corrected. **The claim is weaker after the corrections than before them.**

**The comparison arm was structurally unable to win.** `benchmarks/gates.py` `_naive` can emit only
`CANDIDATE` or `no-bug`, while the correct class for those cases includes the refusal verdicts. Its score
on them was fixed **before any fixture was read**. That is not a measurement of anything. *Corrected:*
there are now three arms. The primary comparison is `gates._fair`, which reads its own positive control,
reads the number it is reporting, may abstain, and can emit every one of the three predicted classes. The
historical check is kept as a clearly-labelled third arm, because it is the real provenance of every case
in the corpus, and its predicates are frozen and pinned by a test for that reason -- a history that gets
edited to look better is no longer evidence of anything.

**The denominator was wrong.** Only 7 of the 11 cases are negatives; the other four make non-negative
claims -- a finding, an over-broad finding, and two claims about a metric. *Corrected:* every fixture now
declares `asserts_absence` and the headline uses only cases that declare it, with a test that the
declaration cannot contradict the fixture's own claim.

**Two cases handed the gate its conclusion, and they were the entire margin.** For 6 of the 11 the fixture
wrote the rule's antecedent down as a literal, and the only two cases where the gates beat a fair baseline
were both from that set. *Corrected:* five of the six are re-expressed so the gate must derive what it
used to read -- `void08` from the probe's own transport record and the run's time window, `void09` from the
recorded egress allowlist against each arm's target host, `ext17` from the detector's recorded invocation,
`scope13` from two separately sourced records, `self15` from a factor model the gate computes the bound
from. The sixth, `hard19`, **cannot** be re-expressed: the set of code paths a target reaches is the whole
difficulty and no fixture can make a gate discover it, so it is marked `conclusion_in_fixture` and
excluded from the headline while still being scored and published.

**The resulting number.** On the corrected denominator of 6 cases: gated 0 of 6, fair baseline 1 of 6,
**Fisher p = 1.00.** The pre-correction figures were 2 of 7 versus 0 of 7, p = 0.46. So the effect this
repository was built to demonstrate is **not distinguishable from no effect at all** against a competent
engineer without the library, on this corpus. The one case the fair baseline still misses (`void09`) is
one the gates now win by deriving shared containment from a recorded allowlist, where before they
compared two labels. That makes the single remaining data point earned. One data point is not a result.

*To close it:* nothing in this repository. External ground truth was the stated route, it has since been
run, and it is reported in G1b. **The number did not move.** On eleven public CVEs with the vendor's patch
as ground truth, the gated configuration and the fair baseline score the same false-negative rate. I can
no longer say "the decisive measurement has not been done". It has been done, and it came out null as
well. What is still open is a corpus that neither this author wrote nor this author selected.

## G2c. The gates failed half of an independently written set; four of the six are now fixed

An external reviewer wrote 12 cases against the gates as implemented. **The gates got 6 wrong** (five
false positives, one false negative): recall 0.83, precision 0.50, accuracy 0.50. All twelve cases, the
reviewer's runner and the reviewer's own fair baseline are permanent fixtures in
`benchmarks/fp_corpus/critic/`, and both numbers are published.

**Four were the gate failing its own documented rule.** That is an implementation defect, not a finding
about the rule, and leaving it unfixed would have been a different kind of dishonesty -- publishing a
known broken implementation as evidence about a method. They are fixed, and the reviewer's cases are the
regression tests that pin each fix: an echo in a JSON *key* name (`A3` says canonicalise before any
differential, and a key-set is a differential); `LISTENER.invalid` against `listener.invalid` (DNS is
case-insensitive, and "independent of" is not `str.__eq__`); an empty `expected_observable` (an empty
string is a missing input and a missing input must never pass); a markdown list read as hard wraps (the
predicate never tested "mid-paragraph" although its verdict text claimed it). Post-fix the set scores
recall 0.83, precision 0.83, accuracy 0.83 -- which on twelve cases is [0.52, 0.98] at 95%.

**Two are published unfixed, because they are limits of the rules.**

`c03-genuine` is a **false negative the gates manufacture** out of ordinary log vocabulary: bare `denied`
and `blocked` are refusal markers, a marker claims its own line and the next one, and proxy and cache logs
contain those words constantly. There is no mechanical fix. Dropping the tokens re-opens the catalogued
FP#3, whose refusals say exactly those words; narrowing the span to the marker's own line re-opens FP#3
too, because a refusal quotes the thing it refuses on the following line, and the reviewer's own
`c03-false` is accepted without the next-line rule. Deciding that "denied by the edge proxy" is an
infrastructure log and not the agent refusing requires understanding what the sentence is *about* --
the interpretive judgement this project exists to keep out of oracles. **Rule A6 cannot be stated
mechanically over vendor prose.** A token list is the best available approximation and it has a known,
published false-negative mode. This is the failure direction G9 says the project should be judged on, so I
named it and did not tune it away.

`c04-false` is a **schema gap**. Rule A5 asks who *populated* a field; the implementation keys on a list
of field names, and the reviewer's fixture puts the rig's own startup configuration under the key `host`,
which is in that list. Adding `listener_startup` to the config-field list is the same vocabulary
substitution in the other direction, and holdout `h02-genuine` already publishes what that costs. The
field the gate would need -- provenance -- is not expressible in this fixture schema, and the reason is
specific: a `provenance` field *asserted by the fixture's author* would be the gate reading its own
conclusion, which is precisely the labelling defect G2b records. Closing it requires provenance recorded
by the rig at capture time, which means instrumenting a real collector. Editing JSON will not do it.

One of the original holdout's two passes also turned out to be **an accident** -- `h01-false` passes
through `A9`, not the `A3` mechanism its own `label_basis` claimed, so the defect it was written to expose
was never exercised. The `label_basis` now says so. Every case in every subcorpus carries a `label_rule`,
and a test asserts that a case which passes does so through the gate its own label names, so this class of
accident cannot recur silently. The A3 canonicalisation defect remains unfixed.

*To close it:* nothing closes this permanently. Every fix invites the next held-out set. What can be
closed is the gap between a gate's stated rule and its implementation -- four of those are closed. What
cannot is the gap between a rule and the world, and the two unfixed failures are both on that side.

## G2d. The CVE study's first published p-value used the wrong denominator, in the flattering direction

The first version of `benchmarks/cve_study/results/cve_study.md` and of the README led with
`22/55 = 0.40` and `p = 3.4e-08` for the sensitivity arm. Those figures are arithmetically correct and
substantively meaningless. Seven of the eight seeded breakage modes produce exactly one outcome across
all eleven CVEs, because the rig breakage decides the verdict and the CVE contributes nothing, so a
run-level denominator counts the same deterministic result eleven times.

The aggravating detail, which an external reviewer found: this repository already applies exactly this
correction to the oracle experiment, where the shared oracle function makes the probe the right unit.
**So I applied the correction where it cost the tool and skipped it where it would have helped the
tool.**

*Corrected:* the unit is the breakage mode. 0 of 5 versus 2 of 5 on the real modes, two-sided Fisher
p = 0.4444; 0 of 8 versus 4 of 8 on all modes, p = 0.0769. The run-level figures are still printed and
labelled as not independent. The inflation stays visible; nothing was quietly dropped.

*To close it:* more breakage modes. Nothing about the analysis improves a five-mode denominator, and the
mode census is now the binding constraint on the only positive finding this project has.

## G1b. The construct is not the one on the label, and the external replacement came out null

An external reviewer reached this independently. The 38-case benchmark measures **catalogue-encoding
fidelity**. It does not measure negative trustworthiness. It shows whether the gates implement the
16-item catalogue. It does not show that a negative produced under them is trustworthy, because the cases
whose ground truth is "untrustworthy" were labelled by the author of the rules.

**The measurement that would close it has now been run.** Eleven known-fixed public CVEs at a pre-fix and
a post-fix pinned version, the vendor's patch as ground truth, 110 runs, nothing in this repository
getting a vote. Memory safety is excluded by rule and by test. Full design and per-CVE table in
[`docs/cve-study.md`](docs/cve-study.md) and
[`benchmarks/cve_study/results/cve_study.md`](benchmarks/cve_study/results/cve_study.md). This entry
exists because the file it is in previously described that study as the undone thing that would make this
project a result, and it had already been done.

**What it found.** One thing. It is a localisation and not an effect. The fair baseline's ability to
refuse a broken rig rests on a single derived record, whether the treatment arm reached the target. Deny
only that record and 2 of the 5 real rig-failure modes return "no bug" where a refusal is correct. At five
modes that is two-sided Fisher p = 0.4444, which is not distinguishable from chance. The mechanism is
visible. Nobody has measured the rate. Treat the figure as a floor and not an estimate: on the three real
modes where the baseline still refuses correctly it refuses for an unrelated reason that happens to fire,
which I did not predict.

**What it did not find.** Any difference between the gated configuration and the fair baseline. Both
score 0/11 false negatives on the pre-fix set, 0/11 false positives on the post-fix set, and 0 of 55
"no bug" calls on real seeded rig breakage. So the construct problem above is answered in the direction
that costs this project the claim: with ground truth from outside the repository, enforcing the lattice
did not change the outcome against a competent engineer who keeps their own controls. It also showed one
measurable cost, recorded separately below in G11.

**What it did not remove.** The circularity is reduced. It is not closed. The probes, the breakage modes
and the gates still share one author. Three of the eight breakage modes are injected and not real, so
their text was chosen here. And n = 11, with two distributions contributing two CVEs each, so **0/11
cannot distinguish a true rate of 0.00 from one of 0.25.** The targets were picked by a selection rule
written before they were chosen, which constrains the selection without making the probe set independent.

*To close it:* a probe set and a target set written by someone else. That is the only remaining route,
and it is why `CONTRIBUTING.md` asks for failures rather than features.

## G0. Where I should have stopped

A reviewer who ran everything made an observation I had not written down anywhere: in all the prose in
this repository, there is no point where I say I should have stopped. That is a fair hit. Here it is.

**The effort was mis-aimed, and I can say exactly where.** The one positive result this project has is
the reachability record, and its binding constraint is the number of breakage modes: seven of the eight
produce a single outcome across all eleven CVEs, so the census is tiny and the p-value is 0.4444 because
of that and nothing else. More modes would have moved it. Instead I wrote another mutation guard.

The guards are not waste. I neutered every one and every one broke a test, so the apparatus is
load-bearing. But the 180th guard and the 120th do not differ in value, and a tenth breakage mode would have
differed a lot. I kept doing the thing I was already good at instead of the thing the result needed.

**Second, and worse: the headline study is the only measurement CI cannot regenerate.** The false-positive
corpus and the dedup study both have full replay gates. The CVE study, which carries the only claim
anyone will quote, does not, because its fixture cache is 187 MB and gitignored. G14 names the cheaper
fix. I did not apply it. I built the gates for the two studies that do not matter and left the one that
does resting on a results file.

**Third, the order of the work was wrong.** This repository was not a git repository until very late, and
the published URL in its own install instructions did not resolve. Three separate reviewers stopped at
that line. A reader cannot run any of the above if they cannot clone it, so every hour spent on guard
coverage before `git init` was an hour spent on the wrong thing.

**Fourth, found on the day of publication: the release gate itself could not fire.** `addopts` carries
`-m 'not release'`, so the bare `pytest` that every CI job runs deselects the one test that checks the
declared repository URL resolves. Nothing ran it with `-m release` either. The README said that test
"fails the build if the declared URL is unreachable". The test's own docstring said `-m release` was
"what the release job does". There was no release job. Two sentences describing a check that could not
fire, one of them inside the check, in the gate a cold reviewer had specifically asked for.

That is this repository's own thesis, for the sixth time, in the place it should have been least likely
to happen. The fix is a `release` job in `.github/workflows/ci.yml` that runs `pytest -m release` on
every push. It is five instances in other people's code and one in mine before this; this one is mine
too. The pattern is not that other people are careless. It is that a check's own output is the worst
available evidence about whether it ran.

None of this changes a number in this file. It changes what I would do with the next week: harvest
breakage modes until the census is large enough to measure, give the CVE study a replay gate, and
publish before polishing.

## G1. The method has never been shown to outperform not using it

The claim this project makes is narrow: that an uncontrolled run produces negatives you cannot rely on.
It makes **no** claim that using it finds more bugs, finds them faster, or finds them more cheaply. No
such comparison has been run.

The private work this was extracted from attempted exactly one A/B test of the methodology, and **that
test was voided as confounded** by its own author: one arm's generator returned a stub and its judge
re-hunted instead of judging, giving that arm a second generation pass. The recorded conclusion was that
the question is open. It still is.

*To close it:* a head-to-head on an identical task set with the lattice on and off, measured on yield and
on hours, with enough runs to separate the two. Nothing short of that licenses an efficacy claim.

## G2bis. Two of five lattice rules were never exercised while coverage was reported as complete

The reviewer's by-hand census of which rules fire across the 38 cases found `B-stale-control` and
`B-reachability` firing **zero** times, because `void08-false` trips three lattice preconditions at once
and the gate returned on the first one it reached. The results file reported catalogue coverage as
complete throughout. *Corrected:* the lattice evaluates every precondition and records every one that
fired, the verdict is still decided by the first in a fixed order because the remedies differ and an
operator needs one next action, and the fired-rule census is now published in `fp_corpus.json` with a test
that each lattice rule fires on at least one committed case.

It sits apart from G2b because of what it says about the rest of the repository: a coverage claim that
nobody had mechanised was wrong, and it took an outside reader to notice.

## G2. The benchmark is substantially circular; only the held-out sets are not

The 38-case corpus and the gates that score it were both derived from the same 16-item catalogue. The
resulting 1.00/1.00 therefore measures whether the implementation encodes the catalogue. It is a
regression suite with a confusion matrix. It is not evidence of generalisation.

Two held-out sets exist. The 6-case adversarial holdout, written by the gates' author after writing them,
scores 0.67/0.67 and one of its two passes turned out to be an accident. The 12-case external critique
set, written by an independent reviewer, scored **0.83 recall, 0.50 precision, 0.50 accuracy** as it was
found and **0.83/0.83/0.83** after four of its six failures were traced to the gates breaking their own
stated rules -- see G2c, which lists what was fixed, what was not, and why. **The external number is the
one to quote, and it should be quoted with both values**, because a held-out score reported only after
repair is a score against an implementation that has already seen the test.

*To close it:* corpus cases contributed by someone else. That is the single most valuable contribution
anyone could make here, and it is why `CONTRIBUTING.md` asks for failures and not features.

## G3. n = 38, from one person's history, and some shapes are the same error counted more than once

Nineteen pairs is not a sample of anything. It is a list, and the README reports counts rather than rates
for that reason. Four of the catalogued shapes are arguably one error in four costumes (matching on a
value the tester put into the request).

An earlier version of this file argued that no confidence interval would be meaningful at this n. That was
a convenient way to avoid reporting uncertainty, and an external reviewer said so. Clopper-Pearson
intervals are now published for the oracle experiment, and they are wide enough that the magnitude of
that effect does not survive a change in the unit of analysis.

*To close it:* more cases, from more people, and a collapsed taxonomy that counts distinct mechanisms
rather than distinct symptoms.

## G4. Injected-defect ground truth bounds nothing about real software, and the real-software run agreed

The example target's ground truth is known because somebody wrote it down. Performance on a target built
to be measurable says little about a target built to do a job.

**This is now partly addressed, and it changed nothing.** The CVE study in G1b runs against real
distributed packages at vendor-pinned versions, so for those eleven targets the ground truth comes from a
maintainer's fix and not from this repository's author. The injected corpus and the real one give the
same answer: no measurable difference between the gated configuration and a fair baseline. This entry
previously named that study as the thing that had not been done.

**The breakage does not generalise. The target, for those eleven, does.** Three of the eight seeded
rig-failure modes are injected, so their text was chosen here, and the five real ones are failures that
actually occurred while building the study rather than a sample of how rigs fail in the field. Five is
also the denominator that holds the one positive finding to p = 0.4444.

*To close it:* stop seeding rig failures here and harvest them from somebody else's CI logs. Also targets
whose pre-fix state was never read by whoever wrote the probes.

## G5. The FP gates scored in the benchmark are not the shipping code path

`benchmarks/gates.py` is a reference implementation of the catalogue. It imports
`controlarm.controls.run` and never `controlarm.gates.fp`, so for the false-positive corpus the scored
gates are a sibling of the product and not the product itself.

This is narrower than it was. The CVE study's gated arm runs the shipping lattice
(`benchmarks/cve_study/runner.py` imports `controlarm.controls.run.Run`), so the study in G1b measures
the code a user actually invokes. The gap is now specific to the FP corpus. Claiming it is wider than
that would be inaccurate in the other direction.

*To close it:* collapse the two, and make the FP benchmark import the shipping gates.

## G6. The rule set is declared far more completely than it is enforced

The methodology this came from carries roughly 96 stated validity rules. Mechanical enforcement exists
for roughly a third. I am not hiding the gap. It is large, and a rule that lives only in prose is a
preference rather than a control.

*To close it:* `audit rules` should report the declared-to-enforced ratio per release, with the unenforced
rules named, so the number moves in public and cannot be rounded up.

## G7. The oracle experiment measures the false-positive axis much better than the false-negative one

On this target the interpretive oracle's errors are nearly all false positives, and the single mechanical
error is a false negative. The design is better at showing that weak oracles invent findings than at
showing what strong oracles miss.

*To close it:* a target whose flaws are deliberately observable only through weak signals, so the
mechanical oracle has a fair chance to fail.

## G8. Oracle strength is an integer that nothing has validated

Oracles are scored 0 to 4 and gated at 2. I reasoned those integers from mechanism. Nobody has measured
them. Nothing establishes that a strength-2 oracle produces more false verdicts than a strength-3 one.

*To close it:* label every case in the corpus with the strength of the oracle used and publish the error
rate against strength. The experiment above is a two-point version of this.

## G9. The false-positive catalogue is a floor, not a measurement

It records false verdicts that were caught. It has no denominator, and it says nothing about how many
*true* findings the same discipline rejected. Two cases in the source material suggest that number is not
zero: one true finding was nearly retracted, and one real code path was wrongly cleared, both because the
proof of concept could not express the positive.

*To close it:* keep every killed lead, re-run the kills against a later release, and publish how many
kills were wrong. Recall is the number this project should be judged on. Precision is not.

## G10. Cost is unmeasured

The discipline adds work per finding. Nobody has counted how much, or compared it against the work it
saves by preventing a retraction.

*To close it:* emit wall-clock and token counts into the run record, which already has somewhere to put
them.

## G11. The lattice has one measured cost, and it is over-conservatism

The CVE study found the only priced side-effect of the discipline so far. On the
`stale_positive_control` breakage mode the exploit arm still runs and still fires, because that mode
corrupts the control's *record* and leaves the exploit path alone. The gated configuration refuses the run
(`VOID`, rule `B-stale-control`); the fair baseline proceeds and reports a finding which, on a pre-fix
pin, is the right answer about the target. That costs the lattice **11 correct findings** that are
genuinely there.

Reporting a refusal of a true finding as a win would be the move this repository criticises elsewhere, so
it is counted as a cost. A second one: a confound table cannot distinguish a target that refuses by not
finding something from a rig that fails the same way, which was measured on a target whose *patched* pin
refuses via `FileNotFoundError`.

*To close it:* a staleness rule that distinguishes a control record that is merely old from one that is
wrong, which requires knowing whether the boundary changed between the two runs.

## G12. The prior-art gate's specificity is poor, and the recall that looks perfect is the easy half

`benchmarks/dedup/results/dedup.md` reports recall 100.0% (40/40), precision 75.5% (40/53) and
specificity 67.5% (27/40) over 80 labelled items. Split by family, which is how the pre-registered
selection rule says to read it, the identifier family scores 100% on all three metrics and its label is
**near-tautological**: the version came from the advisory's own OSV record, so OSV matching it is close to
a self-consistency check. The coordinate family is the real question, and there the gate scores precision
60.6% and **specificity 35.0% (7/20)**, calling 13 of 20 genuinely novel items prior art.

An earlier version of the README quoted recall and precision and omitted specificity, which is the
flattering subset of a results file that published all three, and it called recall "the headline" when the
selection rule had already called that label near-tautological. Both are corrected: the README now leads
that section with the specificity and the per-family split.

*To close it:* a version-aware GitHub query, which is the documented cause of nearly all 13 false alarms,
and a labelled set whose novel half is not drawn from the corpora the sources index.

## G13. The oracle experiment's fixtures were designed by the person who wanted the result

The 12 probes and the two target modes were written here, after the hypothesis. Nothing in the design
prevents a probe set that happens to suit a mechanical oracle, and the magnitude of the effect does not
survive the correct unit of analysis: p = 0.027 at the probe, and p = 0.063 once the single probe no
interpretive callable can match is dropped. A reviewer raised this gap. It had no entry in this file for
a full version.

*To close it:* probes written by somebody who has not read the oracle implementations, against a target
whose flaws were chosen without reference to oracle strength.

## G14. The CVE study's probe execution is the one published measurement CI cannot regenerate

Three studies are published, and until now only one of them had a reproduction gate. `run_benchmark.py
--check` regenerates the fp_corpus benchmark in CI. The other two were bound to the README -- its figures
are checked against the committed `cve_study.json`, the dedup artifacts and the guard table -- but nothing
regenerated them, so if either study's real behaviour changed, the committed results and the README would
have stayed perfectly consistent with each other and both become wrong together, with no gate able to
notice.

Most of that is now closed, and in CI:

- **dedup, fully.** `tests/test_priorart_benchmark.py` re-renders the whole of
  `benchmarks/dedup/results/dedup.md` from a replay of the committed cassettes and diffs it
  (`test_the_whole_published_report_reproduces_from_the_committed_recordings`), and re-executes
  `build_manifest.py` against the same cassettes to rebuild `manifest.json`
  (`test_the_committed_labelled_set_rebuilds_from_the_committed_recordings`). Both run offline and assert
  zero network calls. The recordings themselves are pinned by sha256 in `cassettes.index.json`, which
  `run_dedup.py --check` verifies.
- **the CVE study, down to the probe.** `tests/test_cve_study.py` feeds each of the 110 committed runs'
  probe reports back through the live pipeline and asserts that every field the study *derives* -- the
  per-arm failure classification, `lattice_verdict`, `lattice_reason`, and what all four configurations
  said -- is what the code produces, then scores the re-derived runs and asserts the published measurement
  comes out of them.

**What remains uncheckable in CI is the probe execution itself.** Four facts per run are read from the
committed record and not reproduced: the three `(executed, detail)` arm reports and
`exploit_reached_target`. Producing them means `python benchmarks/cve_study/run_study.py --check`, which
runs 110 subprocesses against two pinned versions of eleven distributions and refuses to measure against
pins whose bytes it has not verified. Those bytes are `benchmarks/cve_study/.cache/`: **187 MB**,
gitignored by `benchmarks/cve_study/.gitignore` because it is third-party source, and reconstructible only
with `--acquire`, which needs the network. A CI job that downloads and builds the 21 pinned distributions
in `fixtures.lock.json` on every push is not a check anyone would keep green, and the cache cannot be
committed. So the gate does not exist, and this entry says so. The hole is that a change to
`_driver.py`, to `acquire.py`, to a probe in `benchmarks/cve_study/probes/`, or to a breakage mode's
`action` would not move any committed number in CI.

*To close it:* a scheduled (not per-push) job that runs `--acquire` and then `--check` against
`fixtures.lock.json`, whose sha256 per pin already makes the download verifiable; or commit the per-run
probe reports as a cassette-style fixture with a digest index, the way `benchmarks/dedup/cassettes/` and
`cassettes.index.json` already do it for the dedup study, which would move those four facts per run from
trusted to pinned without shipping anyone else's source tree.

---

## Things deliberately not claimed

- That a mechanical oracle cannot be wrong. One error in 24 probe-runs, which is 0.04 with a 95%
  Clopper-Pearson interval of [0.001, 0.211]. A single event is not a rate; it is only a demonstration
  that zero is the wrong answer. The two significant figures previously printed here without an interval
  were more precision than one event can carry.
- That the gates generalise beyond the catalogue. The holdout says they partly do not.
- That the discipline is free. G11 prices it at 11 correct findings refused on one breakage mode.
- That a `CLEAR` prior-art verdict is evidence of novelty. G12 prices that gate's specificity at 35.0% on
  the harder of its two question families.
- That this is a new idea. See the README's prior-art section; Naptime named the principle in 2024.
- Anything at all about memory safety, which is out of scope because a cheap perfect oracle already
  exists there.
