# `benchmarks/` -- turning three opinions into three measurements

```
python benchmarks/run_benchmark.py            # measure, write results/
python benchmarks/run_benchmark.py --check    # recompute and fail if a number moved
python benchmarks/run_benchmark.py --no-http  # probe the target in-process
python -m pytest tests/test_benchmark.py      # the instrument's own calibration
```

Standard library only. No credentials, no network, no vendor, no hosted target.
The committed numbers are in [`results/fp_corpus.md`](results/fp_corpus.md) and
[`results/fp_corpus.json`](results/fp_corpus.json). **Read the "What these
numbers do not establish" section of the markdown before quoting any of them.**

## The three measurements

| | claim | what is measured | where |
|---|---|---|---|
| **C2** | the gates reject the catalogued false positives *without* rejecting true positives | precision and recall per FP shape and overall, recall first | `fp_corpus/`, `scoring.py` |
| **C1** | a negative from the harness is trustworthy and an unguarded one is not | a three-class confusion matrix per arm, over three arms | `gates.py`, `run_benchmark.py` |
| **the oracle experiment** | oracle strength, and not target choice, drives the false-verdict rate | the same target and the same lattice, with only the oracle varied | `oracle_experiment.py`, `../examples/local_target` |

## Why C1 is reported the way it is, and why there are three arms

The falsifiable prediction is **not** "better detection". It is that an
unguarded configuration turns untrustworthy negatives into "no bug" at a
measurable rate, while the guarded configuration turns *those same runs* into
`VOID` / `CONFOUNDED` / `INCONCLUSIVE` -- it does not turn them into findings, it
refuses to call them anything. So the matrix has three predicted classes, and
`UNINTERPRETABLE` is one of them.

An earlier version of this file said that the unguarded configuration cannot
emit `UNINTERPRETABLE` at all, "which is the point rather than a handicap". An
external reviewer pointed out what that sentence actually does: it converts the
headline from a comparison into a restatement of two output alphabets. A
comparison arm that cannot express the correct answer has a score of zero before
any fixture is read. So there are now three arms, and `gates.ARMS` names them in
the order the results file reports them:

* `gated` -- the catalogue, enforced. The thing being measured.
* `fair` -- **the primary comparison.** A competent engineer with no library, who
  reads the status code, looks at whether their own positive control fired,
  looks at the number they are about to report, and may answer "I cannot tell".
  It has no echo normalisation, no refusal spans, no field-provenance logic, no
  independence check and no coverage check -- those are the gates, and they are
  what the comparison is *of*. The implementation is the reviewer's, promoted
  from `fp_corpus/critic/run_critic.py` into the scored module so that the
  primary arm is a real code path; a test pins the two to agreement.
* `naive` -- the check that actually produced each catalogued false verdict.
  Every branch of it is a check that someone competent actually shipped, that
  actually fired, and that produced one of the sixteen catalogued false
  verdicts. That makes it **provenance, not a comparison**, and its predicates
  are frozen and pinned by a test: a history edited to look better is no longer
  evidence of anything.

## Why the headline denominator is six and not eleven

The original C1 headline was computed over every case whose ground-truth class
is `UNINTERPRETABLE`. Two conditions were missing and both flattered the result.

*Is it a negative at all?* Four of the eleven are not. One is a finding, one an
over-broad finding, and two are claims about a metric. Counting them under a
headline that reads "ground truth is an untrustworthy negative" is a category
error. Every fixture now declares `asserts_absence`, and a test checks the
declaration against the fixture's own claim.

*Does the gate have to derive its answer?* For six of the eleven the fixture
wrote the rule's antecedent down as a literal -- and the only two cases where the
gates beat a fair baseline were both from that set. Five are re-expressed so the
gate derives the conclusion from raw records; the sixth, `hard19`, cannot be,
because the set of code paths a target reaches is the whole difficulty and no
fixture can make a gate discover it. It declares `conclusion_in_fixture` and is
excluded from the headline while still being scored and published.

The result of both corrections is that the measured effect **got smaller**. See
`GAPS.md` G2b, which states the new number and does not round it.

## Why the oracle experiment is the measurement that matters

The private corpus's headline comparison varied the target type, the oracle
type, the competitive density and the attacker position all at once, then
attributed the result to the oracle. It therefore measures nothing, and the
corpus says so. This experiment fixes one target, fixes the control lattice in
both arms, and changes one variable.

Two probes exist specifically so that the favoured configuration can lose:
`authz-ack` is a real flaw whose only observable is a status code, where the
"a 2xx carrying foreign data" rule is blind; and `tool-injection-behaviour` asks
whether an injected tool description actually *causes* an action, which this rig
cannot answer, so the correct output is a refusal to answer and both oracles are
scored on whether they say so.

## How to attack this benchmark

The fastest routes, in the order a reviewer should try them:

1. **The circularity.** The corpus and the gates come from the same catalogue.
   The honest answer is `fp_corpus/critic/`, twelve cases written by an
   independent reviewer against the gates as implemented. It found six failures;
   four were the gates breaking their own stated rules and are fixed, two are
   limits of the rules and are published unfixed, and the pre-fix and post-fix
   numbers are both printed in `results/fp_corpus.md`. The weaker
   author-written holdout in `fp_corpus/holdout/` is still there and still
   failing. The real fix is more cases contributed by other people.
2. **The labels.** Every case's expected decision follows mechanically from
   which member of its pair it is (`false` → `REFUSED`, `genuine` →
   `SUPPORTED`), which is enforced by a test. So the only judgement left in a
   label is which member a fixture is, and the `note` and `label_basis` fields
   argue that in each case. Disagree with one of those arguments and the number
   moves.
3. **The target.** It is an injected-defect fixture whose ground truth is known
   because somebody wrote it down. Nothing here bounds behaviour on real
   software.

## Adding a case

Add a record to a file in `fp_corpus/cases/` with every field in
`fp_corpus.REQUIRED_FIELDS`: `id`, `shape`, `shape_title`, `catalogue_ref`,
`member`, `correct_decision`, `correct_verdict`, `naive_oracle_strength`,
`gated_oracle_strength`, `note`, `observation`, and the three that were added
after the external critique --

* `asserts_absence` -- does this fixture's claim say that **nothing is there**?
  This is what the headline denominator is selected on, and it is declared rather
  than inferred because inferring it from the claim string is how the published
  count came to include four cases that are not negatives.
* `conclusion_in_fixture` -- does the fixture hand the gate its own conclusion as
  a literal field? `true` means the hard inferential step was done by whoever
  wrote the JSON, so the case measures a lookup rather than a detector; it is
  still scored and published, and it is excluded from the headline.
* `label_rule` -- which gate rule the label's own mechanism belongs to. A test
  asserts that a case the gate gets *right* was decided by this rule, so a case
  cannot pass through a different gate than the one it was written to test. That
  is how one of the holdout's two passes turned out to be an accident.

`label_basis` is additionally expected for anything arguable. Both members of
the pair are required; the loader refuses a record that is missing a field or
that leaks a label key into its observation, and `tests/test_benchmark.py` fails
on a shape with only one member. Then re-run `run_benchmark.py` and commit the
moved numbers -- including, and especially, if they moved the wrong way.

**If your case exposes a gate failing its own documented rule, say so**, because
the disposition differs. A gate that does not implement the rule it claims to is
an implementation defect and gets fixed, with your case kept as the regression
test and the pre-fix number published next to the post-fix one. A gate that
implements its rule correctly and is still wrong is a finding about the rule, and
it gets published unfixed.
