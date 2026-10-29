# Contributing

The most valuable contribution to this repository is **a case the gates get wrong.**

That is not modesty, and it is not an invitation to help polish a result. The benchmark's weakness is
stated in `GAPS.md` **G1b, G2b and G2c**, which supersede the older G2: the corpus and the gates were
derived from the same catalogue, so a high score measures whether the implementation encodes that
catalogue rather than whether it generalises. **A case written by someone who did not write the gates is
the only thing that can break that circularity.**

The obvious objection is that external ground truth would settle it instead. It has been tried. `GAPS.md`
G1b reports a study against eleven known-fixed public CVEs at vendor-pinned versions, where the vendor's
patch is the ground truth and nothing here gets a vote. **It found no difference between enforcing this
lattice and a competent baseline that keeps its own controls**, and the one thing it did find is a
localisation at a five-mode denominator (p = 0.4444). So the open question is not whether more real
targets exist. It is whether a probe set and a corpus written by somebody else behave the way this one
does, and that is the thing only a contributor can supply.

## Contributing a corpus case

Add a pair to `benchmarks/fp_corpus/`: one fixture exhibiting a false signal, and a sibling where the
same signal is genuine. The pair is the unit, because a gate that rejects both is not discriminating, it
is just strict.

Each case is a JSON record carrying every field in `benchmarks.fp_corpus.REQUIRED_FIELDS`: the shape it
tests, which member of the pair it is, the observation the harness is given, the correct verdict, one
line on why a naive check gets it wrong, and three labels that the loader will refuse a record without.

- `asserts_absence` -- does your fixture's claim say that **nothing is there**? The headline count is
  selected on this, declared rather than inferred, because inferring it is how a published count came to
  include four cases that were not negatives.
- `conclusion_in_fixture` -- does your fixture hand the gate its own conclusion as a literal field? Be
  honest here. Writing the rule's antecedent down as a boolean turns the case into a lookup test, and
  such a case is scored and published but kept out of the headline.
- `label_rule` -- which gate rule your label's mechanism belongs to. A test asserts that a case the gate
  gets *right* was decided by that rule, so a case cannot pass through a different gate than the one you
  wrote it to test.

Say what makes the label defensible. If the label is arguable, say that too and argue it in the file.

Then run `python benchmarks/run_benchmark.py` and commit the regenerated results. **If your case makes
the numbers worse, that is a successful contribution and the numbers should get worse in public.** Do not
also change the gates in the same pull request; a case and a fix to the case are two different arguments
and reviewing them together hides which one did the work.

**What happens to your case after it lands**, because the disposition is not uniform and you should know
which one you are arguing for:

- If it shows a gate failing **its own documented rule**, that is an implementation defect. It gets
  fixed, your case becomes the regression test that pins the fix, and the pre-fix number is published
  next to the post-fix one so the improvement is auditable rather than retroactive.
- If it shows a gate implementing its rule correctly and still being wrong, that is a finding about the
  rule. It is **published unfixed**, with the reason it cannot be fixed stated in `GAPS.md`.

`benchmarks/fp_corpus/critic/` is a worked example of both: twelve cases by an independent reviewer, six
failures, four fixed and two published unfixed, all twelve kept.

## Contributing code

- A failing test exists before the implementation.
- Every guard is pinned: add an entry to `tools/mutate_guards.py` so that neutering your guard breaks at
  least one named test. `python tools/mutate_guards.py` must report every guard pinned.
- The core stays dependency-free. Anything needing a dependency goes behind an extra.
- `python -m ruff check . && python -m ruff format --check . && python -m pytest` before you push.
- No prints in library code. A library that writes to stdout cannot be composed.

## Reporting a problem with a claim

If a number in the README is wrong, or a claim is stronger than the evidence, open an issue titled with
the claim. Those are treated as defects of the same severity as a crash, because the project's only
contribution is the trustworthiness of what it reports.
