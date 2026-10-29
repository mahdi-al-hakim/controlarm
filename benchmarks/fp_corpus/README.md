# `fp_corpus/` -- the paired false-positive corpus

19 pairs, 38 cases, in `cases/`. Plus a 3-pair adversarial holdout in
`holdout/`, loaded and scored separately.

Each pair is one shape of false verdict: a fixture exhibiting the false signal,
and a sibling where the **very same signal** is genuine. The pairing is the
design, not a convenience. A corpus of false positives alone measures only a
gate's catches, and a tool that reports only its catches is exactly the
instrument this discipline forbids.

## The 16 catalogued shapes

| shape | the false signal | what kills it |
|---|---|---|
| `fp01` | a `400` echoing a foreign tenant identifier, read as disclosure | a 4xx is a rejection by definition; disclosure needs a 2xx carrying foreign data (A2) |
| `fp02` | two rejections whose bodies differ, read as an existence oracle | normalise the echoed identifiers out, then diff again (A3) |
| `fp03` | a secret present in a transcript, read as exfiltration | the occurrence is inside a refusal, quoted back as the thing being refused (A6) |
| `fp04` | a success marker in a captured output, read as working egress | the marker was a literal in the source *we* submitted (A4) |
| `fp05` | a grep hit for the expected token in a listener log | the hit was the listener's own `expected_token` configuration field (A5) |
| `fp06` | nonce occurrences counted as redirect hops | the nonce was in the allowlisted URL path the tester supplied (A4) |
| `fs07` | identifiers found by grepping newly added lines | a new line can contain an old identifier; set-difference tokens per artifact (A7) |
| `void08` | a clean negative from a probe refused before the application layer | three independent grounds: no app-layer reach, no results artifact, a stale control |
| `void09` | silence in both arms, read as containment | control and treatment tested the same containment; redesign as a 2x2 |
| `fn10` | an absent field read as an absent feature | the listing command never rendered the field |
| `fn11` | an oracle string that never matched | colour escapes survived the suppression variable |
| `fn12` | a "no bypass" verdict | literal control bytes were written into the regex |
| `scope13` | a working PoC whose write-up over-states its scope | one pinned fixture field drives an independent detection path |
| `self14` | `LINEAR_AMPLIFICATION` reported with R-squared of -2.63 | a through-origin fit worse than the mean is `INCONCLUSIVE` |
| `self15` | 105 rows reported as a 3-way covering array | the independently computed feasible minimum was 384, and the constraint predicate read an unbound variable |
| `self16` | every paragraph break flagged as a hard wrap | email line endings leave a bare carriage return on blank lines |

**The structural point, which is the most reusable thing in the catalogue: five
of the six numbered false positives are the same error.** The detector matched
on a value the tester had put into the request, and the request was echoed. Only
`fp01` is a different error, a misread status class. So the remedy is not "be
careful"; it is mechanical -- normalise your own identifiers out, then match only
on a field the two hypotheses predict differently. A scorer that treats
`fp02`/`fp04`/`fp05`/`fp06` as four independent pieces of evidence is
overcounting one mistake four times, and the results file says so.

## The three extensions, labelled as such

* **`ext17`** -- a detector that measured an 81.7% fire rate because it was run
  against the PoC file instead of the source. The catalogue's own headline count
  of sixteen enumerates three of the four items in its section 3.6; this is the
  fourth, included and labelled rather than quietly folded into the total.
* **`hard18`** and **`hard19`** -- the two documented near-misses: a true finding
  nearly retracted, and a second code path wrongly cleared, both because the PoC
  could not express the positive. These are the **hardest cases in the corpus
  and the reason it exists.** They are the only recorded evidence that the
  gates' false-negative rate is not zero, which is the gap nothing in the
  private corpus could close: it never recorded how many true claims the gates
  rejected.

`hard18`'s pair is constructed so that the treatment arm carries no information
at all -- the oracle is silent in both members -- and the two are separated only
by whether a planted positive was observed on the control arm. Anything that
scores that pair correctly is reading the control, which is the whole claim.

## The labels

The expected decision follows mechanically from the member: `false` →
`REFUSED`, `genuine` → `SUPPORTED`, enforced by
`tests/test_benchmark.py::test_the_decision_label_follows_from_the_member`. So
the only judgement in a label is which member a fixture is. That judgement is
argued in the `note` field for every case and at length in `label_basis` for the
arguable ones. Disagree with one of those arguments and the published number
moves; that is the intended way to attack the corpus.

`correct_verdict` additionally records which of the six verdicts a ledger
should hold. Five of them map onto a ground-truth class; `NO-TESTS` maps onto
none, because a run with no test arm makes no claim to be scored, and the three ground-truth classes are derived from it alone
(`CANDIDATE` → FINDING, `KILL` → NO_BUG, `VOID`/`CONFOUNDED`/`INCONCLUSIVE` →
UNINTERPRETABLE), so no case can be labelled two ways.

Three further labels were added after an external critique, and each exists to
stop a class of quiet error rather than to describe a fixture:

* `asserts_absence` -- whether the fixture's claim is that **nothing is there**.
  The published headline count had been computed over every `UNINTERPRETABLE`
  case, four of which make non-negative claims, so the denominator was wrong.
  Membership is now declared, and a test checks the declaration against the
  fixture's own `claim`.
* `conclusion_in_fixture` -- whether the fixture hands the gate its own
  conclusion as a literal field. Only `hard19` is marked, because the set of
  code paths a target reaches is the whole difficulty and no fixture can make a
  gate derive it. Such a case is still scored and still published; it is
  excluded from the headline, because a case that measures a lookup cannot carry
  a claim about a detector.
* `label_rule` -- which gate rule the label's own mechanism belongs to. A case
  the gate gets right must have been decided by that rule. `h01-false` in the
  holdout passed through `A9` while its `label_basis` claimed `A3`, so one of
  the holdout's two passes was an accident and the mechanism it was written to
  test was never reached. That cannot now happen silently.

Five fixtures were also **re-expressed** so the gate derives a conclusion it
used to read: `void08`, `void09`, `ext17`, `scope13` and `self15`. Where a
summary field is retained because an external artifact reads it, a test poisons
it with the wrong value and asserts the verdict does not move, which is the only
way to show that a gate derives rather than reads.

## Provenance and safety

Every fixture is a generic, abstracted shape. None is derived from an unreported
live finding, and no vendor, product, endpoint, program or identifier appears
anywhere. Hostnames use the reserved `.example` and `.invalid` suffixes;
addresses are loopback. The one token-shaped literal in the tree
(`ptk_live_...`) authenticates nowhere and is published on purpose, so that the
"placeholder versus real secret" oracle has something to be right about.
