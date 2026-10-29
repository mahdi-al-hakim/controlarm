# Invariants

Each row is one invariant, the module that enforces it, and the wrong verdict it
prevents. "Enforced" means there is a guard in the source, a test that fails when
the guard is removed, and an entry in `tools/mutate_guards.py` that removes it.

The whole table exists because of a single asymmetry: a *positive* result carries
its own evidence, and a *negative* one does not. "We found nothing" is
indistinguishable from "the rig never ran", "we were not allowed to look", "the
oracle could not have fired" and "somebody already published this" unless
something refuses to let those four be recorded as the first.

---

## The target rail -- `controlarm.rails.scope`

| invariant | wrong verdict it prevents |
|---|---|
| Deny by default: a target not explicitly listed is `BLOCKED` | testing an asset nobody authorised, then reporting the result as if they had |
| Out-of-scope beats in-scope, and beats the loopback declaration too | a carve-out silently overridden by a broader allow entry listed after it |
| An **empty** allowlist denies everything, loopback included | vacuous truth read as permission: "nothing is excluded, so everything is allowed" |
| A wildcard entry is matched by `removeprefix("*.")`, never `lstrip("*.")`, and the schema refuses any other `*` | `*.*.example` collapsing to the bare suffix `example` and silently widening the allowlist |
| Subdomains match only when the entry says `allow_subdomains` | `notapi.example` treated as in scope because `api.example` is |
| The freshness check runs on **every** `check()`, not only in the CLI | a week-old copy of a scope page used as a current authorisation |
| A stale, null, or forward-dated `last_verified` makes the decision untrusted, and `assert_in_scope` refuses on it with no override | results published against a scope nobody reconciled |
| Loopback is allowed only by an explicit declaration in the scope file | a rail written for a local fixture rig quietly permitting a third party's loopback |
| `BLOCKED` is a distinct verdict carrying `is_result = False` | "we were not allowed to test it" recorded as "we tested it and found nothing" |
| The scope file is strict JSON: unknown keys, wrong types and missing required keys raise at load time | a mistyped `out_of_scope` key read as "no exclusions at all" |

## The payload rail -- `controlarm.rails.payload`

| invariant | wrong verdict it prevents |
|---|---|
| A payload URL must resolve, **in any encoding**, to declared infrastructure | pointing somebody else's server-side fetcher at an address the operator does not own |
| Dotted, pure-decimal, hex, octal, zero-padded, one-, two-, three- and four-part forms all decode | `0300.0.2.7`, `3221225991` and `192.0.519` treated as unrecognised names and waved through, or refused as unowned when they are the operator's own box |
| IPv6 decodes, including IPv4-mapped, IPv4-compatible, 6to4 and NAT64 embeddings | `[::ffff:169.254.169.254]` reaching a metadata service past an IPv4-only check |
| `::` and `::1` are **not** unwrapped to `0.0.0.0` / `0.0.0.1` | loopback reclassified as an ordinary address by a careless `::/96` unwrap |
| An ambiguous host keeps **every** reading, and all of them must be declared | `010` decoded as 10 while the fetcher's resolver reads 8 |
| Loopback, private, link-local, reserved, multicast, unspecified and non-global space are refused, and **cannot be declared** -- there is no flag | an "it's my own box" declaration laundering an internal address |
| Documentation space is not forbidden but still must be declared | a stand-in collector becoming a universal exemption |
| A host that cannot be decoded offline and is not a declared name fails closed | "I could not check where this points" recorded as "it points somewhere fine" |
| A malformed URL is `UNPARSEABLE`, not `UNDECODABLE` | a broken call hidden behind a correct-looking refusal |
| The refusal names the host and the verdict only, never the query string | a nonce or token copied out of a payload URL into a log |
| The refusal says what evidence to gather instead | a rail with no alternative, switched off by the next person who needs the result |

## The prior-art gate -- `controlarm.gates.priorart`

| invariant | wrong verdict it prevents |
|---|---|
| `UNGATED` is a distinct verdict, is never `CLEAR`, never clears promotion, and is reported invalid on its own grounds | zero sources answering read as zero prior art found -- the same number, the opposite claim |
| `CLEAR` means "no public prior art found", stated in the reason text, never "novel" | public silence read as novelty, when the dominant duplicate source is a vendor's own internal review that no public query can see |
| An **estimated** row count invalidates the verdict | "about 200 results" -- a report of a search engine's pagination -- used as a count a reader could re-derive |
| A verdict older than the freshness window (default 24h) is inadmissible at promotion | a fix landing between the search and the submission, turning a finding into a duplicate |
| Every query's **own** retrieval time is aged, not just the assessment's | a freshly stamped assessment assembled out of week-old query records |
| A query timestamped after the assessment, or an assessment timestamped in the future, is invalid | a record assembled out of order, or a broken clock, read as fresh |
| Every query record carries query, source, URL, retrieval time and row count, or cannot be constructed | a dedup argument a reader cannot re-run |
| A record attributed to a source other than the one that produced it is fatal | an audit trail that points at the wrong index |
| A one-source answer is valid and carries a warning naming it | a single-source zero treated as a zero, when indexes disagree in both directions |
| `coverage_confidence` is capped below 1 and carries its disclaimer as a field | a public-activity measure read as crowd coverage |
| The core makes no network calls | a dedup gate that cannot run in CI, and therefore does not run |

## The false-positive gate -- `controlarm.gates.fp`

| invariant | wrong verdict it prevents |
|---|---|
| `run_gate` does not short-circuit | four failures reported as one, and three lessons learned a run at a time |
| A missing input is `FAILED` | a measurement that was never taken scored as a measurement that passed |
| A check that raises is `FAILED` | a gate that crashes open and produces a clean report |
| A check returning anything but an `FPGateResult` is `FAILED` | a mode that cannot state its own verdict counted as having stated one |
| A suppression carries a reason, is counted explicitly, and never reads as a pass; suppressing an unknown mode raises | a gate quietly reduced to decoration |
| `clean` requires zero failures **and** at least one pass | a run where every mode was suppressed or inapplicable reported as clean |
| `NOT_APPLICABLE` is counted separately from `PASSED`, and an **undeclared** claim set fails every claim-scoped mode | "this does not apply to us" and "we checked it" collapsed into one column |
| `own_input_echo`: the matched bytes must be absent from everything the tester sent, in any casing | the catalogue's dominant error -- five of six numbered false positives -- where a planted string was echoed back and matched |
| `rejection_vs_disclosure`: a non-2xx is a rejection; a 2xx needs foreign data | an error echoing a foreign identifier read as a disclosure |
| `echoed_identifier_normalisation`: arms that become byte-identical after normalisation have no oracle | two rejections differing only by the identifier each echoed, read as a working existence oracle |
| `raw_artifact_read`: a detector summary is not evidence, and a match inside refusal text is not a leak | a secret quoted *as the thing being refused* reported as exfiltration |
| `placeholder_not_real_secret`: placeholder shapes are refused and realness must be asserted | a fixture value reported as a live credential |
| `liveness`: the tool must have started and a positive control must have fired | a dead rig reported as a defended target |
| `independent_control`: the control must be independent and differ in exactly one field | a control sharing the containment under test, so a silent control proves nothing |
| `poc_reachability`: the PoC must have been shown able to express the positive | a branch unreachable by construction in the fixture, reported as absent in the target |
| `oracle_strength`: strength floor 2, and an unknown oracle fails *as unscored* | string co-occurrence or model narration carrying a verdict |
| `identifier_novelty`, `single_source_dedup`, `fixture_branch_coverage`, `confidence_band`, `coverage_denominator`, `detector_target` | line novelty read as identifier novelty; a single-source zero; a result scoped to one fixture configuration; a named law fitted worse than the mean; coverage of an unchecked denominator; a rate measured against the wrong file |
| No domain-specific mode ships here | a generic gate that looks inapplicable to anything but a smart contract |

## The ledger and its audit -- `controlarm.ledger`

| invariant | wrong verdict it prevents |
|---|---|
| A row asserting an absence with no **results artifact** is refused at write time | a negative nobody can re-read -- a memory recorded as a result |
| A row asserting an absence with no stated **assumption** is refused | a negative that cannot be reopened on a named new perspective, and cannot be refuted either |
| Every row names an oracle, a subject and a control reading | a verdict with no instrument attached to it |
| `VOID` and `CONFOUNDED` are first-class terminal states in their own band, and neither asserts an absence | "the rig was not trustworthy" filed as "we found nothing" |
| Recording *that no control ran* is allowed | honest rows pushed out of the ledger, leaving an audit that only sees flattering ones |
| Append-only: no update, delete or edit method exists; an amendment is a new row with a `supersedes` pointer | a superseded belief erased instead of superseded |
| A duplicate row id, a self-reference, or a dangling `supersedes` pointer is refused, each with its own message | an amendment that overwrites what it claims to amend, or points at nothing |
| A corrupt line or unknown verdict on disk raises | a corrupt ledger read as an empty one, and every proportion computed over a file that could not be parsed |
| `audit` refuses nothing and reports everything | a store that rejects imperfect rows, producing an audit with nothing to find |
| The audit checks the named artifact is **actually on disk** | a promise of an artifact counted as an artifact |
| A control counts only when recorded as both **passing and independent** | a control that passed while testing the same containment as the treatment |
| An oracle absent from the strength table is **inadmissible**, not unknown | an unscored oracle defaulting to acceptable |
| A claim with a blank or missing citation is counted as uncited | an inherited claim treated as a fact |
| With no rows, the three proportions are `None` -- never `0/0 == 1.0` | an empty ledger reporting perfect coverage, which is this harness making exactly the claim it audits against |

## The verdict lattice -- `controlarm.controls.run`

Documented in that module's own numbered defects. Summarised: `VOID` when the rig
is not trustworthy, `CONFOUNDED` when the rig held but every arm failed for an
unrelated reason, `INCONCLUSIVE` when the evidence is partial, `NO-TESTS`,
`KILL`, `CANDIDATE`. Six verdicts because "I could not measure" is not "I
measured nothing", and because those six call for different next actions.

## The mutation harness -- `tools/mutate_guards.py`

| invariant | wrong verdict it prevents |
|---|---|
| A mutation pattern must match its target exactly once, or it is reported `STALE` and counted against the run | a mutation that never applied looking exactly like a guard that was pinned |
| A restore happens only when the file still hashes to what the tool wrote; otherwise it refuses, writes `<target>.orig.bak`, warns and exits 3 | another process's concurrent edit silently clobbered, with nothing in the output to say so -- the harness's own tooling committing the class of defect the harness exists to prevent |
| After restoring, every target must hash to the baseline captured before the run | the tool restoring something different from what it saved |
| A red baseline exits 2 and concludes nothing | mutation results read off a suite that was already failing -- the same rule the harness applies to a dead rig |
