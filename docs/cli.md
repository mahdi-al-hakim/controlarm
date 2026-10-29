# The command line

`controlarm` does not find vulnerabilities. It refuses to let an unaccompanied claim become a result.
The command line exists so those refusals can live in a shell script, a CI job or a pre-commit hook,
which are the three places a rail is actually worth having.

```bash
pip install -e ".[dev]"
controlarm --help
```

## The exit-code contract

Uniform across every subcommand. **It is the interface**, and the reason the whole thing exists: a
wrapper has to be able to tell "the instrument broke" from "the instrument refused" without parsing
text, because those two call for opposite actions.

| code | meaning | what a wrapper should do |
|---|---|---|
| `0` | success | believe the verdict |
| `2` | tool failure | fix the rig and re-run. **Never readable as a negative result.** A crashed run is not a clean one, and nothing that exits 2 has measured anything |
| `3` | refused by a gate | act on the printed reason. **This is a normal outcome, not an error** -- the common case for this tool is refusing to let you proceed |
| `4` | not promoted | a draft. Something executed and has not earned a verdict: re-run from fresh state and gather the rest |

`1` is deliberately unassigned. A generic "something failed" code inside a contract whose point is
that failures are distinguishable would re-create the ambiguity the contract removes.

Two consequences, both pinned by tests in `tests/test_cli.py`:

* **A refusal never exits 2.** `test_a_refusal_never_exits_2` exercises every refusal the
  subcommands can reach and asserts 3 for each.
* **A crash never exits 3.** `test_a_crash_never_exits_3` injects six unrelated exception types and
  asserts 2 for each, with `verdict: TOOL-FAILURE` printed.

A usage error from the argument parser is 2, and correctly so: a mis-invoked instrument measured
nothing either.

### Writing a wrapper

```bash
#!/usr/bin/env bash
controlarm run plan.json --out run.json
case $? in
  0) echo "a trusted negative: the arms ran, the control fired, nothing happened" ;;
  2) echo "THE RIG BROKE. This is not evidence about the target." ; exit 1 ;;
  3) echo "refused. Read run.json for the reason; this is the normal path." ;;
  4) echo "something executed. Re-run from fresh state before calling it a finding." ;;
esac
```

## Output

Every subcommand takes `--json` for one machine-readable object and `--human` for the default
rendering. Either flag works before or after the subcommand.

The human rendering always ends with a greppable line, for a wrapper that cannot use the exit code:

```
verdict: BLOCKED  exit: 3
```

The JSON object always carries `command`, `verdict`, `reason`, `exit_code` and `warnings`, plus the
subcommand's own fields. Both renderers are pure functions of one `Emission`, so a disagreement
between them about the verdict is not expressible; a test asserts they agree for every subcommand in
every outcome. Warnings go to **stderr** in both modes and into the JSON as a field, so neither a
human nor a pipe can lose one.

---

## Subcommands

### `controlarm scope check`

The target rail. Deny by default: a target not explicitly listed is `BLOCKED`, out-of-scope beats
in-scope, and an empty allowlist denies everything including loopback. Exit 0 in scope, 3 denied,
with the reason.

A `BLOCKED` decision carries `is_result: false`. "We were not allowed to test it" is not "we tested
it and found nothing", and nothing downstream may read it as a negative.

```console
$ cat scope.json
{
  "last_verified": "2026-01-01",
  "in_scope": [{"host": "api.example", "allow_subdomains": true}],
  "out_of_scope": [{"host": "internal.api.example", "notes": "carve-out"}]
}

$ controlarm scope check https://api.example/v1/orders
target     https://api.example/v1/orders
host       api.example
scope      scope.json (verified 2026-01-01, window 7d)
trust      verified

in scope via api.example

verdict: IN-SCOPE  exit: 0

$ controlarm scope check https://internal.api.example/v1/orders ; echo "exit=$?"
...
explicitly OUT of scope via internal.api.example (carve-out)

verdict: BLOCKED  exit: 3
exit=3
```

**Staleness warns; it does not refuse.** `check` reports and the library's `assert_in_scope` refuses,
and this subcommand is the reporting path, so a stale or never-reconciled scope file prints a warning
to stderr, sets `trusted: false`, and still exits 0. Pass `--refuse-untrusted` to route through
`assert_in_scope` instead and get exit 3, which is what a wrapper that must not proceed on an
unreconciled authorisation should use:

```console
$ controlarm scope check https://api.example/x --refuse-untrusted ; echo "exit=$?"
warning: scope.json: scope last verified 390 day(s) ago, window is 7. ...
...
verdict: BLOCKED-UNTRUSTED  exit: 3
exit=3
```

A scope file that cannot be parsed is **exit 2**, not 3: a malformed file says nothing about any
target, so reporting it as a denial would be reporting a measurement nobody took.

### `controlarm scope verify`

Stamps `last_verified` with today's date. **Refuses without a cited source.** The stamp is the
scope file's one claim about the world; without a citation it asserts only that somebody looked,
which is exactly the unaccompanied claim this tool exists to refuse.

A source must be a URL with a scheme and a host, or a quoted sentence -- the same standard
`ledger.Claim` applies. A word of reassurance is not a source.

The citation cannot go in the scope file itself: that schema refuses unknown keys, which is the right
behaviour and not one to weaken. It goes into a sidecar `<scope>.verification.jsonl` beside it,
together with the sha256 of the file as stamped, so a stamp can be tied to the version of the file
it was made against.

```console
$ controlarm scope verify ; echo "exit=$?"
refusing to stamp last_verified with no cited source. ...

verdict: REFUSED  exit: 3
exit=3

$ controlarm scope verify --source "I checked it" ; echo "exit=$?"
--source 'I checked it' is not a citation. ...

verdict: REFUSED  exit: 3
exit=3

$ controlarm scope verify --source https://example.invalid/program/policy
scope      scope.json
stamped    2026-10-26
source     https://example.invalid/program/policy
sha256     ece90508a5143f388b0fdd16d1b9ae817d8e25272625a36c3549de0197595ed1
logged to  scope.json.verification.jsonl

verdict: VERIFIED  exit: 0
```

### `controlarm oracle rate`

The 0-4 oracle strength classification, gated at 2. Exit 3 below the floor, and exit 3 for a kind
that is not in the table at all: an unscored oracle is refused as **unscored**, never treated as
unknown, because an unknown oracle defaulting to acceptable is how string co-occurrence carries a
verdict.

**Every path states that the scale is unvalidated.** `GAPS.md` G8: the integers are reasoned from
mechanism, not measured, and nothing establishes that a strength-2 oracle produces more false
verdicts than a strength-3 one. A tool that printed a bare number here would be lending its own
heuristic an authority this repository explicitly disclaims, so the caveat is in the body, on stderr,
and in the JSON as `scale_is_validated: false` and `caveat`.

```console
$ controlarm oracle rate source_diff
warning: UNVALIDATED SCALE (GAPS.md G8): ...
oracle     source_diff
strength   4 of 4
floor      2

oracle 'source_diff' is strength 4, at or above the floor.

UNVALIDATED SCALE (GAPS.md G8): oracles are scored 0 to 4 and gated at 2, and those integers are
reasoned from mechanism rather than measured. ...

verdict: ADMISSIBLE  exit: 0

$ controlarm oracle rate model_text ; echo "exit=$?"
oracle 'model_text' is strength 0, below the floor of 2. Nothing below the floor reaches the
operator: it is what stops probe volume from becoming noise.
...
verdict: INADMISSIBLE  exit: 3
exit=3

$ controlarm oracle rate looks_about_right ; echo "exit=$?"
...
verdict: UNSCORED  exit: 3
exit=3
```

### `controlarm run`

Executes a declared plan and writes `run.json` with the verdict lattice.

**The plan format.** Strict JSON. `id`, `subject`, `oracle`, `control`, `liveness` and `arms` are
all required and none may be null; `notes` is optional and no gate reads it. Unknown keys are
refused by name. `oracle` and `control` are **required non-nullable constructor arguments** of the
`Plan` dataclass, so a plan with no named oracle or no honest control cannot be constructed at all --
there is no override, no `--force`, and no flag to skip the control, because a flag to skip the
control is the only flag anybody would ever use.

> **A plan file is code.** `call` names a dotted `module:attribute` path which `run` imports and
> invokes, resolving against the current working directory as well as the installed environment.
> Give a plan file exactly the trust you would give a Python file.

```json
{
  "id": "fetch-allowlist-backslash",
  "subject": "the fetch allowlist cannot be reached past",
  "notes": "prose only; no gate reads this field",
  "oracle": {
    "kind": "parsed_field_diff",
    "observable": "the parsed final_host field of the fetch response, not the echoed URL"
  },
  "liveness": {
    "name": "LIVENESS",
    "call": "examples.local_target.probes:route_works",
    "args": {"url": "https://allowed.example/ok", "mode": "flawed"},
    "expectation": "executes, or the run is VOID"
  },
  "control": {
    "name": "HONEST-CONTROL",
    "call": "examples.local_target.probes:reached_off_list",
    "args": {"url": "https://listener.invalid/c", "mode": "flawed"},
    "expectation": "refused by the boundary itself, or the run is VOID"
  },
  "arms": [
    {
      "name": "off-list host behind a backslash authority",
      "call": "examples.local_target.probes:reached_off_list",
      "args": {"url": "https://allowed.example\\@listener.invalid/c", "mode": "flawed"},
      "expectation": "refused"
    }
  ]
}
```

Four plans ship in `examples/plans/`, one per exit code. Run them from the repository root:

```console
$ controlarm run examples/plans/fetch_allowlist_patched.json --out run.json ; echo "exit=$?"
plan       fetch-allowlist-backslash-patched  (examples/plans/fetch_allowlist_patched.json)
subject    the fetch allowlist cannot be reached past
oracle     parsed_field_diff (strength 3) reading the parsed final_host field of the fetch response
written    run.json

arms:
  [executed  ] liveness        LIVENESS  reason=other  200 final_host='allowed.example'
  [refused   ] honest-control  HONEST-CONTROL  reason=other  403 final_host=None
  [refused   ] test            off-list host behind a backslash authority  reason=other  403 ...

Every test arm was refused, and none failed for an unrelated reason. ...

verdict: KILL  exit: 0
exit=0

$ controlarm run examples/plans/fetch_allowlist.json --out run.json ; echo "exit=$?"
...
verdict: CANDIDATE  exit: 4
exit=4

$ controlarm run examples/plans/fetch_allowlist_unauthorized.json --out run.json ; echo "exit=$?"
...
The liveness control failed for an unrelated reason, so the rig was never shown to produce a
positive. No absence in this run is interpretable. This is VOID, not KILL.

verdict: VOID  exit: 3
exit=3

$ controlarm run examples/plans/weak_oracle.json --out run.json ; echo "exit=$?"
oracle 'model_text' is strength 0, below the floor of 2. ...

verdict: REFUSED  exit: 3
exit=3
```

**The verdict-to-exit mapping**, and why:

| lattice verdict | exit | why |
|---|---|---|
| `KILL` | 0 | the arms ran, the control fired, nothing happened. The one verdict that is a result |
| `CANDIDATE` | 4 | something executed. A draft, not a finding, until it is re-run from fresh state |
| `VOID` | 3 | the rig was never shown to produce a positive. No absence here is interpretable |
| `CONFOUNDED` | 3 | the rig held and every arm failed for a named unrelated reason |
| `INCONCLUSIVE` | 3 | partial evidence, and one confound is enough to deny a `KILL` |
| `NO-TESTS` | 3 | controls ran and no test arm was defined |

A plan whose oracle is below the floor, or not in the table, is refused **before a single arm
fires**: an inadmissible oracle makes every arm's result unreadable, so firing them spends the
budget to learn nothing. Every callable is resolved before the first one runs too, so a typo in the
last arm refuses the plan rather than producing a half-run whose silence is indistinguishable from a
target that stopped answering.

A plan file that cannot be read at all is **exit 2**. A plan file that is read and rejected is exit
3. Being pointed at nothing is breakage; reading something and refusing it is a refusal.

### `controlarm ledger add`

Appends one row to an append-only JSONL store. There is no update, delete or edit: an amendment is a
new row with a `--supersedes` pointer, so the superseded belief stays readable.

Exit 3 when the store refuses the row. It refuses exactly four things, each with its own message: a
reused id, a dangling or self-referential `supersedes`, and a verdict that asserts an absence
(`KILL`) with no `--artifact` or no `--assumption`. A negative with nothing to re-read is not a
result, it is a memory.

**Recording that no control ran is allowed.** Omit `--control-passed` and the row records `null`,
which the audit counts. A store that rejected every imperfect row would leave an audit that only
ever sees flattering ones. Omitting the flag is deliberately not the same as passing `false`, and
`--control-passed maybe` is a usage error rather than a silent `false`.

```console
$ controlarm ledger add --id n1 --subject "the fetch allowlist" --verdict KILL \
    --oracle parsed_field_diff ; echo "exit=$?"
row 'n1' records KILL, which asserts an absence, and names no results artifact. A negative with
nothing to re-read is not a result; it is a memory. Write the run artifact and name it here.

verdict: REFUSED  exit: 3
exit=3

$ controlarm ledger add --id n1 --subject "the fetch allowlist" --verdict KILL \
    --oracle parsed_field_diff \
    --control-name HONEST-CONTROL --control-passed true --control-independent true \
    --artifact run.json \
    --assumption "the backslash authority is the only parser disagreement on this route" \
    --claim "the two parsers disagree::https://url.spec.whatwg.org/"
ledger     ledger.jsonl
row        n1
verdict    KILL  (band negative-trusted)
oracle     parsed_field_diff
artifact   run.json

verdict: RECORDED  exit: 0
```

### `controlarm ledger show`

Lists the rows. `--current` hides what a later row supersedes. **This subcommand has no refusal
path**: it reports. An unreadable or corrupt store is exit 2, because a corrupt ledger is not an
empty one.

```console
$ controlarm ledger show
ledger     ledger.jsonl
rows       2

row                verdict       band                 oracle
n1                 KILL          negative-trusted     parsed_field_diff
v1                 VOID          negative-untrusted   model_text

2 row(s) including superseded rows

verdict: LISTED  exit: 0
```

### `controlarm audit ledger`

The module that makes the negatives auditable rather than merely asserted. Re-reads the ledger and
reports, per row and in total, the **three proportions**:

1. does the named results artifact actually exist on disk (a promise of an artifact is not one);
2. is a **passing and independent** positive control recorded (a control that passed while testing
   the same containment as the treatment has separated nothing);
3. is the named oracle admissible (an oracle absent from the strength table is **inadmissible**, not
   unknown).

Plus the count of uncited claims: an inherited claim with no citation is a lead, not a fact.

**This subcommand refuses nothing and always exits 0**, and the asymmetry is the design. A badly
scoring ledger still exits 0 and the badness is in the output. With no rows the three proportions
are `null`, never `0/0 == 1.0` -- an empty ledger reporting perfect coverage would be this harness
making exactly the claim it audits against. An unreadable store is exit 2.

`--out audit-2026-10-26.md` also writes the markdown artifact.

```console
$ controlarm audit ledger
# Ledger audit

Rows audited: 2

| proportion | value |
|---|---|
| rows whose results artifact exists | 50% (0.500) |
| rows with a passing independent positive control | 50% (0.500) |
| rows with an admissible oracle (strength >= 2) | 50% (0.500) |

Uncited claims across all rows: 0

## Per row

| row | verdict | artifact | control | oracle | uncited | notes |
|---|---|---|---|---|---|---|
| n1 | KILL | yes | yes | yes | 0 |  |
| v1 | VOID | NO | NO | NO | 0 | no results artifact is named, so the verdict cannot be
re-read; no positive control is recorded for this row; the named oracle 'model_text' is strength 0,
below 2 |

This report refuses nothing. ...

verdict: AUDITED  exit: 0
```

### `controlarm audit rules`

Declared rules against mechanically enforced rules. **This subcommand always exits 2, and that is
the honest answer rather than a defect.**

`GAPS.md` G6 asks for a declared-to-enforced ratio per release. The ratio cannot be derived from
this repository, and the output says so in full rather than printing a number nobody measured:

* **The denominator is prose.** `GAPS.md` G6 states "roughly 96 stated validity rules". The
  ninety-six are not enumerated anywhere here, so there is no set to take a subset of. The figure is
  parsed from G6's own sentence, which is printed verbatim, rather than copied into a constant.
* **The numerator would be a different unit.** `docs/invariants.md` enumerates this harness's
  implementation invariants and defines "enforced" for each as a guard in the source, a test that
  fails when the guard is removed, and an entry in `tools/mutate_guards.py`. Those rows are
  finer-grained than the methodology's validity rules and are not a subset of them.
* **Both available mappings disagree by an order of magnitude**, which is the proof that neither is a
  measurement. Library invariant rows over declared rules gives about two thirds; methodology rule
  identifiers cited by the shipping library over declared rules gives about a thirtieth. The
  published honest baseline for this method is roughly 30 of 96. A figure that can be argued to any
  of three values by choosing a unit is a rhetorical device.

So all three counts are printed with their provenance, both candidate ratios are printed **labelled
unusable**, what would have to exist for the ratio to be computable is printed, and the exit code is
2: an instrument that cannot measure has not measured a low number. `--json` still carries every
real count, with `declared_to_enforced_ratio: null`.

Every count is parsed from a committed artifact at the moment it is printed. A missing or
unparseable artifact is also exit 2, with the artifact named -- a derivation that silently degraded
to zero would divide by ninety-six to a flattering nothing.

```console
$ controlarm audit rules --repo . ; echo "exit=$?"
declared rules (the source methodology)
     96   GAPS.md G6, parsed from its own sentence:
          The methodology this came from carries roughly 96 stated validity rules.
          NOT enumerated in this repository, so there is no set to subset.

invariants this repository declares enforced
     68   docs/invariants.md table rows (64 of them about the library)
           10  controlarm.rails.scope           mutation target: scope
           11  controlarm.rails.payload         mutation target: payload
           11  controlarm.gates.priorart        mutation target: priorart
           18  controlarm.gates.fp              mutation target: fp
           14  controlarm.ledger                mutation target: ledger
            4  tools/mutate_guards.py           mutation target: n/a (tooling)

guards mechanically pinned
    180   tools/mutate_guards.py MUTATIONS, each neutered in CI to prove a test catches its removal
...
DECLARED-TO-ENFORCED RATIO: NOT COMPUTED.
  - The denominator is prose. ...
  - The numerator would be a different unit. ...
  - Both available mappings disagree by an order of magnitude ...
  - To close it: enumerate the declared rules in this repository, one identifier each, and name
    the identifier on every row of docs/invariants.md. ...

candidate ratios, computed and printed so they can be rejected rather than quietly not
considered. NEITHER IS USABLE:
  0.667  library invariant rows over declared rules (64/96)
  0.031  cited rule identifiers over declared rules (3/96)
  The published honest baseline for this method is roughly 30 of 96. ...

verdict: UNDERIVABLE  exit: 2
exit=2
```

### `controlarm selftest`

The instrument's own calibration. An instrument that has never been observed to fire cannot certify
a negative, so this fires the gates at something known:

* a **known-bad fixture** must fire the **exact expected multiset** of modes, no more and no fewer.
  Both directions are separate named checks, so a drift says which way it went. The fixture is the
  clean one broken in exactly three named ways and left correct in every other respect, because a
  fixture that is wrong in every way cannot detect a gate that stopped checking any single thing;
* a **known-clean fixture** must fire **exactly zero** -- and must also still have gated something,
  because a fixture whose every mode was inapplicable has zero failures and has gated nothing;
* every refusing gate must raise the **right exception with the right reason** for each way its
  refusal can be reached. Ten modes across `LedgerError`, `PriorArtError`, `ScopeError` and
  `PayloadError`. A wrong exception type counts as a failure, not a pass.

> **A non-zero exit from this subcommand voids every clean verdict the gates have produced since the
> last passing selftest.** Those runs must be re-run; they are not merely suspect. That is the rule
> that voided two runs in the work this was extracted from and it is why the negatives in that
> ledger can be relied on at all. The exit code is 2, because a drifted instrument is a broken one
> and nothing it said has measured anything.

```console
$ controlarm selftest
known-bad fixture fired:   ['own_input_echo', 'oracle_strength', 'oracle_is_a_parsed_field']
known-bad fixture expects: ['own_input_echo', 'oracle_is_a_parsed_field', 'oracle_strength']
known-clean fixture fired: []

  [pass] known-bad fixture fires no unexpected mode
         no mode fired that was not expected
  [pass] known-bad fixture fires every expected mode
         all 3 expected modes fired: [...]
  [pass] known-bad fixture is not reported clean
         3 failed, 6 passed
  [pass] known-clean fixture fires exactly zero modes
         zero failures
  [pass] known-clean fixture actually gated something
         9 modes passed, 7 not applicable, 0 suppressed
  [pass] refusal mode -- ledger: an absence with no results artifact
         LedgerError: 'names no results artifact'
  ... 9 more refusal modes ...

all 15 calibration checks pass: ...

verdict: CALIBRATED  exit: 0
```

Put it first in CI, and treat a failure as voiding what came before it:

```bash
controlarm selftest || { echo "gates drifted: every clean verdict since the last pass is VOID"; exit 1; }
```

---

## What is deliberately not implemented

The specification this is taken from lists more subcommands than exist here. **Nothing is stubbed.**
A subcommand that printed a plausible-looking nothing would be worse than an absent one, because an
absent one cannot be mistaken for a check that ran. These are absent because no module in this
repository can answer them:

| specified | why it is not here |
|---|---|
| `init <program>` | scaffolding only. There is no code behind it, and a `scope.json` template is three lines of documentation rather than a subcommand |
| `phase0 <lead>` | the five cheapest kill checks are all network and corpus queries. No module performs any of them |
| `plan new <id>` | the ten-field hypothesis record does not exist as code. The plan format `run` consumes is six fields and is written by hand; validating one is what `run` does before it fires anything |
| `dedup run <target>` | `gates/priorart.py` defines the verdict, the freshness rule and the record schema and makes no network call itself; the sources live in `controlarm.gates.sources` behind the `[dedup]` extra and are replay-first. That interface is new and not yet stable, and a subcommand pinned to a moving surface would be a second instrument disagreeing with the first, so none is wired to it yet. **This is the most obvious next subcommand**, and until it exists a `dedup run` with no source registered would emit `UNGATED` every time -- which read as a dedup pass is the exact defect that module exists to prevent |
| `saturation --class` | no base-rate corpus and no parser, so no parse rate, so nothing that could honour the 95% coverage refusal |
| `promote <run>` | the `DRAFT -> CONTROLLED -> REPORT_READY` state machine is not implemented. The pieces a promotion gate would consult exist -- `assert_gated`, `assert_in_scope`, `run_gate`, the ledger's write gate -- and `selftest` fires each of them at its refusal modes, but the machine that sequences them does not |
| `bundle <run>` | no sealer, no manifest, no hash block, no redaction assertion |
| `lint <draft>` | no wording or claim-label gate in the library |
| `replay <bundle>` | there are no bundles to replay |

`tests/test_cli.py` asserts in both directions that the subcommands documented here and the
subcommands the parser implements are the same set, and that each of the names above appears on this
page, so an absent one cannot quietly become an overlooked one.

## The two import paths

The command line is one way in; the library is the other. Which path is canonical matters:

* **The submodule is canonical.** `controlarm.rails.scope`, `controlarm.rails.payload`,
  `controlarm.gates.fp`, `controlarm.gates.priorart`, `controlarm.controls.run` and
  `controlarm.ledger` are where these names are defined, where their docstrings and numbered defects
  live, and what the tests, the mutation table and `docs/invariants.md` refer to. Cite the submodule
  path in a bug report or a review.
* **The top level is ergonomic.** Every public name is re-exported from `controlarm`, so
  `from controlarm import ScopeGuard, check_payload_host, run_gate, Ledger` works. They are the same
  objects, not wrappers, and a test asserts that for every name.

`controlarm.cli` is deliberately **not** re-exported at the top level. It is the only part of the
package that writes to a stream, and a library import that could print is the defect the split
exists to prevent.
