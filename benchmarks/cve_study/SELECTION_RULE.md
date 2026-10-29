# Target selection rule

**Written and committed before any CVE was selected.** The rule is stated first so that
"we picked the CVEs the gates happen to win on" is a checkable accusation rather than an
unanswerable one. `tests/test_cve_study.py` asserts that every committed target satisfies
every clause of C1-C6 below, and that the exclusion in X1 holds.

A candidate CVE is **admissible** iff all of the following hold.

- **C1 Public and fixed.** The vulnerability has a CVE identifier and a *public* fix that is
  identifiable as a specific released version. The registry records the fix URL (advisory,
  commit, or release notes). The vendor's released fix is the ground truth; no label written
  in this repository is.
- **C2 Two installable pinned versions.** There exists a pre-fix version and a post-fix
  version, both installable from PyPI at an exact pin, such that the only intended difference
  relevant to the probe is the fix. Both artefacts are recorded by SHA-256.
- **C3 Locally reachable.** The vulnerable behaviour is reachable by calling library code in
  a subprocess with **no network, no credentials, and no third-party service**. A target whose
  behaviour needs a live peer is inadmissible however interesting it is.
- **C4 No cheap oracle exists for the class.** The class must be one of: authorization,
  business logic, parser differential, sanitizer bypass, deserialization allowlist bypass,
  signature or token verification, path traversal, or trust-store contents. These are the
  domains the README scopes the project to, because no sanitizer-equivalent mechanical oracle
  is already standard practice there.
- **C5 A mechanical oracle is nameable in advance.** The oracle must be a predicate over a
  value the library returns or a side effect it performs, declared in the registry *before*
  the probe is executed, and it must not be a substring of anything the probe supplied as
  input. An oracle that reads back the tester's own payload is the catalogued FP#4/FP#6 shape
  and is inadmissible.
- **C6 Discriminating.** The same oracle must return false on a benign input on the *pre-fix*
  version. This is the probe's honest control: without it, an oracle that returns true
  unconditionally would score a perfect pre-fix result.

## Exclusions

- **X1 No memory safety.** Buffer overflows, use-after-free, NULL dereference and every other
  class for which a sanitizer is already a mechanical oracle are excluded by rule, not by
  convenience. The README scopes the project out of that domain explicitly, so including such
  a CVE would measure a problem the project does not claim to address. Enforced by a test.
- **X2 No resource-exhaustion or timing oracles.** ReDoS, decompression bombs, quadratic
  parsing and side-channel timing are excluded: their only observable is a duration, which is
  not stable enough on shared CI to be a mechanical oracle, and a flaky oracle would
  contaminate the false-negative measurement with scheduler noise.
- **X3 Nothing unreported.** Only CVEs with a public identifier and a public fix. This study
  names no vulnerability that is not already public and already fixed.

## Disposition of candidates that fail the rule

A candidate that is admissible on paper but whose reachability could not actually be
demonstrated is recorded with status `UNREACHED`, kept in the registry with the reason, and
**excluded from every headline number**. Guessing that a probe would have worked is the exact
defect this repository exists to refuse. The count of `UNREACHED` targets is published next to
the count of reached ones.
