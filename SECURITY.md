# Security policy

## Reporting a vulnerability in controlarm

Report privately through GitHub's private vulnerability reporting on this repository
(Security -> Report a vulnerability). Please do not open a public issue for a vulnerability.

Include what you ran, what happened, and what you expected. A reproducer is welcome but not required to
start the conversation.

## What counts as a vulnerability here

This is testing infrastructure, so the interesting failures are in the rails:

- **A scope bypass.** Any input that causes a target outside the declared allowlist to be contacted.
- **A payload-guard bypass.** Any URL encoding that resolves to an address outside the operator's declared
  infrastructure, or into a private, loopback, link-local, reserved or multicast range, without being
  refused.
- **A verdict that overstates its evidence.** Any configuration producing `CANDIDATE` or `KILL` without a
  liveness arm that executed and an honest control refused by the boundary itself. This is the project's
  central invariant and a counterexample is its most severe possible defect.
- **The example target reachable off loopback.**

## What does not count

- Findings about the deliberately flawed `examples/local_target`. Its flaws are the point and they are
  documented in place.
- The gate failures already published in `GAPS.md` and in the adversarial holdout results. Those are known
  and deliberately unfixed. A *new* class of gate failure is very much in scope.

## Scope note

`controlarm` is for testing systems you are authorised to test. The rails reduce the chance of an
accident; they do not constitute authorisation.
