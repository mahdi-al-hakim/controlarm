"""Neuter every guard in the harness, one at a time.

Line coverage executes a guard whether or not any test would notice it being
removed. This script removes each guard in place and runs the suite. A guard
whose removal leaves the suite green is **unpinned**: it is enforced by nobody,
and the harness's claim about it is unverified.

This is the check the harness demands of a security finding, turned on the
harness itself: a control is only meaningful if its absence is observable.

    python tools/mutate_guards.py
    python tools/mutate_guards.py scope payload        # only these targets
    python tools/mutate_guards.py --figures            # the README's figures

Exit 0 when every guard is pinned, 1 with a list when any is not, 2 when the
baseline suite is already red -- in which case nothing can be concluded, which
is the same rule the harness applies to a dead rig -- and 3 when a target was
modified by another process mid-run.

Numbered defects of this tool, kept here for the same reason the modules keep
theirs: a guard cannot be removed without removing its justification.

  1  blind restore after a mutation  -> the tool captured each target's
     content at the start of the run and wrote it back unconditionally when the
     mutation was done. Any edit another process made to that file in between
     was silently overwritten, with nothing in the output to say so. That is
     exactly the class of defect this harness exists to prevent, occurring
     inside the harness's own verification tooling, and it destroyed a real
     edit before it was found. The fix is in ``restore_or_refuse``: the file is
     re-read and hashed against the exact mutated content the tool wrote, and a
     mismatch refuses to restore, writes the captured pristine content to
     ``<target>.orig.bak``, warns loudly and exits 3. "The tool restored
     something different from what it saved" is checked too: after restoring,
     the file must hash to the baseline digest captured before the run.

  2  a mutant that does not parse     -> a replacement that broke the file's
     syntax made the whole suite red because nothing could be imported, and
     the guard was reported pinned on the strength of a syntax error rather
     than of a test. One mutation in this very table did exactly that: its
     pattern excluded a trailing comma, so the ``# MUTATED`` comment swallowed
     it. ``apply_mutation`` now compiles every mutant before writing it and
     reports an unparseable one as stale.

  3  the published figures were outside the loop  -> this tool proved every
     guard in the harness load-bearing while the README's numbers, which are
     the only part of the repository most readers see, were pinned by a test
     nobody had ever watched fail. An adversarial reviewer falsified three of
     them, including a Fisher p of ``1.0e-99``, and the full suite stayed
     green. ``--figures`` runs the same experiment on the README: each
     published figure is falsified in place, one at a time, and a falsification
     that leaves the suite green is reported ``UNPINNED``. The table is derived
     from ``tests/test_readme_figures.py``'s ``BINDINGS`` rather than written
     here, because a second hand-kept copy of that list is the next thing to go
     stale, and a stale mutation reports a figure as pinned when nothing pins
     it.

  4  the mutant compiler refused a markdown target  -> defect 2 compiles every
     mutant, which is right for Python and nonsense for the README: markdown
     has no syntax to break, so every figure mutation came back stale. The
     check is now conditional on ``Mutation.is_python``, and a markdown target
     keeps the weaker guarantee that the replacement differs from the match.

  5  the figure mutations must not inflate the guard census  -> the README
     quotes the guard count from ``MUTATIONS`` and a test pins it, so the
     figure table is kept separate and ``MUTATIONS`` is unchanged. A run with
     no arguments still reports exactly the number the README states.

Mutations are regular expressions, not literals, so reformatting the source
cannot silently desynchronise a mutation from the line it neuters. A pattern
that does not match **exactly once** is reported as stale rather than skipped
quietly, because a mutation that never applied looks exactly like a guard that
was pinned. Several patterns therefore carry their surrounding line: the same
guard shape appears twice in a file as often as not, and "matched 2 times" is
the tool refusing to guess which one it meant.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "controlarm"

#: Short name -> the file its mutations are applied to.
TARGETS: dict[str, pathlib.Path] = {
    "controls": SRC / "controls" / "run.py",
    "scope": SRC / "rails" / "scope.py",
    "payload": SRC / "rails" / "payload.py",
    "priorart": SRC / "gates" / "priorart.py",
    "fp": SRC / "gates" / "fp.py",
    "ledger": SRC / "ledger.py",
    # Not in the package. ``benchmarks/gates.py`` is the scored reference
    # implementation of the false-positive catalogue, and the repairs made after
    # an external critique added predicates that nothing else in the tree would
    # notice the absence of. A gate whose removal leaves the suite green is
    # unpinned whether or not it ships, and a benchmark's own gates are a worse
    # place for that than the library, because an unpinned one silently changes
    # a published number.
    "gates": ROOT / "benchmarks" / "gates.py",
    # The network prior-art sources and the dedup benchmark that scores them.
    # These are the newest guards in the tree and the ones whose removal is
    # least likely to be noticed by eye: a replay that silently returns an
    # empty body, or an as-of filter that silently keeps everything, both turn
    # a published duplicate rate into a published fiction while every test that
    # does not replay a cassette stays green.
    "pa_cassette": SRC / "gates" / "sources" / "cassette.py",
    "pa_subject": SRC / "gates" / "sources" / "subject.py",
    "pa_asof": SRC / "gates" / "sources" / "asof.py",
    "pa_osv": SRC / "gates" / "sources" / "osv.py",
    "pa_ghsa": SRC / "gates" / "sources" / "ghsa.py",
    "pa_nvd": SRC / "gates" / "sources" / "nvd.py",
    "dedup_interval": ROOT / "benchmarks" / "dedup" / "interval.py",
    "dedup_run": ROOT / "benchmarks" / "dedup" / "run_dedup.py",
    # The command line. Its guards are the exit-code contract itself, which is
    # the one part of this repository whose removal is invisible from inside a
    # Python session: a refusal that starts exiting 2, or a crash that starts
    # exiting 3, changes nothing a library test would notice and changes
    # everything a shell script wrapping the tool would conclude. One target per
    # module, because a mutation pattern has to match exactly once in the file
    # it is applied to.
    "cli_exits": SRC / "cli" / "exits.py",
    "cli_commands": SRC / "cli" / "commands.py",
    "cli_render": SRC / "cli" / "render.py",
    "cli_plan": SRC / "cli" / "plan.py",
    "cli_selftest": SRC / "cli" / "selftest.py",
    "cli_rules": SRC / "cli" / "rules.py",
}


@dataclass(frozen=True)
class Mutation:
    target: str
    label: str
    pattern: str
    replacement: str
    #: When set, the replacement is derived from the matched text instead.
    derive: Callable[[str], str] | None = None
    #: Python targets get their mutant compiled first (defect 2). A markdown
    #: target has no syntax to break, so compiling it would report every
    #: mutation as stale. Defect 4.
    is_python: bool = True


MUTATIONS: list[Mutation] = [
    # ------------------------------------------------------------- controls/run
    Mutation(
        "controls",
        "liveness-confounded voids",
        r"if self\._liveness is Outcome\.CONFOUNDED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "liveness-refused voids",
        r"if self\._liveness is Outcome\.REFUSED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "honest-control-executed voids",
        r"if self\._honest is Outcome\.EXECUTED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "honest-control-confounded voids (defect 9)",
        r"if self\._honest is Outcome\.CONFOUNDED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "an executed test arm yields CANDIDATE",
        r"if executed:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "every arm confounded is CONFOUNDED, not INCONCLUSIVE",
        r"if confounded and len\(confounded\) == len\(tests\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "a confounded test arm denies KILL",
        # Matches only the bare branch: the all-arms branch reads
        # ``if confounded and ...``, with no colon after the name.
        r"if confounded:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "no test arms yields NO-TESTS",
        r"if not tests:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "a named failure reason marks the arm confounded",
        r'if reason != "other":',
        "if False:  # MUTATED",
    ),
    Mutation(
        "controls",
        "test arms are filtered by role",
        r"tests = \[a for a in self\.arms if a\.role is Role\.TEST\]",
        "tests = list(self.arms)  # MUTATED",
    ),
    Mutation(
        "controls",
        "the confound table is anchored on word boundaries",
        r'"credential-expired":[^\n]*',
        "",
        derive=lambda matched: matched.replace("\\b", ""),
    ),
    Mutation(
        "controls",
        "tool-unavailable is disambiguated from precondition-missing (defect 10)",
        r"no such \(\?\!tool",
        "no such (?!xxxx",
    ),
    # -------------------------------------------------------------- rails/scope
    Mutation(
        "scope",
        "out-of-scope beats in-scope",
        r"for entry in self\.scope\.out_of_scope:",
        "for entry in ():  # MUTATED",
    ),
    Mutation(
        "scope",
        "an empty allowlist denies everything",
        r"if not self\.scope\.in_scope:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "the wildcard is a prefix, not a character set (defect 1)",
        r'\.removeprefix\(_WILDCARD\)\.strip\("\."\)',
        '.lstrip("*.").strip(".")  # MUTATED',
    ),
    Mutation(
        "scope",
        "subdomains require the explicit flag",
        r"allow_subdomains and host\.endswith",
        "host.endswith",
    ),
    Mutation(
        "scope",
        "a stale scope file is untrusted (defect 2)",
        r"if age > self\.max_age_days:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "a null last_verified is unverified",
        r"if self\.last_verified is None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "a future last_verified is unverified",
        r"if age < 0:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "assert_in_scope refuses an untrusted scope file",
        r"if not decision\.trusted:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "loopback requires an explicit declaration (defect 3)",
        r"if self\.scope\.allow_loopback and _is_loopback\(host\):",
        "if _is_loopback(host):  # MUTATED",
    ),
    Mutation(
        "scope",
        "unknown top-level config keys are refused (defect 5)",
        r"unknown = sorted\(set\(raw\) - known\)\n        if unknown:",
        "unknown = sorted(set(raw) - known)\n        if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "unknown scope-entry keys are refused",
        r'unknown = sorted\(set\(item\) - \{"host", "allow_subdomains", "notes"\}\)\n'
        r"        if unknown:",
        'unknown = sorted(set(item) - {"host", "allow_subdomains", "notes"})\n'
        "        if False:  # MUTATED",
    ),
    Mutation(
        "scope",
        "a malformed host entry is refused by the schema",
        # The trailing comma is part of the pattern on purpose: without it the
        # "# MUTATED" comment swallowed the comma and the file stopped parsing,
        # which made the mutation look pinned when nothing had run. Defect 2.
        r"host=_validate_host\(host, where\),",
        'host=host.strip().lower().rstrip("."),  # MUTATED',
    ),
    Mutation(
        "scope",
        "a required key cannot be omitted",
        r'for required in \("last_verified", "in_scope"\):',
        "for required in ():  # MUTATED",
    ),
    # ------------------------------------------------------------ rails/payload
    Mutation(
        "payload",
        "a forbidden range is refused for a payload host",
        r"    for ip in sorted\(candidates, key=str\):\n"
        r"        forbidden = _forbidden_reason\(ip\)",
        "    for ip in ():  # MUTATED\n        forbidden = _forbidden_reason(ip)",
    ),
    Mutation(
        "payload",
        "a forbidden range cannot be declared as owned",
        r"\n    forbidden = _forbidden_reason\(ip\)\n    if forbidden:",
        "\n    forbidden = _forbidden_reason(ip)\n    if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "every reading of an ambiguous host must be declared (defect 4)",
        r"if undeclared:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "an undecodable host fails closed",
        r"if not candidates:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "a loopback name is refused",
        r"if host in _LOOPBACK_NAMES:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "a zero-padded octet keeps its octal reading",
        r"values\.add\(int\(text, 8\)\)",
        "pass  # MUTATED",
    ),
    Mutation(
        "payload",
        "IPv4-mapped IPv6 is unwrapped (defect 1)",
        r"if v6\.ipv4_mapped is not None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "6to4 is unwrapped (defect 2)",
        r"if v6\.sixtofour is not None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "the ::/96 unwrap excludes 0.0.0.0/8 so ::1 stays loopback",
        r"if \(prefix_is_compat or prefix_is_nat64\) and low32 >> 24:",
        "if prefix_is_compat or prefix_is_nat64:  # MUTATED",
    ),
    Mutation(
        "payload",
        "multicast is classified before is_global is consulted",
        r"if ip\.is_multicast:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "a non-global address is refused",
        r"if not ip\.is_global:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "documentation space is exempt from the non-global refusal",
        r"if any\(ip in net for net in _DOC_NETS\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "a malformed URL host is UNPARSEABLE, not merely undeclared",
        r"if not _HOST_CHARS\.match\(host\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "assert_own_payload_host raises on a refusal",
        r"if not decision\.permitted:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "payload",
        "a declared hostname must be a bare hostname",
        r"if not value or not _HOSTNAME\.match\(value\):",
        "if False:  # MUTATED",
    ),
    # ----------------------------------------------------------- gates/priorart
    Mutation(
        "priorart",
        "UNGATED is never admissible (failure mode 5)",
        r"if self\.verdict is PriorArtVerdict\.UNGATED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a verdict older than the window is invalid (failure mode 4)",
        r"elif age > window:",
        "elif False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "an estimated count invalidates the verdict (failure mode 3)",
        r"if estimated:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a stale query record invalidates the verdict (failure mode 7)",
        r"elif query_age > window:",
        "elif False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a query retrieved after the assessment invalidates it",
        r"if q\.retrieved > self\.assessed_at:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a backwards clock invalidates the verdict",
        r"if age < dt\.timedelta\(0\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "only CLEAR clears promotion",
        r"return self\.is_clear and self\.validity\(now, window\)\.valid",
        "return self.validity(now, window).valid  # MUTATED",
    ),
    Mutation(
        "priorart",
        "coverage confidence is capped (failure mode 6)",
        r"return min\(COVERAGE_CONFIDENCE_CAP, answered \* COVERAGE_CONFIDENCE_CAP\)",
        "return answered  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a single-source verdict carries its warning (failure mode 2)",
        r"if len\(self\.sources_answered\) == 1:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a source returning no records has not answered",
        r"if not produced:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "no answering source yields UNGATED",
        r"if not answered:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a misattributed query record is fatal",
        r"if record\.source != name:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "assert_gated refuses a verdict that is not CLEAR",
        r"if not assessment\.is_clear:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "assert_gated refuses an inadmissible CLEAR verdict",
        r"if not validity\.valid:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a query record must be auditable",
        r'for name in \("query", "source", "url"\):',
        "for name in ():  # MUTATED",
    ),
    Mutation(
        "priorart",
        "a naive timestamp is refused",
        r"if value\.tzinfo is None or value\.tzinfo\.utcoffset\(value\) is None:",
        "if False:  # MUTATED",
    ),
    # ----------------------------------------------------------------- gates/fp
    Mutation(
        "fp",
        "run_gate does not short-circuit",
        r"        results\.append\(result\)\n    return GateReport",
        "        results.append(result)\n"
        "        if result.state is CheckState.FAILED:  # MUTATED\n"
        "            break\n"
        "    return GateReport",
    ),
    Mutation(
        "fp",
        "a check that raises counts as FAILED",
        r"        except Exception as exc:",
        "        except KeyboardInterrupt as exc:  # MUTATED",
    ),
    Mutation(
        "fp",
        "a check returning the wrong type counts as FAILED",
        r"if not isinstance\(result, FPGateResult\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "clean requires at least one mode to have passed",
        r"return self\.n_failed == 0 and self\.n_passed > 0",
        "return self.n_failed == 0  # MUTATED",
    ),
    Mutation(
        "fp",
        "a suppression with no reason does not suppress",
        r"        if reason:",
        "        if mode.name in gi.suppressed:  # MUTATED",
    ),
    Mutation(
        "fp",
        "an undeclared claim set fails every claim-scoped mode",
        r"if asserts is None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "an unasserted claim is NOT-APPLICABLE, not PASSED",
        r"if not asserts:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "the own-input echo check is case-insensitive",
        r"if needle in gi\.request_bytes or "
        r"needle\.casefold\(\) in gi\.request_bytes\.casefold\(\):",
        "if needle in gi.request_bytes:  # MUTATED",
    ),
    Mutation(
        "fp",
        "a non-2xx is a rejection, not a disclosure (FP#1)",
        r"if not 200 <= gi\.response_status < 300:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "a normalised differential that is identical has no oracle (FP#2)",
        r"    if a == b:",
        "    if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "refusal text around a match is detected (FP#3)",
        r"hit = next\(\(m for m in REFUSAL_MARKERS if m in lowered\), None\)",
        "hit = None  # MUTATED",
    ),
    Mutation(
        "fp",
        "a placeholder-shaped secret is detected",
        r"hit = next\(\(p\.pattern for p in _PLACEHOLDER if p\.search\(value\)\), None\)",
        "hit = None  # MUTATED",
    ),
    Mutation(
        "fp",
        "the oracle strength floor is enforced (rule A10)",
        r"if strength < STRENGTH_FLOOR:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "fp",
        "an unscored oracle fails as unscored",
        r"    if strength is None:\n        return _no\(",
        "    if False:  # MUTATED\n        return _no(",
    ),
    Mutation(
        "fp",
        "suppressing an unknown mode fails loudly",
        r"    if unknown:\n        raise ValueError",
        "    if False:  # MUTATED\n        raise ValueError",
    ),
    Mutation(
        "fp",
        "a differing one-field count is required of the control",
        r"if gi\.treatment_control_differing_fields != 1:",
        "if False:  # MUTATED",
    ),
    # ------------------------------------------------------------------- ledger
    Mutation(
        "ledger",
        "a negative row with no results artifact is refused",
        r'if not str\(row\.results_artifact or ""\)\.strip\(\):',
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a negative row with no assumption is refused",
        r'\n            if not str\(row\.assumption or ""\)\.strip\(\):',
        "\n            if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "the absence-asserting band drives both requirements",
        r"        if row\.asserts_absence:\n",
        "        if False:  # MUTATED\n",
    ),
    Mutation(
        "ledger",
        "a row carries a named oracle and subject",
        r'for name in \("id", "subject", "oracle"\):',
        "for name in ():  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a duplicate row id is refused",
        r"if row\.id in ids:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a dangling supersedes pointer is refused",
        r"if row\.supersedes not in ids:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a row cannot supersede itself",
        r"if row\.supersedes == row\.id:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a control reading is required",
        r"if not isinstance\(row\.control, ControlReading\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a naive recorded timestamp is refused",
        r"if row\.recorded\.tzinfo is None or "
        r"row\.recorded\.tzinfo\.utcoffset\(row\.recorded\) is None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "an empty denominator yields no rate, not 100% (item 5)",
        r"if denominator <= 0:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "ledger",
        "a control counts only when passing AND independent (item 3)",
        r"return self\.passed is True and self\.independent is True",
        "return self.passed is True  # MUTATED",
    ),
    Mutation(
        "ledger",
        "an unscored oracle is inadmissible, not unknown",
        r"oracle_admissible = strength is not None and strength >= MIN_ADMISSIBLE_STRENGTH",
        "oracle_admissible = strength is None or strength >= MIN_ADMISSIBLE_STRENGTH  # MUTATED",
    ),
    Mutation(
        "ledger",
        "the audit checks the named artifact is actually on disk (item 1)",
        r"artifact_exists = \(base / named\)\.exists\(\)",
        "artifact_exists = True  # MUTATED",
    ),
    Mutation(
        "ledger",
        "an uncited claim is counted (item 4)",
        r"uncited = tuple\(c\.text for c in row\.claims if not c\.cited\)",
        "uncited = ()  # MUTATED",
    ),
    Mutation(
        "ledger",
        "an unknown verdict on disk fails loudly",
        r"        except ValueError as exc:\n            raise LedgerError\(\n",
        "        except KeyboardInterrupt as exc:  # MUTATED\n            raise LedgerError(\n",
    ),
    Mutation(
        "ledger",
        "a corrupt line fails loudly rather than reading as no rows",
        r'raise LedgerError\(f"\{where\}: not valid JSON \(\{exc\}\)"\) from exc',
        "continue  # MUTATED",
    ),
    # ---------------------------------------------------------- benchmarks/gates
    #
    # Each of these is a repair made after an external critique, with the case
    # that forced it named. The replacement is the *previous* behaviour wherever
    # that is expressible, so the mutation reproduces the exact defect the
    # reviewer found rather than merely breaking something.
    Mutation(
        "gates",
        "A3 normalises key names, not only values (critic c01)",
        r"return tuple\(sorted\(_strip_supplied\(str\(k\), supplied\)"
        r" for k in \(body or \{\}\)\)\)",
        "return tuple(sorted(str(k) for k in (body or {})))  # MUTATED",
    ),
    Mutation(
        "gates",
        "host comparison is case-insensitive, because DNS is (critic c02)",
        r'return str\(value or ""\)\.strip\(\)\.rstrip\("\."\)\.lower\(\)',
        'return str(value or "").strip().rstrip(".")  # MUTATED',
    ),
    Mutation(
        "gates",
        "shared containment is derived from the recorded egress allowlist (void09)",
        r"if allowlist and control and treatment:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "application-layer reachability is derived from the probe record (void08)",
        r"    if records:\n        return any",
        "    if False:  # MUTATED\n        return any",
    ),
    Mutation(
        "gates",
        "control staleness is derived from the run's own time window (void08)",
        r"if started and ended and stamps:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "the scanned artifact is derived from the detector's invocation (ext17)",
        r"        if opened:",
        "        if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "untested branch fields are derived from two separate records (scope13)",
        r"if branch_fields is not None and values is not None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "a positive control claiming to have run must record its observable (critic c05)",
        r'for key in \("expected_observable", "observed"\):',
        "for key in ():  # MUTATED",
    ),
    Mutation(
        "gates",
        "a positive control that names no observable is VOID (critic c05)",
        r"if not expected\.strip\(\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "the covering-array bound is computed from the factor model (self15)",
        r"if isinstance\(factors, dict\) and factors:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "gates",
        "a hard wrap must be inside a paragraph (critic c06)",
        r"if prose\[i\] and prose\[i \+ 1\] and len\(lines\[i\]\) < width",
        "if lines[i].strip() and lines[i + 1].strip() and len(lines[i]) < width  # MUTATED",
    ),
    Mutation(
        "gates",
        "a 4xx cannot carry a disclosure verdict (FP#1, rule A2)",
        r'bad = \[a\["label"\] for a in arms if 400 <= a\["response"\]\["status"\] < 500\]',
        "bad = []  # MUTATED",
    ),
    Mutation(
        "gates",
        "every refusal span is subtracted before an occurrence counts (FP#3, rule A6)",
        r"outside = \[o for o in occurrences if not any\(lo <= o < hi for lo, hi in spans\)\]",
        "outside = list(occurrences)  # MUTATED",
    ),
    Mutation(
        "gates",
        "a hit must land in a receiving field, not a configured one (FP#5, rule A4)",
        r"    if not receiving:",
        "    if False:  # MUTATED",
    ),
    # ------------------------------------------------- gates/sources/cassette
    Mutation(
        "pa_cassette",
        "a replay miss raises instead of reaching the network (failure mode 1)",
        r"if self\.mode is FetchMode\.REPLAY:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "a hand-written recording is not evidence (failure mode 3)",
        r"if hit\.provenance != RECORDED and not self\.allow_synthetic:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "a non-2xx response is not a row count (failure mode 5)",
        r"if not self\.ok:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "only https is fetched (failure mode 6)",
        r'if parts\.scheme != "https":',
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "an IP-literal host is refused (failure mode 6)",
        r"if re\.fullmatch\(",
        "if False and re.fullmatch(",
    ),
    Mutation(
        "pa_cassette",
        "a credential embedded in the URL is refused",
        r"if not host or parts\.username or parts\.password:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "calls to one host are spaced (failure mode 5)",
        r"if remaining > 0:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "the scrub runs on the body being written (failure mode 4)",
        r"body=scrub_body\(recording\.body\),",
        "body=recording.body,  # MUTATED",
    ),
    Mutation(
        "pa_cassette",
        "scrub_body refuses a body the scrub turned into invalid JSON",
        r"        raise PriorArtError\(\n"
        r'            "the scrub turned a parseable body into invalid JSON',
        "        return scrubbed  # MUTATED\n        raise PriorArtError(\n"
        '            "the scrub turned a parseable body into invalid JSON',
    ),
    # -------------------------------------------------- gates/sources/subject
    Mutation(
        "pa_subject",
        "prose is not queryable (failure mode 1)",
        r"return bool\(self\.advisory_ids\) or bool\(self\.package\)",
        "return True  # MUTATED",
    ),
    Mutation(
        "pa_subject",
        "an unknown ecosystem is refused, not passed through (failure mode 2)",
        r"return ECOSYSTEMS\[raw\.lower\(\)\]",
        "return ECOSYSTEMS.get(raw.lower(), raw)  # MUTATED",
    ),
    Mutation(
        "pa_subject",
        "an empty subject is refused",
        r"if not isinstance\(subject, str\) or not subject\.strip\(\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_subject",
        "a colon that is not an ecosystem is not a package (failure mode 2)",
        r"if candidate is None:",
        "if False:  # MUTATED",
    ),
    # ----------------------------------------------------- gates/sources/asof
    Mutation(
        "pa_asof",
        "a record published after the cutoff is dropped",
        r"return stamp <= self\.cutoff, False",
        "return True, False  # MUTATED",
    ),
    Mutation(
        "pa_asof",
        "an undated record is counted rather than dropped (failure mode 2)",
        r"            return True, True\n",
        "            return False, True  # MUTATED\n",
    ),
    Mutation(
        "pa_asof",
        "a naive cutoff is refused (failure mode 3)",
        r"if self\.cutoff\.tzinfo is None or self\.cutoff\.tzinfo"
        r"\.utcoffset\(self\.cutoff\) is None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_asof",
        "the as-of filter reads published, not modified (failure mode 1)",
        r'def filter\(self, records: list\[dict\], field: str = "published"\)',
        'def filter(self, records: list[dict], field: str = "modified")',
    ),
    # ------------------------------------------------------ gates/sources/osv
    Mutation(
        "pa_osv",
        "a 404 is a measured zero, not an error (failure mode 1)",
        r"if recording\.status == 404:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_osv",
        "an unexhausted page token makes the count an estimate (failure mode 2)",
        r"basis = CountBasis\.ESTIMATED if token else CountBasis\.MEASURED",
        "basis = CountBasis.MEASURED  # MUTATED",
    ),
    Mutation(
        "pa_osv",
        "one advisory arriving twice is counted once (failure mode 4)",
        r'seen\.setdefault\(str\(vuln\["id"\]\), vuln\)',
        "seen.setdefault(str(len(seen)), vuln)  # MUTATED",
    ),
    # ----------------------------------------------------- gates/sources/ghsa
    Mutation(
        "pa_ghsa",
        "a GraphQL error is not a row count of zero (failure mode 1)",
        r'if payload\.get\("errors"\):',
        "if False:  # MUTATED",
    ),
    Mutation(
        "pa_ghsa",
        "a truncated connection is an estimate (failure mode 2)",
        r'if not info\.get\("hasNextPage"\):',
        "if True:  # MUTATED",
    ),
    Mutation(
        "pa_ghsa",
        "a truncated package connection is an estimate too (failure mode 2)",
        r"CountBasis\.ESTIMATED if has_next else CountBasis\.MEASURED",
        "CountBasis.MEASURED,  # MUTATED",
    ),
    Mutation(
        "pa_ghsa",
        "the package-granularity gap travels with the row count",
        r'f"PACKAGE GRANULARITY: version \{parsed\.version\} was NOT matched by this source, so "',
        'f"matched version {parsed.version}, "  # MUTATED',
    ),
    # ------------------------------------------------------ gates/sources/nvd
    Mutation(
        "pa_nvd",
        "an identifier NVD does not carry is declined, not answered zero",
        r'cves = \[i for i in parsed\.advisory_ids if i\.upper\(\)\.startswith\("CVE-"\)\]',
        "cves = list(parsed.advisory_ids)  # MUTATED",
    ),
    Mutation(
        "pa_nvd",
        "a rejected CVE is counted, not subtracted (failure mode 2)",
        r"rejected \+= 1  # failure mode 2: counted, not subtracted",
        "continue  # MUTATED",
    ),
    Mutation(
        "pa_nvd",
        "a truncated result set is an estimate (failure mode 3)",
        r"truncated = isinstance\(total, int\) and total > start \+ per_page",
        "truncated = False  # MUTATED",
    ),
    # ----------------------------------------------- benchmarks/dedup/interval
    Mutation(
        "dedup_interval",
        "a rate with no denominator is None, not zero (failure mode 3)",
        r"if total <= 0:\n        return None",
        "if False:  # MUTATED\n        return None",
    ),
    Mutation(
        "dedup_interval",
        "the interval is two-sided at the stated confidence",
        r"alpha = \(1\.0 - confidence\) / 2\.0",
        "alpha = 1.0 - confidence  # MUTATED",
    ),
    Mutation(
        "dedup_interval",
        "an impossible proportion is refused",
        r"if not 0 <= successes <= total:",
        "if False:  # MUTATED",
    ),
    # -------------------------------------------- benchmarks/dedup/run_dedup
    Mutation(
        "dedup_run",
        "UNGATED is neither a catch nor a false alarm",
        r'return "ungated-positive" if label == "duplicate" else "ungated-negative"',
        'return "tp" if label == "duplicate" else "tn"  # MUTATED',
    ),
    Mutation(
        "dedup_run",
        "only CROWDED or SATURATED count as a duplicate call",
        r"FLAGGED = \(PriorArtVerdict\.CROWDED, PriorArtVerdict\.SATURATED\)",
        "FLAGGED = (PriorArtVerdict.CROWDED, PriorArtVerdict.SATURATED, PriorArtVerdict.CLEAR)",
    ),
    Mutation(
        "dedup_run",
        "an UNGATED duplicate stays in the recall denominator",
        r'positives = counts\["tp"\] \+ counts\["fn"\] \+ counts\["ungated-positive"\]',
        'positives = counts["tp"] + counts["fn"]  # MUTATED',
    ),
    # ------------------------------------------------------------- cli/exits.py
    Mutation(
        "cli_exits",
        "a refusal exits 3 and never 2",
        r"Refused: Exit\.REFUSED,",
        "Refused: Exit.TOOL_FAILURE,  # MUTATED",
    ),
    Mutation(
        "cli_exits",
        "an inability to measure exits 2 and never 3",
        r"CannotMeasure: Exit\.TOOL_FAILURE,",
        "CannotMeasure: Exit.REFUSED,  # MUTATED",
    ),
    Mutation(
        "cli_exits",
        "a draft exits 4",
        r"NotPromoted: Exit\.NOT_PROMOTED,",
        "NotPromoted: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_exits",
        "an undeclared outcome is a tool failure, never a success",
        r"return EXIT_FOR\.get\(type\(exc\), Exit\.TOOL_FAILURE\)",
        "return EXIT_FOR.get(type(exc), Exit.OK)  # MUTATED",
    ),
    # ---------------------------------------------------------- cli/commands.py
    Mutation(
        "cli_commands",
        "an unhandled exception renders as a tool failure",
        r"            code=Exit\.TOOL_FAILURE,",
        "            code=Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "a mis-invocation is a tool failure, not a success",
        r"return int\(Exit\.TOOL_FAILURE\)",
        "return int(Exit.OK)  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "VOID refuses rather than passing",
        r"Verdict\.VOID: Exit\.REFUSED,",
        "Verdict.VOID: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "CONFOUNDED refuses rather than passing",
        r"Verdict\.CONFOUNDED: Exit\.REFUSED,",
        "Verdict.CONFOUNDED: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "INCONCLUSIVE refuses rather than passing",
        r"Verdict\.INCONCLUSIVE: Exit\.REFUSED,",
        "Verdict.INCONCLUSIVE: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "NO-TESTS refuses rather than passing",
        r"Verdict\.NO_TESTS: Exit\.REFUSED,",
        "Verdict.NO_TESTS: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "CANDIDATE is a draft, not a result",
        r"Verdict\.CANDIDATE: Exit\.NOT_PROMOTED,",
        "Verdict.CANDIDATE: Exit.OK,  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "a BLOCKED target refuses",
        r"if decision\.verdict is ScopeVerdict\.BLOCKED:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "--refuse-untrusted reaches assert_in_scope",
        r"if ns\.refuse_untrusted and not decision\.trusted:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "an unreadable scope file is a tool failure, not a denial",
        r'raise CannotMeasure\(str\(exc\), verdict="UNREADABLE-SCOPE"\) from exc',
        'raise Refused(str(exc), verdict="UNREADABLE-SCOPE") from exc  # MUTATED',
    ),
    Mutation(
        "cli_commands",
        "scope verify refuses with no cited source",
        r"if not citation:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "scope verify refuses a source that is not a citation",
        r"if not _is_a_citation\(citation\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "an unscored oracle kind is refused as unscored",
        # Matched on the guard alone, not on the guard plus the statement that
        # follows it. The previous pattern spanned both and went stale the moment
        # a comment was inserted between them, which is how a mutation silently
        # stops applying while the sweep still reports the guard as pinned.
        "    if strength is None:",
        "    if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "an oracle below the strength floor is refused",
        r"if strength < STRENGTH_FLOOR:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "audit ledger defaults its root to the ledger's own directory",
        r"root = ns\.root or str\(Path\(ns\.ledger\)\.parent\)",
        "root = ns.root  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "audit rules cannot measure, and that is not a refusal",
        'raise CannotMeasure\\(\n        "the declared-to-enforced ratio cannot be derived',
        'raise Refused(  # MUTATED\n        "the declared-to-enforced ratio cannot be derived',
    ),
    Mutation(
        "cli_commands",
        "a drifted selftest is a tool failure",
        r"if report\.drifted:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_commands",
        "a tristate flag refuses a word that is neither true nor false",
        '    raise argparse\\.ArgumentTypeError\\(\n        f"expected true or false',
        "    return False  # MUTATED\n"
        "    raise argparse.ArgumentTypeError(\n"
        '        f"expected true or false',
    ),
    # ------------------------------------------------------------ cli/render.py
    Mutation(
        "cli_render",
        "the greppable verdict line is always printed",
        r'out\.append\(f"verdict: \{emission\.verdict\}  exit: \{int\(emission\.code\)\}"\)',
        'out.append("")  # MUTATED',
    ),
    Mutation(
        "cli_render",
        "a warning reaches stderr",
        r'        print\(f"warning: \{warning\}", file=err\)',
        "        continue  # MUTATED",
    ),
    Mutation(
        "cli_render",
        "the exit code travels in the JSON object",
        r'"exit_code": int\(self\.code\),',
        '"exit_code": 0,  # MUTATED',
    ),
    # -------------------------------------------------------------- cli/plan.py
    Mutation(
        "cli_plan",
        "an inadmissible oracle refuses the plan before any arm fires",
        r"if not plan\.oracle\.admissible:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "an unknown top-level key is refused rather than ignored",
        "unknown = sorted\\(set\\(raw\\) - PLAN_KEYS\\)\n        if unknown:",
        "unknown = sorted(set(raw) - PLAN_KEYS)\n        if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a missing required key is refused rather than defaulted",
        "missing = \\[k for k in _REQUIRED_PLAN_KEYS if k not in raw\\]\n        if missing:",
        "missing = [k for k in _REQUIRED_PLAN_KEYS if k not in raw]\n        if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a null required key is refused rather than defaulted",
        r"if raw\[k\] is None:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "oracle must be an OracleSpec, not None",
        r"if not isinstance\(self\.oracle, OracleSpec\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "control and liveness must be ArmSpecs, not None",
        r"if not isinstance\(getattr\(self, name\), ArmSpec\):",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a call that is not a dotted path is refused",
        r'if ":" not in self\.call:',
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a non-callable attribute is refused",
        r"if not callable\(fn\):",
        "if False:  # MUTATED",
    ),
    # ---------------------------------------------------------- cli/selftest.py
    Mutation(
        "cli_selftest",
        "a mode that fired unexpectedly is drift",
        r"extra = sorted\(\(got - want\)\.elements\(\)\)",
        "extra = []  # MUTATED",
    ),
    Mutation(
        "cli_selftest",
        "a mode that stopped firing is drift",
        r"absent = sorted\(\(want - got\)\.elements\(\)\)",
        "absent = []  # MUTATED",
    ),
    Mutation(
        "cli_selftest",
        "the clean fixture must have gated something, not merely failed nothing",
        r"            clean_report\.clean,",
        "            True,  # MUTATED",
    ),
    Mutation(
        "cli_selftest",
        "a refusal raising the wrong exception type is drift",
        r"if type\(exc\) is not mode\.expected:",
        "if False:  # MUTATED",
    ),
    Mutation(
        "cli_selftest",
        "a refusal raising the wrong reason is drift",
        r"if mode\.fragment not in str\(exc\):",
        "if False:  # MUTATED",
    ),
    # ------------------------------------------------------------- cli/rules.py
    Mutation(
        "cli_rules",
        "a declared-rule count that cannot be parsed refuses to measure",
        "    if not match:\n        raise RulesDerivationError\\(",
        "    if False:  # MUTATED\n        raise RulesDerivationError(",
    ),
    Mutation(
        "cli_rules",
        "an invariants doc with no parseable rows refuses to measure",
        "    if not sections:\n        raise RulesDerivationError\\(",
        "    if False:  # MUTATED\n        raise RulesDerivationError(",
    ),
    Mutation(
        "cli_plan",
        "a blank oracle kind or observable is refused",
        r'for name in \("kind", "observable"\):',
        "for name in ():  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a blank arm name or call is refused",
        r'for name in \("name", "call"\):',
        "for name in ():  # MUTATED",
    ),
    Mutation(
        "cli_plan",
        "a blank plan id or subject is refused",
        r'for name in \("id", "subject"\):',
        "for name in ():  # MUTATED",
    ),
    Mutation(
        "cli_rules",
        "an unreadable artifact refuses to measure rather than counting zero",
        "except OSError as exc:\n        raise RulesDerivationError\\(",
        'except OSError as exc:\n        return ""  # MUTATED\n        raise RulesDerivationError(',
    ),
    Mutation(
        "cli_rules",
        "a library invariant with no mutation entry refuses to measure",
        "    if uncovered:\n        raise RulesDerivationError\\(",
        "    if False:  # MUTATED\n        raise RulesDerivationError(",
    ),
]


#: Defect 3. The README is not a guard and is deliberately not in ``TARGETS``:
#: it carries no control whose removal could be observed, it is not part of the
#: guard census the README itself quotes, and mixing the two tables would make
#: that count wrong. What it carries is every number this project publishes.
FIGURE_TARGETS: dict[str, pathlib.Path] = {
    "readme": ROOT / "README.md",
}


def _already_imported(path: pathlib.Path):
    """The binding module, if the running process has already imported it.

    Under pytest it has: re-executing it would build the whole binding table a
    second time and compare one copy's dataclass against another's.
    """
    for module in list(sys.modules.values()):
        candidate = getattr(module, "__file__", None)
        if candidate and pathlib.Path(candidate) == path and hasattr(module, "BINDINGS"):
            return module
    return None


def figure_mutations() -> list[Mutation]:
    """One mutation per published figure, derived from the binding table.

    Imported from ``tests/test_readme_figures.py`` rather than restated here.
    That file computes each expected value from the committed results it cites
    and keeps the regex that must match the README; a copy of those regexes
    living in this file would drift, and a drifted figure mutation is worse
    than none, because it reports ``STALE`` in a run that nobody reads to the
    end while the figure it was meant to pin stays unpinned.

    ``falsify`` is taken from the same module for the same reason: the mutation
    and the test's own non-vacuity proof have to falsify a figure identically,
    or they are not checking the same thing.
    """
    import importlib.util

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    path = ROOT / "tests" / "test_readme_figures.py"
    module = _already_imported(path)
    if module is None:
        spec = importlib.util.spec_from_file_location("controlarm_published_figures", path)
        if spec is None or spec.loader is None:  # pragma: no cover - a real file has both
            raise RuntimeError(f"cannot load the figure bindings from {path}")
        module = importlib.util.module_from_spec(spec)
        # Registered before execution: the bindings are a dataclass, and
        # ``dataclasses`` resolves a field's annotation through
        # ``sys.modules[cls.__module__]``. An unregistered module makes that
        # lookup raise, which looked like a defect in this tool and was a
        # defect in how it loaded the file.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return [
        Mutation(
            "readme",
            binding.label,
            binding.pattern,
            "",
            derive=module.falsify,
            is_python=False,
        )
        for binding in module.BINDINGS
    ]


def apply_mutation(source: str, mut: Mutation) -> tuple[str | None, str]:
    """Return (mutated source, note). ``None`` means the mutation did not apply.

    Defect 2: a mutation whose replacement leaves the file unparseable proves
    nothing. The suite goes red because nothing can be imported, not because a
    test noticed the missing guard, and every such guard is reported pinned on
    the strength of a syntax error. The mutant is therefore compiled before it
    is written, and a mutant that does not parse is stale rather than applied.
    """
    matches = list(re.finditer(mut.pattern, source))
    if len(matches) != 1:
        return None, f"matched {len(matches)} times, expected 1"
    match = matches[0]
    replacement = mut.derive(match.group(0)) if mut.derive else mut.replacement
    if replacement == match.group(0):
        return None, "replacement is identical to the match, so it proves nothing"
    mutated = source[: match.start()] + replacement + source[match.end() :]
    if mut.is_python:
        try:
            compile(mutated, "<mutant>", "exec")
        except SyntaxError as exc:
            return None, (
                f"the mutated source does not parse ({exc.msg} at line {exc.lineno}), so a red "
                "suite would prove nothing but that the file is broken"
            )
    return mutated, ""


def run_suite() -> tuple[bool, str]:
    """Run the suite. Returns (green, the first failing test name or the summary)."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--no-header",
            "-x",
            "-rf",
            "-p",
            "no:cacheprovider",
            # See the ``pristine`` and ``release`` markers in pyproject.toml.
            # With a mutation in place the tree is deliberately wrong, so a test
            # asserting a property of the pristine tree would go red for every
            # mutation and mask whichever guard actually caught it. ``release``
            # asserts a property of the published world and is red until the
            # repository is pushed, which would make the baseline red and stop
            # the sweep concluding anything.
            #
            # Both markers must be named here. A single ``-m`` on the command
            # line REPLACES the one in ``addopts`` rather than combining with
            # it, so omitting ``release`` silently re-selected it and the sweep
            # reported "BASELINE IS RED" against a test that is expected to fail.
            "-m",
            "not pristine and not release",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    out = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return True, next(
            (ln.strip() for ln in reversed(out.splitlines()) if "passed" in ln), "green"
        )
    failed = next((ln for ln in out.splitlines() if ln.startswith("FAILED ")), "")
    if failed:
        return False, failed.removeprefix("FAILED ").split(" - ")[0].split("::", 1)[-1]
    error = next((ln for ln in out.splitlines() if ln.startswith("ERROR ")), "")
    if error:
        return False, error.strip()
    return False, "red, but no FAILED line could be parsed"


def digest(text: str) -> str:
    """The sha256 this tool compares file states with. Newlines are not
    normalised: a tool that normalised them could not tell a real edit from its
    own write-back on a platform that rewrites line endings."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ConcurrentModification(Exception):
    """Another process wrote to a target while a mutation was in place.

    Defect 1. Restoring here would overwrite that edit with content the tool
    captured minutes earlier, and the edit would be gone with nothing in the
    output to say so. So this is raised instead, the would-be restore content is
    written beside the target, and the run exits non-zero.
    """


def restore_or_refuse(path: pathlib.Path, wrote: str, original: str, baseline: str) -> None:
    """Put ``original`` back, unless somebody else changed the file meanwhile.

    ``wrote`` is the exact mutated content this tool last wrote. If what is on
    disk does not hash to that, the file is not ours to restore.

    ``baseline`` is the digest of the pristine file captured at the start of the
    run; after restoring, what is on disk must hash to it. Writing ``original``
    and ending up with something else means the write itself was raced, and that
    is also a refusal rather than a shrug.
    """
    on_disk = path.read_text(encoding="utf-8")
    if digest(on_disk) != digest(wrote):
        backup = path.with_suffix(path.suffix + ".orig.bak")
        backup.write_text(original, encoding="utf-8")
        raise ConcurrentModification(
            f"{path} changed on disk while a mutation was in place.\n"
            f"  expected (what this tool wrote): {digest(wrote)}\n"
            f"  found    (what is there now):    {digest(on_disk)}\n"
            f"  NOT RESTORING. The pristine content this tool captured at the start of the "
            f"run has been written to {backup} instead, so nothing is lost and nothing of "
            f"yours is overwritten. Reconcile the two by hand, delete the .orig.bak, and "
            f"re-run."
        )
    path.write_text(original, encoding="utf-8")
    after = path.read_text(encoding="utf-8")
    if digest(after) != baseline:
        backup = path.with_suffix(path.suffix + ".orig.bak")
        backup.write_text(original, encoding="utf-8")
        raise ConcurrentModification(
            f"{path} was restored and does not match the baseline captured at the start of "
            f"the run.\n"
            f"  baseline: {baseline}\n"
            f"  restored: {digest(after)}\n"
            f"  The restoring write was itself raced. The captured pristine content is in "
            f"{backup}."
        )


def main(
    argv: list[str],
    *,
    targets: dict[str, pathlib.Path] | None = None,
    mutations: list[Mutation] | None = None,
) -> int:
    """Exit 0 all pinned, 1 something unpinned or stale, 2 baseline red or bad
    arguments, 3 a target was modified by another process mid-run.

    ``targets`` and ``mutations`` are injectable so the tool's own tests can
    exercise it against a temporary file rather than against the repository.

    ``--figures`` switches both tables to the README's published figures
    (defect 3). It is a separate run rather than an extra target, so that a
    plain invocation still reports the guard count the README quotes.
    """
    flags = [arg for arg in argv[1:] if arg.startswith("-")]
    unknown_flags = [flag for flag in flags if flag != "--figures"]
    if unknown_flags:
        print(f"unknown flag(s) {unknown_flags}; known: ['--figures']")
        return 2
    figures = "--figures" in flags

    if figures and targets is None and mutations is None:
        table = dict(FIGURE_TARGETS)
        all_mutations = figure_mutations()
        noun = "published figures"
    else:
        table = dict(targets) if targets is not None else TARGETS
        all_mutations = list(mutations) if mutations is not None else MUTATIONS
        noun = "guards"

    selected = {arg for arg in argv[1:] if not arg.startswith("-")} or set(table)
    unknown = sorted(selected - set(table))
    if unknown:
        print(f"unknown target(s) {unknown}; known: {sorted(table)}")
        return 2
    chosen = [m for m in all_mutations if m.target in selected]

    originals = {name: path.read_text(encoding="utf-8") for name, path in table.items()}
    baselines = {name: digest(text) for name, text in originals.items()}

    green, baseline = run_suite()
    if not green:
        print(f"BASELINE IS RED, so nothing can be concluded: {baseline}")
        return 2
    print(f"baseline: {baseline}\n")

    unpinned: list[str] = []
    current = ""
    for mut in chosen:
        if mut.target != current:
            current = mut.target
            print(f"-- {current} ({_label_for(table[current])})")
        path = table[mut.target]
        mutated, note = apply_mutation(originals[mut.target], mut)
        if mutated is None:
            print(f"  STALE     {mut.label}: {note}")
            unpinned.append(f"{mut.target}/{mut.label} (stale mutation: {note})")
            continue
        path.write_text(mutated, encoding="utf-8")
        try:
            still_green, summary = run_suite()
        finally:
            # Restore before interpreting the result, and refuse rather than
            # clobber. Defect 1.
            try:
                restore_or_refuse(path, mutated, originals[mut.target], baselines[mut.target])
            except ConcurrentModification as exc:
                print(f"\n!! ABORTING: {exc}\n")
                return 3
        if still_green:
            print(f"  UNPINNED  {mut.label}")
            unpinned.append(f"{mut.target}/{mut.label}")
        else:
            print(f"  pinned    {mut.label[:62]:<62}  caught by: {summary[:56]}")

    # Every target must be byte-identical to how the run found it.
    drifted = [
        name
        for name, path in table.items()
        if digest(path.read_text(encoding="utf-8")) != baselines[name]
    ]
    if drifted:
        print(f"\n!! {drifted} do not match the baseline captured at the start of this run.")
        return 3

    print()
    if unpinned:
        print(f"{len(unpinned)} of {len(chosen)} {noun} are UNPINNED or stale:")
        for name in unpinned:
            print(f"  - {name}")
        return 1
    print(f"all {len(chosen)} {noun} are pinned by at least one test")
    return 0


def _label_for(path: pathlib.Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
