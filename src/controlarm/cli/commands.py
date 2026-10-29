"""The command line. Every subcommand is backed by a guard that already exists.

The library refuses things. Until this module existed, every one of those
refusals had to be reached by writing Python, which meant the refusals could not
be put in a shell script, a CI job or a pre-commit hook -- the three places a
rail is actually worth having. A reviewer's judgement was that this made the
project a library rather than a tool, and that the gap between the two was the
command line. This is that gap.

**Nothing here is a stub.** A subcommand exists only where a module under
``src/controlarm`` can actually answer it. The specification this is taken from
lists ``init``, ``phase0``, ``plan new``, ``dedup run``, ``saturation``,
``promote``, ``bundle``, ``lint`` and ``replay`` as well. None of those has code
behind it in this repository, so none of them is here: a subcommand that prints
a plausible-looking nothing is worse than an absent one, because an absent one
cannot be mistaken for a check that ran. ``docs/cli.md`` lists them under what
is deliberately missing, and ``tests/test_cli.py`` asserts the documented set
and the implemented set are the same set in both directions.

The exit-code contract lives in ``exits.py`` and is the point of the whole
thing. Three structural guards here keep it honest, and each is pinned by a test
and by an entry in ``tools/mutate_guards.py``:

  1  a crash reading as a result            -> ``main`` maps anything that is
     not a deliberately constructed outcome to ``TOOL_FAILURE``. The
     ``except Exception`` clause is last, it never returns ``OK``, and it never
     returns ``REFUSED``: a refusal is something a gate decided, not something
     that happened to the interpreter.
  2  a refusal reading as a crash           -> ``Refused`` is caught before the
     general clause and maps to ``3`` only. A wrapper seeing ``3`` knows the
     instrument refused; seeing ``2`` it knows the instrument broke. Collapsing
     them is what ``|| true`` did to the pipeline this is ported from.
  3  a subcommand falling off the end       -> every handler returns an
     ``Emission`` carrying an explicit ``Exit``. There is no default return and
     no implicit ``0``, so "the handler did nothing" is not expressible as
     success.

Library code does not print. ``render.write`` is the only writer in the package,
and the streams are injected so the tests read what a terminal would.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO

from controlarm.cli import clock, render, rules, selftest
from controlarm.cli.exits import CannotMeasure, CliOutcome, Exit, NotPromoted, Refused, exit_for
from controlarm.cli.plan import Plan, PlanError, execute
from controlarm.cli.render import Emission
from controlarm.controls.run import Verdict
from controlarm.gates.fp import ORACLE_STRENGTH, STRENGTH_FLOOR
from controlarm.ledger import (
    Claim,
    ControlReading,
    Ledger,
    LedgerError,
    LedgerRow,
    LedgerVerdict,
    audit,
)
from controlarm.rails.scope import (
    ScopeConfigError,
    ScopeError,
    ScopeFile,
    ScopeGuard,
    ScopeTrust,
    ScopeVerdict,
)

__all__ = ["EXIT_FOR_VERDICT", "build_parser", "main"]

_PROG = "controlarm"

#: The strength caveat ``oracle rate`` must print. GAPS.md G8: the integers are
#: reasoned from mechanism and nothing has measured them, so a tool that printed
#: a bare number would be lending its own heuristic an authority the repository
#: explicitly disclaims. Carried in the JSON as well, so the caveat cannot be
#: dropped by piping the output somewhere.
G8 = (
    "UNVALIDATED SCALE (GAPS.md G8): oracles are scored 0 to 4 and gated at "
    f"{STRENGTH_FLOOR}, and those integers are reasoned from mechanism rather than measured. "
    "Nothing establishes that a strength-2 oracle produces more false verdicts than a "
    "strength-3 one. Treat this classification as a declared convention, not as a measurement."
)

#: ``run``'s verdict lattice mapped onto the contract. The three refusal states
#: and NO-TESTS are refusals (3): the lattice would not let the run count.
#: CANDIDATE is a draft (4): something executed and has not earned a verdict.
#: KILL is the one verdict that is a result, so it alone exits 0.
EXIT_FOR_VERDICT = {
    Verdict.KILL: Exit.OK,
    Verdict.CANDIDATE: Exit.NOT_PROMOTED,
    Verdict.VOID: Exit.REFUSED,
    Verdict.CONFOUNDED: Exit.REFUSED,
    Verdict.INCONCLUSIVE: Exit.REFUSED,
    Verdict.NO_TESTS: Exit.REFUSED,
}


# ================================================================ the subcommands


def _scope_file(path: str) -> ScopeFile:
    """Load the scope file, or fail as a *tool failure* rather than a refusal.

    A malformed scope file is a broken instrument: it says nothing about any
    target, so reporting it as a denial would be reporting a measurement that
    was never taken. ``ScopeConfigError`` therefore becomes ``CannotMeasure``.
    """
    try:
        return ScopeFile.from_path(path)
    except ScopeConfigError as exc:
        raise CannotMeasure(str(exc), verdict="UNREADABLE-SCOPE") from exc


def cmd_scope_check(ns: argparse.Namespace) -> Emission:
    """Report the target rail's decision. Exit 0 in scope, 3 denied."""
    scope = _scope_file(ns.scope)
    today = clock.date(ns.today)
    guard = ScopeGuard(scope, today=today)
    decision = guard.check(ns.url)
    trust, trust_reason = scope.trust_on(today)

    warnings = () if trust is ScopeTrust.VERIFIED else (trust_reason,)
    data = {
        "url": ns.url,
        "host": decision.host,
        "scope_file": scope.source,
        "trust": decision.trust.value,
        "trusted": decision.trusted,
        "is_result": decision.is_result,
        "checked_on": today.isoformat(),
    }
    lines = [
        f"target     {ns.url}",
        f"host       {decision.host}",
        f"scope      {scope.source} (verified {scope.last_verified}, window {scope.max_age_days}d)",
        f"trust      {decision.trust.value}",
    ]

    if decision.verdict is ScopeVerdict.BLOCKED:
        raise Refused(
            decision.reason,
            verdict=ScopeVerdict.BLOCKED.value,
            data=data
            | {
                "lines": lines,
                "warnings": list(warnings),
            },
        )

    if ns.refuse_untrusted and not decision.trusted:
        # The strict path, for a wrapper that must not proceed on a scope
        # nobody reconciled. ``check`` reports and ``assert_in_scope`` refuses;
        # this flag is how a shell script reaches the second one.
        try:
            guard.assert_in_scope(ns.url)
        except ScopeError as exc:
            raise Refused(
                str(exc), verdict="BLOCKED-UNTRUSTED", data=data | {"lines": lines}
            ) from exc

    return Emission(
        command="scope check",
        verdict=ScopeVerdict.IN_SCOPE.value,
        reason=decision.reason,
        code=Exit.OK,
        data=data,
        lines=lines,
        warnings=warnings,
    )


def cmd_scope_verify(ns: argparse.Namespace) -> Emission:
    """Stamp ``last_verified``. Refuses without a cited source.

    The citation is not storable in the scope file -- its schema refuses unknown
    keys, which is the right behaviour and not one to weaken for this -- so it
    goes into a sidecar verification log beside the file, together with the
    digest of the scope file as stamped. A stamp with no record of what it was
    reconciled against is the thing this subcommand exists to refuse, and a
    record that cannot be tied to a particular version of the file is the same
    defect one step removed.
    """
    citation = (ns.source or "").strip()
    if not citation:
        raise Refused(
            "refusing to stamp last_verified with no cited source. The stamp is the file's one "
            "claim about the world; without a citation it asserts that somebody looked, which "
            "is exactly the unaccompanied claim this tool exists to refuse. Pass --source with "
            "the URL of the policy page you reconciled against, or a quoted sentence from it.",
            verdict="REFUSED",
            data={"scope_file": ns.scope},
        )
    if not _is_a_citation(citation):
        raise Refused(
            f"--source {citation!r} is not a citation. It must be a URL with a scheme and a "
            'host, or a quoted sentence ("..."), which is the same standard the ledger applies '
            "to a claim. A word of reassurance is not a source.",
            verdict="REFUSED",
            data={"scope_file": ns.scope, "source": citation},
        )

    scope = _scope_file(ns.scope)
    today = clock.date(ns.today)
    path = Path(ns.scope)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["last_verified"] = today.isoformat()
    text = json.dumps(raw, indent=2, sort_keys=True) + "\n"
    # Re-validate before writing: a stamp that makes the file unloadable would
    # leave the rail unusable and the stamp would be the thing that did it.
    ScopeFile.from_text(text, source=str(path))
    path.write_text(text, encoding="utf-8")

    log = path.with_suffix(path.suffix + ".verification.jsonl")
    entry = {
        "last_verified": today.isoformat(),
        "source": citation,
        "scope_file": str(path),
        "sha256": _digest(text),
    }
    with log.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")

    return Emission(
        command="scope verify",
        verdict="VERIFIED",
        reason=(
            f"stamped last_verified={today.isoformat()} and recorded the citation in {log}. "
            f"The window is {scope.max_age_days} day(s): after that every result from this "
            "scope file is untrusted until it is reconciled again."
        ),
        code=Exit.OK,
        data={**entry, "verification_log": str(log), "max_age_days": scope.max_age_days},
        lines=[
            f"scope      {path}",
            f"stamped    {today.isoformat()}",
            f"source     {citation}",
            f"sha256     {entry['sha256']}",
            f"logged to  {log}",
        ],
    )


def cmd_oracle_rate(ns: argparse.Namespace) -> Emission:
    """The 0-4 strength classification. Exit 3 below the floor, or if unscored."""
    strength = ORACLE_STRENGTH.get(ns.kind)
    data = {
        "kind": ns.kind,
        "strength": strength,
        "floor": STRENGTH_FLOOR,
        "scale_is_validated": False,
        "caveat": G8,
        "known_kinds": sorted(ORACLE_STRENGTH),
    }
    if strength is None:
        # A near miss is almost always a typo, and a typo that reads as a
        # judgement is the defect this project is named after. The exit code is
        # deliberately the same as a real refusal (fail closed), so the reason
        # has to carry the difference; `verdict` and a null `strength` also
        # separate the two cases in --json for an automated caller.
        near = difflib.get_close_matches(ns.kind, sorted(ORACLE_STRENGTH), n=3, cutoff=0.7)
        data["suggestions"] = near
        raise Refused(
            f"oracle kind {ns.kind!r} is not in the strength table, so it is unscored -- which "
            f"is refused, not treated as unknown. An unscored oracle defaulting to acceptable "
            f"is how string co-occurrence carries a verdict."
            + (f" Did you mean {' or '.join(repr(k) for k in near)}?" if near else "")
            + f" Known kinds: "
            f"{sorted(ORACLE_STRENGTH)}\n\n{G8}",
            verdict="UNSCORED",
            # The caveat rides on the refusal too, in the body and on stderr: a
            # reader who only ever sees refusals must still be told that the
            # scale doing the refusing has never been validated.
            data=data | {"warnings": [G8]},
        )
    lines = [f"oracle     {ns.kind}", f"strength   {strength} of 4", f"floor      {STRENGTH_FLOOR}"]
    if strength < STRENGTH_FLOOR:
        raise Refused(
            f"oracle {ns.kind!r} is strength {strength}, below the floor of {STRENGTH_FLOOR}. "
            "Nothing below the floor reaches the operator: it is what stops probe volume from "
            f"becoming noise.\n\n{G8}",
            verdict="INADMISSIBLE",
            data=data | {"lines": lines, "warnings": [G8]},
        )
    return Emission(
        command="oracle rate",
        verdict="ADMISSIBLE",
        reason=f"oracle {ns.kind!r} is strength {strength}, at or above the floor.\n\n{G8}",
        code=Exit.OK,
        data=data,
        lines=lines,
        warnings=(G8,),
    )


def cmd_run(ns: argparse.Namespace) -> Emission:
    """Execute a declared plan and write ``run.json`` with the verdict lattice."""
    try:
        plan = Plan.from_path(ns.plan)
    except OSError as exc:
        raise CannotMeasure(
            f"plan file {ns.plan!r} could not be read ({exc}). Being pointed at nothing is the "
            "instrument breaking, not a gate refusing.",
            verdict="UNREADABLE-PLAN",
        ) from exc
    except PlanError as exc:
        raise Refused(str(exc), verdict="REFUSED", data={"plan": ns.plan}) from exc

    try:
        run = execute(plan)
    except PlanError as exc:
        raise Refused(str(exc), verdict="REFUSED", data={"plan": plan.as_dict()}) from exc

    record = run.verdict(now=clock.stamp(ns.now))
    verdict = Verdict(record["verdict"])
    out = Path(ns.out)
    payload = {"plan": plan.as_dict(), **record}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"plan       {plan.id}  ({plan.source})",
        f"subject    {plan.subject}",
        f"oracle     {plan.oracle.kind} (strength {plan.oracle.strength}) reading "
        f"{plan.oracle.observable}",
        f"written    {out}",
        "",
        "arms:",
    ]
    for arm in record["arms"]:
        lines.append(
            f"  [{_value(arm['outcome']):<10}] {_value(arm['role']):<15} {arm['name']}"
            f"  reason={arm['reason']}  {arm['detail']}"
        )

    code = EXIT_FOR_VERDICT[verdict]
    data = {"run_json": str(out), **payload}
    if code is Exit.REFUSED:
        raise Refused(record["reason"], verdict=verdict.value, data=data | {"lines": lines})
    if code is Exit.NOT_PROMOTED:
        raise NotPromoted(record["reason"], verdict=verdict.value, data=data | {"lines": lines})
    return Emission(
        command="run",
        verdict=verdict.value,
        reason=record["reason"],
        code=code,
        data=data,
        lines=lines,
    )


def cmd_ledger_add(ns: argparse.Namespace) -> Emission:
    """Append one row. A refused row is exit 3; an unreadable store is exit 2."""
    ledger = Ledger(ns.ledger)
    try:
        existing = len(ledger.rows())
    except LedgerError as exc:
        # Read failure and write refusal are both LedgerError, and they are not
        # the same outcome: a corrupt store is a broken instrument.
        raise CannotMeasure(
            f"the ledger could not be read, so nothing can be appended to it: {exc}",
            verdict="UNREADABLE-LEDGER",
        ) from exc

    row = LedgerRow(
        id=ns.id,
        recorded=clock.stamp(ns.now),
        subject=ns.subject,
        verdict=LedgerVerdict(ns.verdict),
        oracle=ns.oracle,
        control=ControlReading(
            name=ns.control_name,
            passed=ns.control_passed,
            independent=ns.control_independent,
            detail=ns.control_detail,
        ),
        results_artifact=ns.artifact,
        assumption=ns.assumption,
        supersedes=ns.supersedes,
        next_axis=ns.next_axis,
        dedup_score=ns.dedup_score,
        claims=tuple(Claim(*_claim(c)) for c in ns.claim),
    )
    try:
        ledger.append(row)
    except LedgerError as exc:
        raise Refused(str(exc), verdict="REFUSED", data={"ledger": str(ledger.path)}) from exc

    return Emission(
        command="ledger add",
        verdict="RECORDED",
        reason=(
            f"row {row.id!r} appended to {ledger.path} in band {row.band.value}. The store is "
            "append-only: an amendment is a new row with a supersedes pointer, never an edit."
        ),
        code=Exit.OK,
        data={"ledger": str(ledger.path), "rows_before": existing, "row": row.as_dict()},
        lines=[
            f"ledger     {ledger.path}",
            f"row        {row.id}",
            f"verdict    {row.verdict.value}  (band {row.band.value})",
            f"oracle     {row.oracle}",
            f"artifact   {row.results_artifact}",
        ],
    )


def cmd_ledger_show(ns: argparse.Namespace) -> Emission:
    """Print the rows. Reports; refuses nothing."""
    ledger = Ledger(ns.ledger)
    try:
        rows = ledger.current_rows() if ns.current else ledger.rows()
    except LedgerError as exc:
        raise CannotMeasure(str(exc), verdict="UNREADABLE-LEDGER") from exc

    lines = [f"ledger     {ledger.path}", f"rows       {len(rows)}"]
    if rows:
        lines.append("")
        lines.append(f"{'row':<18} {'verdict':<13} {'band':<20} oracle")
        for row in rows:
            lines.append(f"{row.id:<18} {row.verdict.value:<13} {row.band.value:<20} {row.oracle}")
    return Emission(
        command="ledger show",
        verdict="LISTED",
        reason=(
            f"{len(rows)} row(s)"
            + (" with superseded rows hidden" if ns.current else " including superseded rows")
        ),
        code=Exit.OK,
        data={"ledger": str(ledger.path), "rows": [r.as_dict() for r in rows]},
        lines=lines,
    )


def cmd_audit_ledger(ns: argparse.Namespace) -> Emission:
    """The three proportions, per row and in total.

    This subcommand **refuses nothing**, and that is deliberate rather than
    lax: a store that rejected every imperfect row would leave an audit that
    only ever saw flattering ones. So a badly-scoring ledger still exits 0 and
    the badness is in the output. The proportions are ``None`` on an empty
    ledger, never ``0/0 == 1.0``, which would be this harness making exactly
    the claim it audits against.
    """
    ledger = Ledger(ns.ledger)
    try:
        rows = ledger.current_rows() if ns.current else ledger.rows()
    except LedgerError as exc:
        raise CannotMeasure(str(exc), verdict="UNREADABLE-LEDGER") from exc

    root = ns.root or str(Path(ns.ledger).parent)
    report = audit(rows, root=root, now=clock.stamp(ns.now))
    lines = report.as_markdown().rstrip("\n").splitlines()
    if ns.out:
        Path(ns.out).write_text(report.as_markdown(), encoding="utf-8")
        lines.append("")
        lines.append(f"written to {ns.out}")
    return Emission(
        command="audit ledger",
        verdict="AUDITED",
        reason=(
            f"{report.n_rows} row(s) audited against {root}. artifact exists: "
            f"{_pct(report.artifact_rate)}; passing independent control: "
            f"{_pct(report.control_rate)}; admissible oracle: "
            f"{_pct(report.admissible_oracle_rate)}; uncited claims: "
            f"{report.uncited_claim_count}. This audit refuses nothing by design."
        ),
        code=Exit.OK,
        data={"ledger": str(ledger.path), "root": root, **report.as_dict()},
        lines=lines,
    )


def cmd_audit_rules(ns: argparse.Namespace) -> Emission:
    """Declared rules against enforced rules, and the refusal to invent a ratio.

    Always exits 2, and the reason is in the output every time. See
    ``rules.py``: the declared rules are not enumerated in this repository, the
    invariants doc counts a different unit, and the two available mappings
    disagree by an order of magnitude. Printing either would be printing a
    coverage number that had never been measured, which is the one thing this
    repository is for refusing. ``--json`` still carries every real count.
    """
    try:
        coverage = rules.derive(ns.repo)
    except rules.RulesDerivationError as exc:
        raise CannotMeasure(str(exc), verdict="UNDERIVABLE", data={"repo": ns.repo}) from exc

    lines = [
        "declared rules (the source methodology)",
        f"  {coverage.declared_rules:>5}   GAPS.md G6, parsed from its own sentence:",
        f"          {coverage.declared_rules_citation}",
        "          NOT enumerated in this repository, so there is no set to subset.",
        "",
        "invariants this repository declares enforced",
        f"  {coverage.invariant_rows:>5}   docs/invariants.md table rows "
        f"({coverage.library_invariant_rows} of them about the library)",
    ]
    for section in coverage.sections:
        where = coverage.section_coverage.get(section.module)
        lines.append(
            f"          {len(section.rows):>3}  {section.module:<32} "
            f"mutation target: {where or 'n/a (tooling)'}"
        )
    lines += [
        "",
        "guards mechanically pinned",
        f"  {coverage.guards:>5}   tools/mutate_guards.py MUTATIONS, each neutered in CI to "
        "prove a test catches its removal",
    ]
    for target, count in coverage.guards_by_target.items():
        lines.append(f"          {count:>3}  {target}")
    lines += [
        "",
        f"library invariant sections under mutation coverage: "
        f"{coverage.sections_covered} of {len(coverage.section_coverage)}",
        f"methodology rule identifiers cited by the shipping library: "
        f"{len(coverage.cited_rule_ids)} "
        f"({', '.join(coverage.cited_rule_ids) or 'none'})",
        "",
        "DECLARED-TO-ENFORCED RATIO: NOT COMPUTED.",
    ]
    for refusal in coverage.refusals:
        lines.append(f"  - {refusal}")
    lines += [
        "",
        "candidate ratios, computed and printed so they can be rejected rather than "
        "quietly not considered. NEITHER IS USABLE:",
        f"  {coverage.candidate_ratio_by_invariant_row:.3f}  library invariant rows over "
        f"declared rules ({coverage.library_invariant_rows}/{coverage.declared_rules})",
        f"  {coverage.candidate_ratio_by_cited_rule_id:.3f}  cited rule identifiers over "
        f"declared rules ({len(coverage.cited_rule_ids)}/{coverage.declared_rules})",
        "  The published honest baseline for this method is roughly 30 of 96. A figure that "
        "can be argued to any of three values by choosing a unit is a rhetorical device.",
    ]
    raise CannotMeasure(
        "the declared-to-enforced ratio cannot be derived from this repository, so it is not "
        "printed. Exit 2, not 0: an instrument that cannot measure has not measured a low "
        "number. Every count above is real and parsed from a committed artifact.",
        verdict="UNDERIVABLE",
        data={"repo": str(ns.repo), **coverage.as_dict(), "lines": lines},
    )


def cmd_selftest(ns: argparse.Namespace) -> Emission:
    """Fire the gates at both fixtures and every refusal mode.

    A non-zero exit here **voids every clean verdict the gates have produced
    since the last passing selftest.** Those runs must be re-run; they are not
    merely suspect. That is the rule that voided two runs in the work this was
    extracted from and it is why the negatives in that ledger can be relied on.
    """
    report = selftest.selftest()
    lines = [
        f"known-bad fixture fired:   {list(report.bad_fired)}",
        f"known-bad fixture expects: {list(selftest.EXPECTED_BAD_FAILURES)}",
        f"known-clean fixture fired: {list(report.clean_fired)}",
        "",
    ]
    for outcome in report.outcomes:
        lines.append(f"  [{'pass' if outcome.passed else 'DRIFT'}] {outcome.name}")
        lines.append(f"         {outcome.detail}")
    data = {"voids_prior_clean_verdicts": report.drifted, **report.as_dict()}
    if report.drifted:
        raise CannotMeasure(
            f"{len(report.failures)} of {len(report.outcomes)} calibration checks DRIFTED. "
            "Every clean verdict these gates have produced since the last passing selftest is "
            "VOID and must be re-run. An instrument that has never been observed to fire "
            "cannot certify a negative, and one observed to fire differently certifies nothing "
            "it certified before.",
            verdict="DRIFTED",
            data=data | {"lines": lines},
        )
    return Emission(
        command="selftest",
        verdict="CALIBRATED",
        reason=(
            f"all {len(report.outcomes)} calibration checks pass: the known-bad fixture fires "
            f"exactly {list(selftest.EXPECTED_BAD_FAILURES)}, the known-clean fixture fires "
            f"nothing and still gated something, and all {len(selftest.REFUSAL_MODES)} refusal "
            "modes raise the right exception with the right reason. A non-zero exit from this "
            "subcommand voids every clean verdict since the last passing run."
        ),
        code=Exit.OK,
        data=data,
        lines=lines,
    )


# ====================================================================== the parser


def _add_output_flags(parser: argparse.ArgumentParser, *, leaf: bool) -> None:
    """``--json`` and ``--human`` on the top level and on every leaf.

    ``SUPPRESS`` on the leaf copies is what makes both positions work: an
    unused leaf flag is absent from the namespace rather than present as
    ``False``, so it cannot overwrite a value given before the subcommand.
    """
    default = argparse.SUPPRESS if leaf else False
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--json",
        dest="json",
        action="store_true",
        default=default,
        help="emit one machine-readable JSON object instead of the human rendering",
    )
    group.add_argument(
        "--human",
        dest="human",
        action="store_true",
        default=default,
        help="emit the human rendering (the default)",
    )


def _leaf(sub: argparse._SubParsersAction, name: str, help_text: str) -> argparse.ArgumentParser:
    parser = sub.add_parser(name, help=help_text, description=help_text)
    _add_output_flags(parser, leaf=True)
    return parser


def build_parser() -> argparse.ArgumentParser:
    """The whole surface. ``argparse`` only: no third-party dependency.

    The core of this package is stdlib-only on purpose. A tool whose job is to
    refuse unsupported claims should not ask you to trust a dependency tree in
    order to do it, and the argument parser is the easiest place to break that
    rule for the smallest gain.
    """
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "A red-team evidence harness. It does not find vulnerabilities: it refuses to let "
            "an unaccompanied claim become a result. Exit 0 success, 2 tool failure (never a "
            "negative result), 3 refused by a gate (the normal outcome, not an error), 4 not "
            "promoted."
        ),
        epilog=(
            "The exit code is the interface. 2 and 3 are different numbers on purpose: 3 means "
            "the instrument refused, 2 means the instrument broke. See docs/cli.md."
        ),
    )
    _add_output_flags(parser, leaf=False)
    top = parser.add_subparsers(dest="group", metavar="<group>")

    # ------------------------------------------------------------------- scope
    scope = top.add_parser("scope", help="the target rail: deny by default")
    scope_sub = scope.add_subparsers(dest="action", metavar="<action>")

    check = _leaf(scope_sub, "check", "Is this target in scope? Exit 0 in scope, 3 denied.")
    check.add_argument("url", help="a URL or a bare host")
    check.add_argument("--scope", default="scope.json", help="path to the scope file")
    check.add_argument(
        "--refuse-untrusted",
        action="store_true",
        help=(
            "exit 3 when the scope file is stale or unverified, instead of exiting 0 with a "
            "warning. This routes through assert_in_scope, which has no override."
        ),
    )
    check.add_argument("--today", type=dt.date.fromisoformat, default=None, help=argparse.SUPPRESS)
    check.set_defaults(handler=cmd_scope_check)

    verify = _leaf(
        scope_sub, "verify", "Stamp last_verified. Refuses without a cited source (exit 3)."
    )
    verify.add_argument("--scope", default="scope.json", help="path to the scope file")
    verify.add_argument(
        "--source",
        default="",
        help="the URL of the policy page reconciled against, or a quoted sentence from it",
    )
    verify.add_argument("--today", type=dt.date.fromisoformat, default=None, help=argparse.SUPPRESS)
    verify.set_defaults(handler=cmd_scope_verify)

    # ------------------------------------------------------------------ oracle
    oracle = top.add_parser("oracle", help="the oracle strength table")
    oracle_sub = oracle.add_subparsers(dest="action", metavar="<action>")
    rate = _leaf(
        oracle_sub,
        "rate",
        f"Classify an oracle kind 0-4. Exit 3 below the floor of {STRENGTH_FLOOR}.",
    )
    rate.add_argument("kind", help=f"one of: {', '.join(sorted(ORACLE_STRENGTH))}")
    rate.set_defaults(handler=cmd_oracle_rate)

    # --------------------------------------------------------------------- run
    run = _leaf(top, "run", "Execute a declared plan and write run.json with the lattice.")
    run.add_argument("plan", help="path to a plan file (strict JSON; see docs/cli.md)")
    run.add_argument("--out", default="run.json", help="where to write the run record")
    run.add_argument("--now", type=dt.datetime.fromisoformat, default=None, help=argparse.SUPPRESS)
    run.set_defaults(handler=cmd_run)

    # ------------------------------------------------------------------ ledger
    ledger = top.add_parser("ledger", help="the append-only row store")
    ledger_sub = ledger.add_subparsers(dest="action", metavar="<action>")

    add = _leaf(ledger_sub, "add", "Append one row. Exit 3 when the store refuses it.")
    add.add_argument("--ledger", default="ledger.jsonl", help="path to the JSONL store")
    add.add_argument("--id", required=True, help="the row id; reusing one is refused")
    add.add_argument("--subject", required=True, help="what was tested")
    add.add_argument(
        "--verdict",
        required=True,
        choices=[v.value for v in LedgerVerdict],
        help="the verdict; VOID and CONFOUNDED are first-class terminal states",
    )
    add.add_argument("--oracle", required=True, help="the named oracle that answered")
    add.add_argument("--control-name", default="", help="the control arm's name")
    add.add_argument(
        "--control-passed",
        type=_tristate,
        default=None,
        help="true, false, or omitted for 'no control was recorded', which is allowed and counted",
    )
    add.add_argument(
        "--control-independent",
        type=_tristate,
        default=None,
        help="true, false, or omitted. A control that passed but was not independent is counted "
        "as no control at all",
    )
    add.add_argument("--control-detail", default="", help="free text")
    add.add_argument(
        "--artifact",
        default=None,
        help="the results artifact, relative to the ledger's directory. Required for a verdict "
        "that asserts an absence",
    )
    add.add_argument(
        "--assumption",
        default=None,
        help="the assumption an absence rests on. Required for a verdict that asserts one",
    )
    add.add_argument("--supersedes", default=None, help="the row id this one amends")
    add.add_argument("--next-axis", default=None, help="the next perspective to try")
    add.add_argument("--dedup-score", default=None, help="the dedup digits, recorded verbatim")
    add.add_argument(
        "--claim",
        action="append",
        default=[],
        metavar="TEXT[::CITATION]",
        help="a claim and its citation, separated by '::'. An uncited claim is counted as one",
    )
    add.add_argument("--now", type=dt.datetime.fromisoformat, default=None, help=argparse.SUPPRESS)
    add.set_defaults(handler=cmd_ledger_add)

    show = _leaf(ledger_sub, "show", "List the rows. Refuses nothing.")
    show.add_argument("--ledger", default="ledger.jsonl", help="path to the JSONL store")
    show.add_argument("--current", action="store_true", help="hide rows a later row supersedes")
    show.set_defaults(handler=cmd_ledger_show)

    # ------------------------------------------------------------------- audit
    audit_p = top.add_parser("audit", help="what the record will and will not support")
    audit_sub = audit_p.add_subparsers(dest="action", metavar="<action>")

    al = _leaf(
        audit_sub,
        "ledger",
        "The three proportions: artifact exists, passing independent control, admissible oracle.",
    )
    al.add_argument("--ledger", default="ledger.jsonl", help="path to the JSONL store")
    al.add_argument(
        "--root",
        default=None,
        help="the directory results_artifact paths are relative to; defaults to the ledger's own "
        "directory. An unchecked artifact is reported absent, never present",
    )
    al.add_argument("--current", action="store_true", help="audit only rows nothing supersedes")
    al.add_argument("--out", default=None, help="also write the audit-<date>.md artifact here")
    al.add_argument("--now", type=dt.datetime.fromisoformat, default=None, help=argparse.SUPPRESS)
    al.set_defaults(handler=cmd_audit_ledger)

    ar = _leaf(
        audit_sub,
        "rules",
        "Declared rules against enforced rules. Exits 2: the ratio cannot be derived honestly.",
    )
    ar.add_argument(
        "--repo",
        default=".",
        help="a checkout of this repository; the counts are parsed from its committed artifacts",
    )
    ar.set_defaults(handler=cmd_audit_rules)

    # ---------------------------------------------------------------- selftest
    st = _leaf(
        top,
        "selftest",
        "The instrument's own calibration. A non-zero exit voids prior clean verdicts.",
    )
    st.set_defaults(handler=cmd_selftest)

    return parser


# ========================================================================= main


def main(
    argv: Sequence[str] | None = None,
    *,
    out: IO[str] | None = None,
    err: IO[str] | None = None,
) -> int:
    """Parse, dispatch, render, and return the exit code.

    The three structural guards of this module are all here, in this order,
    and the order is the guard:

    * ``Refused`` is caught first and maps to ``3`` only (defect 2).
    * ``NotPromoted`` maps to ``4``.
    * ``CannotMeasure`` maps to ``2`` and is a *sibling* of ``Refused``, never a
      subclass, so an inability to measure can never be rendered as a refusal
      or the other way round.
    * ``except Exception`` is last and maps to ``2`` (defect 1). It never
      returns ``OK``: a crash is not a clean negative.
    """
    stdout = out or sys.stdout
    stderr = err or sys.stderr
    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(ns, "handler", None)
    if handler is None:
        # No subcommand, or a group with no action. Usage, and a tool failure:
        # a mis-invoked instrument measured nothing.
        parser.print_help(stderr)
        return int(Exit.TOOL_FAILURE)

    as_json = bool(getattr(ns, "json", False))
    try:
        emission = handler(ns)
    except (Refused, NotPromoted, CannotMeasure) as exc:
        return int(render.write(_from_outcome(exc, ns), as_json=as_json, out=stdout, err=stderr))
    except Exception as exc:
        crash = Emission(
            command=_command_of(ns),
            verdict="TOOL-FAILURE",
            reason=(
                f"{type(exc).__name__}: {exc}\n\nThis is exit 2 and it is NOT a negative "
                "result. The instrument broke; nothing was measured. A crashed run is not a "
                "clean one."
            ),
            code=Exit.TOOL_FAILURE,
        )
        return int(render.write(crash, as_json=as_json, out=stdout, err=stderr))
    return int(render.write(emission, as_json=as_json, out=stdout, err=stderr))


def _from_outcome(exc: CliOutcome, ns: argparse.Namespace) -> Emission:
    """Turn a declared outcome into the one thing the renderers read."""
    data = dict(exc.data)
    lines = tuple(data.pop("lines", ()) or ())
    warnings = tuple(data.pop("warnings", ()) or ())
    return Emission(
        command=_command_of(ns),
        verdict=exc.verdict,
        reason=exc.reason,
        code=exit_for(exc),
        data=data,
        lines=lines,
        warnings=warnings,
    )


def _command_of(ns: argparse.Namespace) -> str:
    group = getattr(ns, "group", None) or ""
    action = getattr(ns, "action", None) or ""
    return " ".join(p for p in (group, action) if p) or _PROG


# -------------------------------------------------------------------- helpers


def _value(enum_or_str: object) -> str:
    """The string a ``str``-subclass enum member carries.

    ``dataclasses.asdict`` keeps enum members as members, and formatting one
    with a width renders ``Role.LIVENESS`` rather than ``liveness``. The JSON
    path serialises the value correctly on its own, so without this the two
    renderers would disagree about the same field -- which is the one thing the
    single-``Emission`` design exists to make impossible.
    """
    return str(getattr(enum_or_str, "value", enum_or_str))


def _tristate(value: str) -> bool:
    """``true``/``false`` only. Nothing here coerces an unknown word to False.

    A flag that silently read ``--control-passed maybe`` as ``false`` would be
    recording a failed control where none was recorded, which is the opposite
    of the distinction the ledger keeps.
    """
    lowered = value.strip().casefold()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    raise argparse.ArgumentTypeError(
        f"expected true or false, got {value!r}. Omit the flag entirely to record that no "
        "control ran, which is a different thing from recording that one failed."
    )


def _claim(raw: str) -> tuple[str, str | None]:
    text, sep, citation = raw.partition("::")
    return (text.strip(), citation.strip() if sep else None)


def _is_a_citation(value: str) -> bool:
    """A URL with a scheme and a host, or a quoted sentence.

    The same standard ``ledger.Claim`` applies, stated mechanically so the
    refusal is not a matter of taste.
    """
    from urllib.parse import urlparse

    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) > 2:
        return True
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pct(rate: float | None) -> str:
    return "n/a (no rows)" if rate is None else f"{rate:.0%}"


if __name__ == "__main__":
    raise SystemExit(main())
