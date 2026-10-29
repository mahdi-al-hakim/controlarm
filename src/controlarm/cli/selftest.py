"""The instrument's own calibration.

*An instrument that has never been observed to fire cannot certify a negative.*
That is the whole premise. Every clean verdict this tool produces is a claim
that the gates would have fired had there been something to fire at, and nothing
establishes that claim except firing them at something known.

So: a known-bad fixture must fire **exactly** the expected multiset of modes, no
more and no fewer; a known-clean fixture must fire **exactly zero**; and each
refusing gate must raise the **right** exception with the **right** reason for
each way its refusal can be reached.

**If this drifts, every clean verdict the gates have produced since the last
passing selftest is void and must be re-run.** That is not a formality. It is
the rule that voided two runs in the work this was extracted from, and it is why
the negatives in that ledger can be relied on at all.

Numbered items are the wrong verdicts this design prevents:

  1  "at least these modes fired"              -> a gate that gained a spurious
     failure still passed a subset assertion, and the spurious failure then
     killed true candidates for a week before anybody looked. The comparison
     here is a ``Counter`` equality, and the two directions are reported as two
     separately named outcomes so the output says which way it drifted.
  2  a wrong exception type counted as a pass  -> a refusal was asserted with
     ``pytest.raises(Exception)``, and a later refactor made the gate raise an
     unrelated ``KeyError`` from a typo. The refusal was still "observed". Both
     the type and a fragment of the reason are asserted here.
  3  a clean fixture that gated nothing        -> a fixture whose every mode was
     inapplicable produced zero failures and was read as proof the gate works.
     The clean case therefore also asserts ``report.clean``, which requires at
     least one mode to have actually passed.
  4  a selftest that only tested the cheap half -> the modes were calibrated and
     the *refusals* were not, so the state machine that actually blocks a
     promotion was never observed to block one. The refusal table is part of
     this selftest, not a separate optional command.
"""

from __future__ import annotations

import datetime as dt
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from controlarm.gates.fp import (
    CheckState,
    ClaimKind,
    EvidenceSource,
    GateInputs,
    GateReport,
    OracleAccess,
    run_gate,
)
from controlarm.gates.priorart import (
    DEFAULT_FRESHNESS,
    CountBasis,
    PriorArtError,
    PriorArtQuery,
    StaticSource,
    assert_gated,
    gate,
)
from controlarm.ledger import (
    ControlReading,
    Ledger,
    LedgerError,
    LedgerRow,
    LedgerVerdict,
)
from controlarm.rails.payload import OwnedInfra, PayloadError, assert_own_payload_host
from controlarm.rails.scope import ScopeError, ScopeFile, ScopeGuard

__all__ = [
    "EXPECTED_BAD_FAILURES",
    "REFUSAL_MODES",
    "CheckOutcome",
    "RefusalMode",
    "SelftestReport",
    "clean_fixture",
    "known_bad_fixture",
    "selftest",
]

#: A fixed instant. The selftest must give the same answer on every day of the
#: week, so nothing here reads the clock.
_WHEN = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

#: The exact modes the known-bad fixture must fire. This is the *specification*
#: of that fixture, not an observation of it: the fixture is wrong in three named
#: ways and correct in every other way, so any fourth failure is drift in the
#: gate and any missing one is a gate that stopped checking.
EXPECTED_BAD_FAILURES: tuple[str, ...] = (
    "own_input_echo",
    "oracle_is_a_parsed_field",
    "oracle_strength",
)


def clean_fixture() -> GateInputs:
    """A candidate that is right in every respect the generic modes police."""
    return GateInputs(
        claims=frozenset({ClaimKind.BYPASS}),
        oracle_match="x-upstream-authority: listener.invalid",
        request_bytes='POST /v1/fetch {"url": "https://allowed.example/ok"}',
        oracle_access=OracleAccess.PARSED_FIELD,
        evidence_source=EvidenceSource.RAW_ARTIFACT,
        match_context="the parsed final_host field of a 200 response",
        tool_started=True,
        positive_control_fired=True,
        control_independent_of_treatment=True,
        treatment_control_differing_fields=1,
        poc_can_express_the_positive=True,
        oracle_kind="parsed_field_diff",
        fixture_branch_fields=("mode",),
        fixture_fields_varied=("mode",),
        detector_ran_against="examples/local_target/app.py",
        subject_under_test="examples/local_target/app.py",
    )


def known_bad_fixture() -> GateInputs:
    """The clean fixture, broken in exactly the three ways named above.

    The three are the catalogue's dominant shape and its two companions: the
    oracle matched bytes the tester planted, it read them by substring, and the
    oracle kind it declared is model narration. Everything else is left correct
    on purpose, because a fixture that is wrong in every way cannot detect a
    gate that stopped checking any single thing.
    """
    import dataclasses as _dc

    planted = "marker-9f2a"
    return _dc.replace(
        clean_fixture(),
        oracle_match=planted,
        request_bytes=f'POST /v1/echo?value={planted} {{"url": "https://allowed.example/ok"}}',
        oracle_access=OracleAccess.SUBSTRING,
        oracle_kind="model_text",
    )


@dataclass(frozen=True)
class CheckOutcome:
    """One named calibration check, and whether the instrument still passes it."""

    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass(frozen=True)
class RefusalMode:
    """One way a gate can refuse, with the exception it must raise to do it.

    Item 2: both halves are asserted. A gate that refuses for the right reason
    by raising the wrong type has lost the thing that makes a refusal usable,
    which is that a caller can tell it apart from a crash.
    """

    name: str
    fire: Callable[[], object]
    expected: type[BaseException]
    fragment: str


def _append(row: LedgerRow) -> object:
    """Offer ``row`` to a real, empty ledger and let it refuse.

    A throwaway directory rather than a reach into a private validator: the gate
    an operator meets is ``append``, and a selftest that calibrated a private
    method would be calibrating something nobody calls. Validation raises before
    any write, so the file is never created; the directory is removed either way.
    """
    with tempfile.TemporaryDirectory(prefix="controlarm-selftest-") as tmp:
        return Ledger(Path(tmp) / "ledger.jsonl").append(row)


def _row(**overrides: object) -> LedgerRow:
    base: dict[str, object] = {
        "id": "r1",
        "recorded": _WHEN,
        "subject": "the boundary holds",
        "verdict": LedgerVerdict.KILL,
        "oracle": "parsed_field_diff",
        "control": ControlReading("c", True, True),
        "results_artifact": "run.json",
        "assumption": "the rig could have produced a positive",
    }
    base.update(overrides)
    return LedgerRow(**base)  # type: ignore[arg-type]


def _ledger_absence_without_artifact() -> object:
    return _append(_row(results_artifact=None))


def _ledger_absence_without_assumption() -> object:
    return _append(_row(assumption=None))


def _ledger_naive_timestamp() -> object:
    naive = dt.datetime(2026, 1, 1)
    return _append(_row(recorded=naive, verdict=LedgerVerdict.CANDIDATE))


def _ledger_dangling_supersedes() -> object:
    return _append(_row(id="r2", verdict=LedgerVerdict.CANDIDATE, supersedes="r1"))


def _priorart_assessment(stamp: dt.datetime, rows: int = 0):
    record = PriorArtQuery(
        query="component AND class",
        source="advisories",
        retrieved=stamp,
        row_count=rows,
        url="https://example.invalid/search?q=component",
        basis=CountBasis.MEASURED,
    )
    return gate("subject", [StaticSource("advisories", [record])], now=stamp)


def _priorart_ungated_does_not_clear() -> object:
    return assert_gated(gate("subject", [], now=_WHEN), now=_WHEN)


def _priorart_stale_verdict() -> object:
    return assert_gated(
        _priorart_assessment(_WHEN),
        now=_WHEN + DEFAULT_FRESHNESS + dt.timedelta(seconds=1),
    )


def _scope_empty_allowlist_denies() -> object:
    scope = ScopeFile.from_text(
        '{"last_verified": "2026-01-01", "in_scope": [], "allow_loopback": true}',
        source="<selftest>",
    )
    return ScopeGuard(scope, today=dt.date(2026, 1, 2)).assert_in_scope("https://127.0.0.1/x")


def _scope_unverified_file_refuses() -> object:
    scope = ScopeFile.from_text(
        '{"last_verified": null, "in_scope": [{"host": "api.example"}]}',
        source="<selftest>",
    )
    return ScopeGuard(scope, today=dt.date(2026, 1, 2)).assert_in_scope("https://api.example/x")


def _payload_undeclared_host_refuses() -> object:
    return assert_own_payload_host(
        "https://listener.invalid/c", OwnedInfra(hostnames=("collector.example",))
    )


def _payload_encoded_internal_address_refuses() -> object:
    return assert_own_payload_host("http://2130706433/c", OwnedInfra(addresses=("198.51.100.7",)))


#: Every refusal mode the promotion path can reach, and the exception each must
#: raise to reach it. Item 4: this table is part of the selftest rather than an
#: optional extra, because the gates that block a promotion are the ones whose
#: silence would be most expensive.
REFUSAL_MODES: tuple[RefusalMode, ...] = (
    RefusalMode(
        "ledger: an absence with no results artifact",
        _ledger_absence_without_artifact,
        LedgerError,
        "names no results artifact",
    ),
    RefusalMode(
        "ledger: an absence with no stated assumption",
        _ledger_absence_without_assumption,
        LedgerError,
        "states no assumption",
    ),
    RefusalMode(
        "ledger: a naive timestamp in a durable row",
        _ledger_naive_timestamp,
        LedgerError,
        "must be timezone-aware",
    ),
    RefusalMode(
        "ledger: a dangling supersedes pointer",
        _ledger_dangling_supersedes,
        LedgerError,
        "which is not in the ledger",
    ),
    RefusalMode(
        "prior art: UNGATED never clears a promotion",
        _priorart_ungated_does_not_clear,
        PriorArtError,
        "UNGATED",
    ),
    RefusalMode(
        "prior art: a verdict older than the freshness window",
        _priorart_stale_verdict,
        PriorArtError,
        "not admissible",
    ),
    RefusalMode(
        "scope: an empty allowlist denies everything, loopback included",
        _scope_empty_allowlist_denies,
        ScopeError,
        "BLOCKED",
    ),
    RefusalMode(
        "scope: an unverified scope file refuses with no override",
        _scope_unverified_file_refuses,
        ScopeError,
        "never been reconciled",
    ),
    RefusalMode(
        "payload: an undeclared collector host",
        _payload_undeclared_host_refuses,
        PayloadError,
        "COMPLIANCE BLOCK",
    ),
    RefusalMode(
        "payload: an internal address behind a decimal encoding",
        _payload_encoded_internal_address_refuses,
        PayloadError,
        "FORBIDDEN-RANGE",
    ),
)


@dataclass(frozen=True)
class SelftestReport:
    """What the calibration found. ``drifted`` is the only field that gates."""

    outcomes: tuple[CheckOutcome, ...]
    bad_fired: tuple[str, ...]
    clean_fired: tuple[str, ...]

    @property
    def drifted(self) -> bool:
        return any(not o.passed for o in self.outcomes)

    @property
    def n_passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def failures(self) -> tuple[CheckOutcome, ...]:
        return tuple(o for o in self.outcomes if not o.passed)

    def as_dict(self) -> dict:
        return {
            "drifted": self.drifted,
            "checks": len(self.outcomes),
            "passed": self.n_passed,
            "failed": len(self.failures),
            "known_bad_fired": list(self.bad_fired),
            "known_bad_expected": list(EXPECTED_BAD_FAILURES),
            "known_clean_fired": list(self.clean_fired),
            "outcomes": [o.as_dict() for o in self.outcomes],
        }


def _fired(report: GateReport) -> tuple[str, ...]:
    return tuple(r.mode for r in report.results if r.state is CheckState.FAILED)


def selftest(
    *,
    expected: tuple[str, ...] = EXPECTED_BAD_FAILURES,
    refusals: tuple[RefusalMode, ...] = REFUSAL_MODES,
    inputs: Mapping[str, GateInputs] | None = None,
) -> SelftestReport:
    """Fire the gates at both fixtures and every refusal mode. Prints nothing."""
    fixtures = dict(inputs or {"bad": known_bad_fixture(), "clean": clean_fixture()})
    bad_report = run_gate(fixtures["bad"])
    clean_report = run_gate(fixtures["clean"])
    bad_fired = _fired(bad_report)
    clean_fired = _fired(clean_report)

    outcomes: list[CheckOutcome] = []

    # Item 1: a Counter equality, reported in both directions as two named
    # outcomes, so a drift says which way it went.
    want, got = Counter(expected), Counter(bad_fired)
    extra = sorted((got - want).elements())
    absent = sorted((want - got).elements())
    outcomes.append(
        CheckOutcome(
            "known-bad fixture fires no unexpected mode",
            not extra,
            f"unexpected failures: {extra}" if extra else "no mode fired that was not expected",
        )
    )
    outcomes.append(
        CheckOutcome(
            "known-bad fixture fires every expected mode",
            not absent,
            f"expected but silent: {absent}"
            if absent
            else f"all {len(expected)} expected modes fired: {list(expected)}",
        )
    )
    outcomes.append(
        CheckOutcome(
            "known-bad fixture is not reported clean",
            not bad_report.clean,
            f"{bad_report.n_failed} failed, {bad_report.n_passed} passed",
        )
    )

    outcomes.append(
        CheckOutcome(
            "known-clean fixture fires exactly zero modes",
            not clean_fired,
            f"fired: {list(clean_fired)}" if clean_fired else "zero failures",
        )
    )
    # Item 3: zero failures is not enough. A fixture whose every mode was
    # inapplicable also has zero failures and has gated nothing.
    outcomes.append(
        CheckOutcome(
            "known-clean fixture actually gated something",
            clean_report.clean,
            f"{clean_report.n_passed} modes passed, "
            f"{clean_report.n_not_applicable} not applicable, "
            f"{clean_report.n_suppressed} suppressed",
        )
    )

    for mode in refusals:
        outcomes.append(_check_refusal(mode))

    return SelftestReport(tuple(outcomes), bad_fired, clean_fired)


def _check_refusal(mode: RefusalMode) -> CheckOutcome:
    """Item 2: the right exception type **and** the right reason, or a failure."""
    label = f"refusal mode -- {mode.name}"
    try:
        mode.fire()
    except BaseException as exc:
        if type(exc) is not mode.expected:
            return CheckOutcome(
                label,
                False,
                f"raised {type(exc).__name__}, expected {mode.expected.__name__}: {exc}",
            )
        if mode.fragment not in str(exc):
            return CheckOutcome(
                label,
                False,
                f"raised {mode.expected.__name__} but the reason does not contain "
                f"{mode.fragment!r}: {exc}",
            )
        return CheckOutcome(label, True, f"{mode.expected.__name__}: {mode.fragment!r}")
    return CheckOutcome(
        label,
        False,
        f"did not refuse at all. A gate that has never been observed to fire cannot "
        f"certify a negative, and {mode.expected.__name__} was expected here.",
    )
