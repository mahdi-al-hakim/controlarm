"""Tests for the false-positive gate.

Three properties are checked harder than the individual modes, because they are
what make the gate usable rather than decorative:

* ``run_gate`` does not short-circuit, so a candidate failing four modes shows
  four failures and the next attempt can fix all of them at once;
* a missing input is FAILED and never PASSED;
* a check that raises is FAILED, because a gate that crashes open is worse than
  no gate.

Every mode has at least one failing case, and the completeness test fails the
build if a mode is ever added without one.
"""

from __future__ import annotations

import dataclasses

import pytest

from controlarm.gates.fp import (
    MODES,
    ORACLE_STRENGTH,
    CheckState,
    ClaimKind,
    Differential,
    EvidenceSource,
    FPGateResult,
    GateInputs,
    NoveltyBasis,
    OracleAccess,
    run_gate,
    summarise,
)

# A set of inputs under which every applicable mode passes. Each test perturbs
# exactly one field, which is the same discipline the gate demands of a PoC.
CLEAN = {
    "claims": frozenset(
        {
            ClaimKind.BYPASS,
            ClaimKind.DISCLOSURE,
            ClaimKind.SECRET_EXPOSURE,
            ClaimKind.NOVELTY,
            ClaimKind.DIFFERENTIAL,
            ClaimKind.COVERAGE,
            ClaimKind.QUANTITATIVE_FIT,
        }
    ),
    # 1 own_input_echo: the oracle matched a header the target emitted, and that
    # string appears nowhere in anything the tester sent.
    "oracle_match": "x-upstream-trace: 7f3a1c",
    "request_bytes": "GET /v1/fetch?u=https%3A%2F%2Fdeclared.example HTTP/1.1\nhost: api.example",
    # 2, 12 the oracle itself
    "oracle_access": OracleAccess.PARSED_FIELD,
    "oracle_kind": "parsed_field_diff",
    # 3 rejection vs disclosure
    "response_status": 200,
    "foreign_data_present": True,
    # 4 the differential
    "differential": Differential(
        arm_a='{"error":"not_found","id":"obj_A","trace":"a1"}',
        arm_b='{"error":"not_found","id":"obj_B"}',
        echoed_identifiers=("obj_A", "obj_B"),
    ),
    # 5 raw artifact
    "evidence_source": EvidenceSource.RAW_ARTIFACT,
    "match_context": "...content-length: 42\nx-upstream-trace: 7f3a1c\nvary: accept...",
    # 6 placeholder vs real secret
    "secret_value": "7f3a1c9d44b2e8",
    "secret_is_real": True,
    # 7 liveness
    "tool_started": True,
    "positive_control_fired": True,
    # 8 independence
    "control_independent_of_treatment": True,
    "treatment_control_differing_fields": 1,
    # 9 novelty basis
    "novelty_basis": NoveltyBasis.TOKEN_SET_DIFF,
    # 10 fixture branching
    "fixture_branch_fields": ("mode", "encoding"),
    "fixture_fields_varied": ("mode", "encoding"),
    # 11 reachability
    "poc_can_express_the_positive": True,
    # 13 dedup breadth
    "dedup_sources_answered": 2,
    # 14 fit confidence
    "fit_r_squared": 0.97,
    # 15 coverage denominator
    "coverage_rows_emitted": 384,
    "coverage_feasible_minimum": 384,
    # 16 detector target
    "detector_ran_against": "src/component/parser.c",
    "subject_under_test": "src/component/parser.c",
}


def inputs(**overrides) -> GateInputs:
    return GateInputs(**{**CLEAN, **overrides})


def states(report) -> dict[str, CheckState]:
    return {r.mode: r.state for r in report.results}


def failed(report) -> set[str]:
    return {r.mode for r in report.results if r.state is CheckState.FAILED}


# ---------------------------------------------------------------- the baseline


def test_the_clean_baseline_passes_every_mode():
    report = run_gate(inputs())
    assert failed(report) == set()
    assert report.clean
    assert report.n_suppressed == 0
    assert report.n_passed == len(MODES)


def test_every_mode_is_reported_every_time():
    """No short-circuit, and no mode silently skipped."""
    report = run_gate(inputs(tool_started=False, oracle_match="host: api.example"))
    assert len(report.results) == len(MODES)
    assert [r.mode for r in report.results] == [m.name for m in MODES]


def test_run_gate_does_not_short_circuit():
    """Four failures must be visible as four, not as the first one."""
    report = run_gate(
        inputs(
            tool_started=False,
            poc_can_express_the_positive=False,
            oracle_access=OracleAccess.SUBSTRING,
            novelty_basis=NoveltyBasis.LINE_DIFF,
        )
    )
    assert len(failed(report)) >= 4
    assert not report.clean


# --------------------------------------------------- one failing case per mode

#: One override per mode that must make exactly that mode fail. The
#: completeness test below asserts this table covers every mode.
FAILING_CASES: dict[str, dict] = {
    "own_input_echo": {"oracle_match": "host: api.example"},
    "oracle_is_a_parsed_field": {"oracle_access": OracleAccess.SUBSTRING},
    "rejection_vs_disclosure": {"response_status": 400},
    "echoed_identifier_normalisation": {
        "differential": Differential(
            arm_a='{"error":"not_found","id":"obj_A"}',
            arm_b='{"error":"not_found","id":"obj_B"}',
            echoed_identifiers=("obj_A", "obj_B"),
        )
    },
    "raw_artifact_read": {"evidence_source": EvidenceSource.DETECTOR_SUMMARY},
    "placeholder_not_real_secret": {"secret_value": "your-api-key-here"},
    "liveness": {"tool_started": False},
    "independent_control": {"control_independent_of_treatment": False},
    "identifier_novelty": {"novelty_basis": NoveltyBasis.LINE_DIFF},
    "fixture_branch_coverage": {"fixture_fields_varied": ("mode",)},
    "poc_reachability": {"poc_can_express_the_positive": False},
    "oracle_strength": {"oracle_kind": "model_text"},
    "single_source_dedup": {"dedup_sources_answered": 1},
    "confidence_band": {"fit_r_squared": -2.63},
    "coverage_denominator": {"coverage_rows_emitted": 105},
    "detector_target": {"detector_ran_against": "tests/poc_component.c"},
}


@pytest.mark.parametrize("mode", sorted(FAILING_CASES))
def test_each_mode_has_a_case_that_fails_it(mode):
    report = run_gate(inputs(**FAILING_CASES[mode]))
    assert mode in failed(report), f"{mode} did not fail on its own failing case"
    assert not report.clean


def test_every_mode_has_a_failing_case():
    """A mode with no failing case is a mode nothing checks."""
    assert sorted(FAILING_CASES) == sorted(m.name for m in MODES)


@pytest.mark.parametrize("mode", sorted(FAILING_CASES))
def test_a_failing_case_names_its_mode_and_explains_itself(mode):
    report = run_gate(inputs(**FAILING_CASES[mode]))
    result = next(r for r in report.results if r.mode == mode)
    assert result.detail.strip(), f"{mode} failed without a reason"
    assert len(result.detail) > 20


# --------------------------------------------------- the dominant failure mode


@pytest.mark.parametrize(
    "match",
    [
        "host: api.example",  # FP#6: the nonce lived in the path the tester sent
        "HOST: API.EXAMPLE",  # the same, re-cased
        "declared.example",  # the payload host, which the tester chose
        "https%3A%2F%2Fdeclared.example",  # and its encoded form, verbatim
    ],
)
def test_matching_a_value_the_tester_supplied_is_not_an_oracle(match):
    """Five of the six numbered false positives are this one error.

    A detector matched a string that the tester had planted in the request, and
    the request was echoed. The remedy is mechanical, not an instruction to be
    careful: the matched bytes must be absent from everything that was sent.
    """
    report = run_gate(inputs(oracle_match=match))
    assert "own_input_echo" in failed(report)
    result = next(r for r in report.results if r.mode == "own_input_echo")
    assert "supplied" in result.detail or "sent" in result.detail


def test_a_match_the_tester_did_not_supply_passes():
    report = run_gate(inputs(oracle_match="x-upstream-trace: 7f3a1c"))
    assert "own_input_echo" not in failed(report)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 500, 503])
def test_an_error_echoing_your_input_is_a_rejection_not_a_disclosure(status):
    """FP#1, the one numbered false positive that is not an echo error.

    The foreign identifier really was in the body. A 4xx is a rejection by
    definition, and a disclosure verdict needs a 2xx carrying foreign data.
    """
    report = run_gate(inputs(response_status=status))
    assert "rejection_vs_disclosure" in failed(report)
    result = next(r for r in report.results if r.mode == "rejection_vs_disclosure")
    assert "rejection" in result.detail


def test_a_two_hundred_without_foreign_data_is_also_not_a_disclosure():
    report = run_gate(inputs(response_status=200, foreign_data_present=False))
    assert "rejection_vs_disclosure" in failed(report)


def test_normalising_echoed_identifiers_can_make_a_differential_vanish():
    """FP#2. Two rejections that differed only by the echoed identifier.

    After normalisation both arms were byte-identical and the existence oracle
    the differential appeared to provide did not exist.
    """
    vanishing = Differential(
        arm_a='{"error":"not_found","id":"obj_A"}',
        arm_b='{"error":"not_found","id":"obj_B"}',
        echoed_identifiers=("obj_A", "obj_B"),
    )
    report = run_gate(inputs(differential=vanishing))
    result = next(r for r in report.results if r.mode == "echoed_identifier_normalisation")
    assert result.state is CheckState.FAILED
    assert "identical" in result.detail


def test_a_differential_that_survives_normalisation_passes():
    report = run_gate(inputs())
    assert "echoed_identifier_normalisation" not in failed(report)


@pytest.mark.parametrize(
    "context",
    [
        "I cannot help with that. The value SECRET-SHAPED-STRING appears to be a credential.",
        "I'm unable to retrieve SECRET-SHAPED-STRING for you.",
        "Request refused: SECRET-SHAPED-STRING is not permitted here.",
    ],
)
def test_a_match_inside_refusal_text_is_not_a_leak(context):
    """FP#3. The secret appeared inside a refusal, quoted as the thing refused.

    A detector reading its own summary sees the token and reports exfiltration.
    Reading the raw bytes shows a refusal.
    """
    report = run_gate(inputs(match_context=context))
    assert "raw_artifact_read" in failed(report)


@pytest.mark.parametrize(
    "value",
    [
        "your-api-key-here",
        "CHANGEME",
        "<redacted>",
        "placeholder",
        "xxxxxxxxxxxx",
        "AAAAAAAAAAAA",
        "000000000000",
        "example-token",
        "dummy_secret",
        "test-token-1",
    ],
)
def test_a_placeholder_is_not_a_real_secret(value):
    report = run_gate(inputs(secret_value=value))
    assert "placeholder_not_real_secret" in failed(report)


def test_a_secret_not_asserted_as_real_is_not_a_real_secret():
    report = run_gate(inputs(secret_is_real=False))
    assert "placeholder_not_real_secret" in failed(report)


def test_a_tool_that_failed_to_start_is_not_a_clean_negative():
    """The liveness mode, which is the reason negatives are the headline claim.

    A dead runtime and a defended target produce the same bytes: none. Without
    this mode a harness reports the second when it observed the first.
    """
    report = run_gate(inputs(tool_started=False))
    result = next(r for r in report.results if r.mode == "liveness")
    assert result.state is CheckState.FAILED
    assert "negative" in result.detail


def test_a_control_that_never_fired_is_not_a_clean_negative():
    report = run_gate(inputs(positive_control_fired=False))
    assert "liveness" in failed(report)


def test_a_control_sharing_the_containment_under_test_is_confounded():
    report = run_gate(inputs(treatment_control_differing_fields=2))
    assert "independent_control" in failed(report)


# ------------------------------------------------- missing inputs are failures


@pytest.mark.parametrize(
    "field_name",
    sorted(
        set(CLEAN)
        - {
            "claims",
            "differential",
            "secret_value",
            "fixture_branch_fields",
            "fixture_fields_varied",
        }
    ),
)
def test_a_missing_input_is_failed_and_never_passed(field_name):
    """ "A missing result is not a passing result" -- the source's own words.

    Every input the gate consumes is ``X | None`` and ``None`` fails. Nothing
    defaults to a value that would let a check pass without evidence.
    """
    report = run_gate(inputs(**{field_name: None}))
    assert failed(report), f"setting {field_name} to None left every mode passing"
    assert not report.clean


def test_an_undeclared_claim_set_fails_every_claim_scoped_mode():
    report = run_gate(inputs(claims=None))
    for mode in ["rejection_vs_disclosure", "placeholder_not_real_secret", "identifier_novelty"]:
        assert mode in failed(report)


def test_a_claim_not_asserted_makes_its_mode_not_applicable():
    report = run_gate(inputs(claims=frozenset({ClaimKind.BYPASS})))
    assert states(report)["rejection_vs_disclosure"] is CheckState.NOT_APPLICABLE
    assert states(report)["identifier_novelty"] is CheckState.NOT_APPLICABLE
    # The modes that apply to every run still apply.
    assert states(report)["liveness"] is CheckState.PASSED


def test_not_applicable_is_not_counted_as_passed():
    report = run_gate(inputs(claims=frozenset({ClaimKind.BYPASS})))
    assert report.n_not_applicable > 0
    assert report.n_passed + report.n_not_applicable == len(MODES)


def test_a_report_with_nothing_passing_is_not_clean():
    """A gate every mode skipped has gated nothing."""
    report = run_gate(
        inputs(claims=frozenset()),
        modes=[m for m in MODES if m.claim is not None],
    )
    assert report.n_passed == 0
    assert report.n_failed == 0
    assert not report.clean


# ------------------------------------------------------------- suppressions


def test_a_suppression_is_counted_and_never_reads_as_a_pass():
    report = run_gate(inputs(tool_started=False, suppressed={"liveness": "rig is a local stub"}))
    assert states(report)["liveness"] is CheckState.SUPPRESSED
    assert report.n_suppressed == 1
    assert "liveness" not in failed(report)
    assert report.suppressed_modes == ("liveness",)


def test_a_suppression_carries_its_reason_into_the_report():
    report = run_gate(inputs(suppressed={"liveness": "rig is a local stub"}))
    result = next(r for r in report.results if r.mode == "liveness")
    assert "rig is a local stub" in result.detail


@pytest.mark.parametrize("reason", ["", "   "])
def test_a_suppression_with_no_reason_does_not_suppress(reason):
    """A silent suppression is how a gate becomes decoration."""
    report = run_gate(inputs(tool_started=False, suppressed={"liveness": reason}))
    assert "liveness" in failed(report)
    assert report.n_suppressed == 0


def test_suppressing_an_unknown_mode_fails_loudly():
    with pytest.raises(ValueError) as exc:
        run_gate(inputs(suppressed={"no_such_mode": "typo"}))
    assert "no_such_mode" in str(exc.value)


def test_suppressing_everything_is_not_clean():
    report = run_gate(inputs(suppressed={m.name: "all off" for m in MODES}))
    assert report.n_suppressed == len(MODES)
    assert not report.clean


def test_the_summary_states_the_suppression_count_explicitly():
    report = run_gate(inputs(suppressed={"liveness": "rig is a local stub"}))
    text = summarise(report)
    assert "1 suppressed" in text
    assert "[SUPPRESSED] liveness" in text


# ------------------------------------------------------ a check that raises


def test_a_check_that_raises_counts_as_failed():
    """A gate that crashes open is worse than no gate at all."""

    def explodes(gi: GateInputs) -> FPGateResult:
        raise ZeroDivisionError("the check itself is broken")

    broken = dataclasses.replace(MODES[0], name="broken_mode", check=explodes)
    report = run_gate(inputs(), modes=[broken])
    result = report.results[0]
    assert result.state is CheckState.FAILED
    assert "ZeroDivisionError" in result.detail
    assert not report.clean


def test_a_check_returning_the_wrong_type_counts_as_failed():
    def wrong(gi: GateInputs):
        return "passed, honestly"

    broken = dataclasses.replace(MODES[0], name="wrong_type", check=wrong)
    report = run_gate(inputs(), modes=[broken])
    assert report.results[0].state is CheckState.FAILED


# ------------------------------------------------------------------ the record


def test_the_cheapest_and_most_decisive_modes_run_first():
    """Ordering is part of the design: an unrealisable candidate should die
    before anyone spends time quantifying its impact."""
    names = [m.name for m in MODES]
    assert names.index("liveness") < names.index("coverage_denominator")
    assert names.index("own_input_echo") < names.index("confidence_band")


def test_every_mode_explains_why_the_obvious_check_is_not_enough():
    """The docstrings are the artifact. A mode whose justification is missing
    will be deleted by the next person who finds it inconvenient."""
    for mode in MODES:
        doc = (mode.check.__doc__ or "").lower()
        assert "obvious" in doc, f"{mode.name} does not say why the obvious check is not enough"
        assert len(doc) > 200, f"{mode.name}'s justification is too thin to defend"


def test_each_mode_cites_the_catalogue_entry_it_came_from():
    for mode in MODES:
        assert mode.catalogue, f"{mode.name} cites no catalogue entry"


def test_results_are_immutable():
    report = run_gate(inputs())
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.results[0].state = CheckState.PASSED  # type: ignore[misc]


def test_inputs_are_immutable():
    gi = inputs()
    with pytest.raises(dataclasses.FrozenInstanceError):
        gi.tool_started = False  # type: ignore[misc]


def test_the_report_serialises_without_losing_a_mode():
    import json

    report = run_gate(inputs(tool_started=False))
    text = json.dumps(report.as_dict())
    for mode in MODES:
        assert mode.name in text
    assert '"clean": false' in text


def test_the_oracle_strength_table_matches_the_rule_it_encodes():
    """Strength 0 is the auto-reject band and nothing below 2 may pass."""
    assert ORACLE_STRENGTH["model_text"] == 0
    assert ORACLE_STRENGTH["string_co_occurrence"] == 0
    assert ORACLE_STRENGTH["revert_or_crash"] == 1
    assert ORACLE_STRENGTH["assertion_only"] == 2
    assert ORACLE_STRENGTH["source_diff"] == 4
    assert set(ORACLE_STRENGTH.values()) <= {0, 1, 2, 3, 4}


@pytest.mark.parametrize("kind", sorted(ORACLE_STRENGTH))
def test_the_strength_floor_is_enforced_for_every_known_oracle(kind):
    report = run_gate(inputs(oracle_kind=kind))
    should_fail = ORACLE_STRENGTH[kind] < 2
    assert ("oracle_strength" in failed(report)) is should_fail


def test_an_unknown_oracle_kind_fails_rather_than_defaulting():
    """And it fails *as unscored*, not by crashing on a comparison with None."""
    report = run_gate(inputs(oracle_kind="vibes"))
    result = next(r for r in report.results if r.mode == "oracle_strength")
    assert result.state is CheckState.FAILED
    assert "strength table" in result.detail


def test_the_gate_ships_no_domain_specific_modes():
    """The EVM-specific modes of the source live in a separate package.

    Mixing them in made the generic gate look inapplicable to anything that is
    not a smart contract, which is most things.
    """
    for mode in MODES:
        blob = f"{mode.name} {mode.check.__doc__ or ''}".lower()
        for token in ["wei", "gas", "flashloan", "solidity", "cheatcode", "forge"]:
            assert token not in blob, f"{mode.name} mentions {token}"
