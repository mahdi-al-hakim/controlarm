"""The false-positive catalogue, as executable checks.

Sixteen modes, each one a false verdict that was actually produced and caught by
hand. Every mode carries, in its own docstring, **why the obvious check is not
enough** -- because the obvious check is what was being done when the false
verdict shipped, and a mode whose justification is missing gets deleted by the
next person who finds it inconvenient. A test fails the build if any mode loses
that paragraph.

Four properties of the runner are load-bearing, and all four are pinned by
tests:

* **No short-circuit.** A candidate failing four modes reports four failures.
  Knowing which ones fail is how the next attempt gets built, and a gate that
  reports only the first failure teaches the operator one lesson per run.
* **A missing input is FAILED.** Every consumed field is ``X | None`` and
  ``None`` fails. A missing result is not a passing result.
* **A check that raises is FAILED.** A gate that crashes open is worse than no
  gate, because it produces a clean report.
* **Suppressions are counted explicitly, carry a reason, and never read as a
  pass.** A suppression with no reason does not suppress.

The dominant mode is ``own_input_echo``. Five of the six numbered false
positives in the source catalogue are that same single error: the detector
matched a value the tester had put into the request, and the request was echoed
back. It therefore runs near the front and takes the whole request as input.

The domain-specific modes of the source -- the ones about gas, exit liquidity
and fork block pinning -- are deliberately **not** here. Mixing them in made the
generic gate look inapplicable to anything that was not a smart contract, which
is most things. They belong in a separate package over the same ``Mode``
protocol, and a test asserts none of them leaked back in.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "MODES",
    "ORACLE_STRENGTH",
    "PLACEHOLDER_PATTERNS",
    "REFUSAL_MARKERS",
    "STRENGTH_FLOOR",
    "CheckState",
    "ClaimKind",
    "Differential",
    "EvidenceSource",
    "FPGateResult",
    "GateInputs",
    "GateReport",
    "Mode",
    "NoveltyBasis",
    "OracleAccess",
    "run_gate",
    "summarise",
]


class CheckState(str, Enum):
    """Four states. Only ``PASSED`` is evidence of anything."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    SUPPRESSED = "SUPPRESSED"
    NOT_APPLICABLE = "NOT-APPLICABLE"
    """The claim this mode polices was not asserted. Counted separately from
    ``PASSED``, because a gate that skipped every mode has gated nothing."""


class ClaimKind(str, Enum):
    """What the candidate asserts. Scopes the modes that apply."""

    BYPASS = "bypass"
    DISCLOSURE = "disclosure"
    SECRET_EXPOSURE = "secret-exposure"
    NOVELTY = "novelty"
    DIFFERENTIAL = "differential"
    COVERAGE = "coverage"
    QUANTITATIVE_FIT = "quantitative-fit"


class OracleAccess(str, Enum):
    """How the oracle reads its answer out of the evidence."""

    PARSED_FIELD = "parsed-field"
    SUBSTRING = "substring"


class EvidenceSource(str, Enum):
    """What the verdict was read from."""

    RAW_ARTIFACT = "raw-artifact"
    DETECTOR_SUMMARY = "detector-summary"


class NoveltyBasis(str, Enum):
    """How novelty was measured."""

    TOKEN_SET_DIFF = "token-set-diff"
    LINE_DIFF = "line-diff"


#: Oracle strength, 0-4, with the floor that makes it a gate rather than a
#: label. The first six entries are the rule as originally written; the rest are
#: the admissible oracles the same rule set names elsewhere, scored on the same
#: scale. An unknown kind is not scored -- it fails.
ORACLE_STRENGTH: Mapping[str, int] = {
    # as written
    "source_diff": 4,
    "upstream_patch_absent": 4,
    "exact_arithmetic_diff": 3,
    "assertion_only": 2,
    "revert_or_crash": 1,
    "model_text": 0,
    # the admissible set, scored on the same scale
    "sanitizer_crash": 4,
    "conserved_quantity_delta": 3,
    "secret_vs_placeholder": 3,
    "collector_hit": 3,
    "normalised_status_diff": 3,
    "parsed_field_diff": 3,
    # the inadmissible set, named so it can be rejected by name
    "status_code_argument": 1,
    "string_co_occurrence": 0,
}

#: Nothing below this reaches the operator.
STRENGTH_FLOOR = 2

#: Text that means a model declined. A secret quoted inside a refusal is the
#: thing being refused, not a leak.
REFUSAL_MARKERS: tuple[str, ...] = (
    "i cannot",
    "i can't",
    "i can not",
    "i am unable",
    "i'm unable",
    "not permitted",
    "refus",
    "declin",
    "won't help",
    "will not help",
    "against my",
)

#: ``\b`` is the wrong boundary here: ``_`` is a word character, so
#: ``\bdummy\b`` does not match ``dummy_secret`` -- and ``dummy_secret`` is
#: exactly the shape a fixture value takes. These lookarounds treat ``_`` and
#: ``-`` as separators, which is how credential-shaped names are written.
_LEFT = r"(?<![a-zA-Z0-9])"
_RIGHT = r"(?![a-zA-Z0-9])"

#: Shapes a fixture value takes. A real credential cannot look like any of
#: these and still authenticate, which is what makes the check mechanical.
PLACEHOLDER_PATTERNS: tuple[str, ...] = (
    r"^<.*>$",
    rf"{_LEFT}change[-_ ]?me{_RIGHT}",
    rf"{_LEFT}placeholder{_RIGHT}",
    rf"{_LEFT}redacted{_RIGHT}",
    rf"{_LEFT}dummy{_RIGHT}",
    rf"{_LEFT}example{_RIGHT}",
    rf"{_LEFT}your[-_ ]?(api[-_ ]?)?(key|token|secret){_RIGHT}",
    rf"{_LEFT}test[-_ ]?(token|key|secret){_RIGHT}",
    rf"{_LEFT}fake{_RIGHT}",
    rf"{_LEFT}sample{_RIGHT}",
    rf"{_LEFT}not[-_ ]?a[-_ ]?real{_RIGHT}",
    r"^(.)\1{5,}$",  # one character repeated: xxxxxx, AAAAAA, 000000
)
_PLACEHOLDER = tuple(re.compile(p, re.IGNORECASE) for p in PLACEHOLDER_PATTERNS)


@dataclass(frozen=True)
class Differential:
    """Two arms of a comparison, plus the identifiers each arm echoes back."""

    arm_a: str
    arm_b: str
    echoed_identifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateInputs:
    """Everything the modes consume.

    Every field defaults to ``None``, and ``None`` fails its mode. That is the
    point: a gate whose inputs default to plausible values scores an absent
    measurement as a passing one, which is the failure the whole catalogue is
    about.
    """

    #: What the candidate claims. ``None`` is not "no claims" -- it is an
    #: undeclared claim set, and every claim-scoped mode fails on it.
    claims: frozenset[ClaimKind] | None = None

    # 1 own_input_echo
    oracle_match: str | None = None
    request_bytes: str | None = None

    # 2 oracle_is_a_parsed_field
    oracle_access: OracleAccess | None = None

    # 3 rejection_vs_disclosure
    response_status: int | None = None
    foreign_data_present: bool | None = None

    # 4 echoed_identifier_normalisation
    differential: Differential | None = None

    # 5 raw_artifact_read
    evidence_source: EvidenceSource | None = None
    match_context: str | None = None

    # 6 placeholder_not_real_secret
    secret_value: str | None = None
    secret_is_real: bool | None = None

    # 7 liveness
    tool_started: bool | None = None
    positive_control_fired: bool | None = None

    # 8 independent_control
    control_independent_of_treatment: bool | None = None
    treatment_control_differing_fields: int | None = None

    # 9 identifier_novelty
    novelty_basis: NoveltyBasis | None = None

    # 10 fixture_branch_coverage
    fixture_branch_fields: tuple[str, ...] | None = None
    fixture_fields_varied: tuple[str, ...] | None = None

    # 11 poc_reachability
    poc_can_express_the_positive: bool | None = None

    # 12 oracle_strength
    oracle_kind: str | None = None

    # 13 single_source_dedup
    dedup_sources_answered: int | None = None

    # 14 confidence_band
    fit_r_squared: float | None = None
    fit_r_squared_floor: float = 0.90

    # 15 coverage_denominator
    coverage_rows_emitted: int | None = None
    coverage_feasible_minimum: int | None = None

    # 16 detector_target
    detector_ran_against: str | None = None
    subject_under_test: str | None = None

    #: mode name -> why it is suppressed. An empty reason does not suppress.
    suppressed: Mapping[str, str] = field(default_factory=dict)

    def asserts(self, claim: ClaimKind) -> bool | None:
        """True, False, or ``None`` when the claim set was never declared."""
        if self.claims is None:
            return None
        return claim in self.claims


@dataclass(frozen=True)
class FPGateResult:
    mode: str
    state: CheckState
    detail: str

    @property
    def passed(self) -> bool:
        return self.state is CheckState.PASSED

    @property
    def failed(self) -> bool:
        return self.state is CheckState.FAILED


Check = Callable[[GateInputs], FPGateResult]


@dataclass(frozen=True)
class Mode:
    """One catalogue entry, bound to the check that kills it."""

    name: str
    #: The catalogue entry this came from, so a reader can find the original.
    catalogue: str
    check: Check
    #: The claim this mode polices, or ``None`` when it applies to every run.
    claim: ClaimKind | None = None


# ==================================================================== the modes


def _ok(name: str, detail: str) -> FPGateResult:
    return FPGateResult(name, CheckState.PASSED, detail)


def _no(name: str, detail: str) -> FPGateResult:
    return FPGateResult(name, CheckState.FAILED, detail)


def check_own_input_echo(gi: GateInputs) -> FPGateResult:
    """Mode 1: the oracle matched a value the tester put into the request.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the string really is in the response,
    the log, or the captured output -- so "does the evidence contain the marker"
    fires true, and it fires true for the wrong reason. Five of the six numbered
    false positives in the catalogue are this one error wearing different
    costumes: a nonce counted as a redirect hop when it sat in the allowlisted
    path the tester supplied; a token matched inside a listener's own
    ``expected_token`` configuration field; a success marker matched inside the
    source the tester submitted rather than in the stdout it produced. Being
    careful is not a remedy. The remedy is mechanical: the matched bytes must be
    absent from everything that was sent, in every casing, and the oracle must
    key on a field the two hypotheses predict differently.
    """
    name = "own_input_echo"
    if gi.oracle_match is None:
        return _no(name, "no oracle_match supplied: what the oracle matched is not recorded")
    if gi.request_bytes is None:
        return _no(
            name,
            "no request_bytes supplied. Without the bytes the tester sent, the one check that "
            "kills the catalogue's dominant false positive cannot run, and a missing check is "
            "not a passing check.",
        )
    needle = gi.oracle_match.strip()
    if not needle:
        return _no(name, "oracle_match is empty, so the oracle matched nothing")
    if needle in gi.request_bytes or needle.casefold() in gi.request_bytes.casefold():
        return _no(
            name,
            f"the oracle matched {needle!r}, which also appears in the request the tester "
            "supplied. A string you planted and the target echoed is not an oracle. Re-key the "
            "oracle onto a field that distinguishes the two hypotheses -- the host header, the "
            "parsed authorization field, the source address, the path prefix.",
        )
    return _ok(
        name,
        f"the matched bytes {needle!r} appear nowhere in the {len(gi.request_bytes)} bytes the "
        "tester sent",
    )


def check_oracle_is_a_parsed_field(gi: GateInputs) -> FPGateResult:
    """Mode 2: the oracle is a substring match rather than a parsed field.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: grepping the body for the token is the
    fastest thing to write and it is correct often enough to feel reliable. It
    fails on exactly the cases that matter, because a body contains
    configuration fields, echoed input and refusal text, all of which carry the
    token for reasons that are not the finding. The mechanical form is to parse
    the structure and read the key. There is no substring API in an admissible
    oracle at all, which is why this is a separate mode from strength: a
    strength-3 oracle read by substring is a strength-0 oracle.
    """
    name = "oracle_is_a_parsed_field"
    if gi.oracle_access is None:
        return _no(name, "oracle_access not declared: parsed field or substring is unrecorded")
    if gi.oracle_access is OracleAccess.SUBSTRING:
        return _no(
            name,
            "the oracle reads its answer by substring. Parse the structure and read the field: "
            "a body carries configuration keys, echoed input and refusal text, and each of "
            "those holds the token for a reason that is not the finding.",
        )
    return _ok(name, "the oracle reads a parsed field")


def check_rejection_vs_disclosure(gi: GateInputs) -> FPGateResult:
    """Mode 3: an error that echoes your input, read as a disclosure.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the foreign identifier genuinely is in
    the response body, so "does the response contain the victim's identifier"
    fires true. But a 4xx is a rejection by definition -- the server is telling
    you what it refused, and what it refused is the thing you sent. A disclosure
    verdict requires a 2xx carrying data the caller should not have. This is the
    one numbered false positive in the catalogue that is not an echo-matching
    error; it is a status-class misreading, and it is the cheapest of all the
    modes to check.
    """
    name = "rejection_vs_disclosure"
    if gi.response_status is None:
        return _no(name, "no response_status recorded, so the status class cannot be read")
    if not 200 <= gi.response_status < 300:
        return _no(
            name,
            f"HTTP {gi.response_status} is a rejection, not a disclosure. The server is "
            "reporting what it refused, and what it refused is what you sent. A disclosure "
            "needs a 2xx carrying foreign data.",
        )
    if gi.foreign_data_present is None:
        return _no(name, "foreign_data_present not recorded, so the 2xx body is unclassified")
    if not gi.foreign_data_present:
        return _no(
            name,
            f"HTTP {gi.response_status} carried no foreign data. A success response holding "
            "only your own data is the feature working.",
        )
    return _ok(name, f"HTTP {gi.response_status} carrying foreign data")


def check_echoed_identifier_normalisation(gi: GateInputs) -> FPGateResult:
    """Mode 4: a differential that is only the echoed identifier.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: a genuine byte difference between two
    arms is exactly what a working existence oracle looks like, and diffing two
    responses is the standard move. But if the only thing that differs is the
    identifier each arm echoed back, the difference is the request, not the
    server's knowledge. The catalogue's case: two ``400 ... not found`` bodies
    that differed, read as a working oracle; normalised, both arms were
    byte-identical and the oracle did not exist. So normalise every echoed
    identifier out of both arms *first*, then diff.
    """
    name = "echoed_identifier_normalisation"
    if gi.differential is None:
        return _no(name, "no differential supplied, so nothing was compared")
    d = gi.differential
    a, b = d.arm_a, d.arm_b
    for token in d.echoed_identifiers:
        if token:
            a = a.replace(token, "<ID>")
            b = b.replace(token, "<ID>")
    if a == b:
        return _no(
            name,
            f"after normalising {list(d.echoed_identifiers)} the two arms are byte-identical, "
            "so the only difference between them was the identifier each one echoed back. "
            "There is no existence oracle here.",
        )
    if not d.echoed_identifiers:
        return _ok(
            name,
            "the arms differ, and no echoed identifiers were declared -- which is itself a "
            "claim: list every identifier the arms carry before relying on this.",
        )
    return _ok(
        name,
        f"the arms still differ after normalising {list(d.echoed_identifiers)}",
    )


def check_raw_artifact_read(gi: GateInputs) -> FPGateResult:
    """Mode 5: the verdict came from a detector's summary, not the raw bytes.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the detector is right that the token is
    present. Refusal text, code strings and configuration fields routinely
    contain the very tokens a heuristic flags, and a summary strips the context
    that distinguishes them. The catalogue's case: a secret appeared inside a
    model's *refusal*, quoted back as the thing being refused, and a naive
    detector reported exfiltration. Reading the raw artifact showed a refusal.
    So the mode checks two things -- that a raw artifact was read at all, and
    that the match is not sitting inside refusal text.
    """
    name = "raw_artifact_read"
    if gi.evidence_source is None:
        return _no(name, "evidence_source not declared: raw artifact or detector summary?")
    if gi.evidence_source is EvidenceSource.DETECTOR_SUMMARY:
        return _no(
            name,
            "the verdict was read from a detector's summary. Read the raw artifact: the "
            "summary strips the context that separates a leak from a refusal quoting the "
            "thing it refused.",
        )
    if gi.match_context is None:
        return _no(name, "no match_context supplied, so the bytes around the match are unknown")
    lowered = gi.match_context.casefold()
    hit = next((m for m in REFUSAL_MARKERS if m in lowered), None)
    if hit:
        return _no(
            name,
            f"the match sits inside text containing {hit!r}, which means the token may be "
            "quoted as the thing being refused rather than disclosed. Re-read the raw bytes "
            "and establish what the surrounding response actually did.",
        )
    return _ok(name, "read from the raw artifact, and the match is not inside refusal text")


def check_placeholder_not_real_secret(gi: GateInputs) -> FPGateResult:
    """Mode 6: a placeholder read as a real secret.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: a secret-shaped string in an
    unexpected place is a genuine, high-severity-looking signal, and entropy
    heuristics score fixture values highly. But a real credential cannot contain
    ``changeme`` or be one character repeated and still authenticate, which is
    what makes the distinction mechanical rather than a judgement call. The
    corollary is the one that costs time: a value that passes the shape check
    still has to be *asserted real*, and the only honest assertion is that it
    was used and worked.
    """
    name = "placeholder_not_real_secret"
    if gi.secret_value is None:
        return _no(name, "no secret_value recorded, so its shape cannot be checked")
    value = gi.secret_value.strip()
    if not value:
        return _no(name, "secret_value is empty")
    hit = next((p.pattern for p in _PLACEHOLDER if p.search(value)), None)
    if hit:
        return _no(
            name,
            f"the value matches the placeholder shape {hit!r}. A credential that looks like "
            "this cannot authenticate, so its presence is a fixture, not an exposure.",
        )
    if gi.secret_is_real is None:
        return _no(
            name,
            "secret_is_real not recorded. A value that merely looks real is a lead; the "
            "assertion that has to be made is that it was used and worked.",
        )
    if not gi.secret_is_real:
        return _no(name, "the value is recorded as not real, so there is no exposure to report")
    return _ok(name, "the value is not placeholder-shaped and is recorded as real")


def check_liveness(gi: GateInputs) -> FPGateResult:
    """Mode 7: a rig that never ran, read as a clean negative.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: a dead runtime and a defended target
    produce exactly the same evidence -- none. Reading the transcript does not
    separate them either, because a tool that failed to start often fails
    quietly, and the agent narrates the silence as an absence of vulnerability.
    The catalogue records four such verdicts in a single session: a command that
    did not render the field under test, a colour-suppression variable that did
    not suppress, a regex carrying literal control bytes, and a run whose tools
    were absent. Each produced a confident "no bypass". The only separator is a
    positive control that fired in the same run.
    """
    name = "liveness"
    if gi.tool_started is None:
        return _no(name, "tool_started not recorded, so it is unknown whether the rig ran")
    if not gi.tool_started:
        return _no(
            name,
            "the tool under test never started. A rig that did not run and a target that "
            "defended itself produce identical evidence, so this is VOID, not a negative.",
        )
    if gi.positive_control_fired is None:
        return _no(name, "positive_control_fired not recorded, so the rig is unproven")
    if not gi.positive_control_fired:
        return _no(
            name,
            "no positive control fired in this run, so the rig was never shown to be able to "
            "produce a positive. A silent treatment beside a silent control is a VOID run and "
            "not a negative result.",
        )
    return _ok(name, "the rig started and a positive control fired in the same run")


def check_independent_control(gi: GateInputs) -> FPGateResult:
    """Mode 8: a control that tests the same thing as the treatment.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the control exists, it is named
    "positive control", and it is silent -- which looks like a clean result. The
    catalogue's case is exact: the control pointed at a host that was itself
    absent from the allowlist, so control and treatment tested the *same*
    containment, and a silent control could not distinguish "the installer never
    fetches" from "egress is blocked". Independence is a property of the design,
    not of the naming, and the second half of it is that treatment and control
    must differ in exactly one field. Two differences mean two explanations.
    """
    name = "independent_control"
    if gi.control_independent_of_treatment is None:
        return _no(name, "control independence not recorded")
    if not gi.control_independent_of_treatment:
        return _no(
            name,
            "the control is not independent of the treatment, so a silent control cannot "
            "distinguish the hypothesis from the containment both arms share. Redesign as a "
            "two-by-two.",
        )
    if gi.treatment_control_differing_fields is None:
        return _no(name, "the number of differing fields between the arms is not recorded")
    if gi.treatment_control_differing_fields != 1:
        return _no(
            name,
            f"treatment and control differ in {gi.treatment_control_differing_fields} fields. "
            "Two differences admit two explanations, and the result cannot be attributed to "
            "either. A minimal differential varies exactly one.",
        )
    return _ok(name, "an independent control differing from the treatment in exactly one field")


def check_identifier_novelty(gi: GateInputs) -> FPGateResult:
    """Mode 9: line novelty measured and reported as identifier novelty.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the lines really are new, and the
    identifiers really are in them, so grepping a diff for interesting names
    produces hits that are all individually true. A new line can contain an old
    identifier. The catalogue's case: a release diff produced 27,817 "new
    lines", three subsystems were reported as newly introduced, and extracting
    identifier tokens per artifact and set-differencing them showed 1,163
    genuinely new identifiers and all three subsystems already present in the
    prior release. This is string co-occurrence in a different costume.
    """
    name = "identifier_novelty"
    if gi.novelty_basis is None:
        return _no(name, "novelty_basis not recorded: token set-difference or line diff?")
    if gi.novelty_basis is NoveltyBasis.LINE_DIFF:
        return _no(
            name,
            "novelty was measured by diffing lines. A new line can contain an old identifier, "
            "so this measures line novelty. Extract identifier tokens per artifact "
            "independently and set-difference those.",
        )
    return _ok(name, "novelty measured by per-artifact identifier token set-difference")


def check_fixture_branch_coverage(gi: GateInputs) -> FPGateResult:
    """Mode 10: a fixture value that silently bypassed a second code path.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the finding reproduces, the PoC is
    real, and the write-up is therefore true of the configuration the fixture
    happened to encode. The catalogue's case: a convenience value for one
    fixture field turned out to drive an independent detection path that the
    fixture bypassed, so the finding was real but far more narrowly scoped than
    claimed, and the correction had to be filed after the fact. Enumerate every
    field the code branches on and test both values of each, or state in the
    report exactly which configuration the result is scoped to.
    """
    name = "fixture_branch_coverage"
    if gi.fixture_branch_fields is None:
        return _no(
            name,
            "the fields the code branches on were never enumerated, so the scope the result "
            "is valid for is unknown.",
        )
    if gi.fixture_fields_varied is None:
        return _no(name, "no record of which fixture fields were tested both ways")
    missing = [f for f in gi.fixture_branch_fields if f not in gi.fixture_fields_varied]
    if missing:
        return _no(
            name,
            f"the fixture branches on {missing} and those fields were not tested both ways. "
            "Either vary them or scope the claim explicitly to this configuration.",
        )
    if not gi.fixture_branch_fields:
        return _ok(
            name,
            "no branching fixture fields were declared. That is itself a claim: it means the "
            "code under test branches on nothing the fixture controls.",
        )
    return _ok(name, f"every branching field {list(gi.fixture_branch_fields)} tested both ways")


def check_poc_reachability(gi: GateInputs) -> FPGateResult:
    """Mode 11: a negative produced by a PoC that could not express a positive.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: this is not a failed control -- the
    control passes, the rig is alive, the run is valid, and the answer is still
    wrong. The branch under test was unreachable by construction in the fixture,
    so "tested, does not happen" was a statement about the fixture. The
    catalogue's case flipped to 60 of 60 positives once a different fixture
    value put the relevant data into the output. A negative is only as strong as
    the PoC's ability to express the positive, and that is a separate question
    from whether the rig works.
    """
    name = "poc_reachability"
    if gi.poc_can_express_the_positive is None:
        return _no(
            name,
            "no record that the PoC can express a positive at all. Demonstrate the positive "
            "with the branch forced before trusting its absence.",
        )
    if not gi.poc_can_express_the_positive:
        return _no(
            name,
            "the PoC cannot express the positive, so the branch under test is unreachable by "
            "construction and its silence is a statement about the fixture, not the target.",
        )
    return _ok(name, "the PoC was shown able to express a positive")


def check_oracle_strength(gi: GateInputs) -> FPGateResult:
    """Mode 12: an oracle too weak to carry the verdict it was asked to carry.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: every oracle looks adequate when it
    agrees with the hypothesis. The catalogue's strongest empirical claim is
    that all six numbered false positives occurred behind interpretive oracles
    and none behind mechanical ones, so strength is not a stylistic preference.
    Ranking it 0-4 and refusing below 2 is what stops volume becoming noise:
    strength 0 is string co-occurrence and model narration, which auto-reject.
    An unknown oracle kind is unscored, and an unscored oracle fails rather than
    taking a default.
    """
    name = "oracle_strength"
    if gi.oracle_kind is None:
        return _no(name, "no oracle named. A probe without a named oracle has no verdict.")
    strength = ORACLE_STRENGTH.get(gi.oracle_kind)
    if strength is None:
        return _no(
            name,
            f"oracle kind {gi.oracle_kind!r} is not in the strength table, so it is unscored. "
            f"An unscored oracle fails; score it against {sorted(ORACLE_STRENGTH)} or add it "
            "deliberately.",
        )
    if strength < STRENGTH_FLOOR:
        extra = (
            " Strength 0 is string co-occurrence or model narration, which auto-reject."
            if strength == 0
            else ""
        )
        return _no(
            name,
            f"oracle {gi.oracle_kind!r} is strength {strength}, below the floor of "
            f"{STRENGTH_FLOOR}.{extra}",
        )
    return _ok(name, f"oracle {gi.oracle_kind!r} is strength {strength}")


def check_single_source_dedup(gi: GateInputs) -> FPGateResult:
    """Mode 13: a single-source zero read as a zero.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the query ran, the source answered, and
    the answer was zero -- there is nothing visibly wrong with it. Indexes
    disagree in both directions: a repository-level advisory is invisible to a
    package-level database, and a repository's own advisories page can say
    "there aren't any" while a national database carries seven entries for it.
    One source answering zero is one source's coverage, and the remedy is
    cheap: ask a second.
    """
    name = "single_source_dedup"
    if gi.dedup_sources_answered is None:
        return _no(name, "the number of prior-art sources that answered is not recorded")
    if gi.dedup_sources_answered < 2:
        return _no(
            name,
            f"only {gi.dedup_sources_answered} prior-art source(s) answered. Never treat a "
            "single-source zero as a zero: indexes disagree in both directions, and asking a "
            "second costs one query.",
        )
    return _ok(name, f"{gi.dedup_sources_answered} prior-art sources answered")


def check_confidence_band(gi: GateInputs) -> FPGateResult:
    """Mode 14: a fitted quantity reported confidently below its own band.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the classifier returned a label and a
    number, and the label looked like a result. The catalogue's case is a
    severity classifier that reported a confident growth law with an R-squared
    of -2.63 -- a through-origin fit worse than predicting the mean -- because
    nothing in the code required the fit to be any good before naming it. The
    remedy is an explicit inconclusive band guarded on the goodness of fit, not
    a reviewer noticing the number.
    """
    name = "confidence_band"
    if gi.fit_r_squared is None:
        return _no(
            name,
            "a quantitative fit is claimed but its goodness of fit is not recorded, so the "
            "label cannot be distinguished from a label applied to noise.",
        )
    if gi.fit_r_squared < gi.fit_r_squared_floor:
        return _no(
            name,
            f"the fit's R-squared is {gi.fit_r_squared} against a floor of "
            f"{gi.fit_r_squared_floor}. Report INCONCLUSIVE rather than a named law: a "
            "negative R-squared is a fit worse than predicting the mean.",
        )
    return _ok(name, f"R-squared {gi.fit_r_squared} at or above {gi.fit_r_squared_floor}")


def check_coverage_denominator(gi: GateInputs) -> FPGateResult:
    """Mode 15: coverage reported against a denominator nobody checked.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the generator reported complete
    coverage and raised no error, which is what a working generator also does.
    The catalogue's case: a combinatorial library emitted 105 rows where the
    independently computed feasible minimum was 384, so it was not a covering
    array at all -- and separately, a constraint predicate reading an unbound
    variable rejected rows whose completions were legal, producing "100%
    coverage" of a denominator that was itself wrong. Compute the feasible
    minimum independently and compare.
    """
    name = "coverage_denominator"
    if gi.coverage_rows_emitted is None or gi.coverage_feasible_minimum is None:
        return _no(
            name,
            "coverage is claimed without both the rows emitted and an independently computed "
            "feasible minimum. A generator reporting complete coverage of its own denominator "
            "is reporting nothing.",
        )
    if gi.coverage_rows_emitted < gi.coverage_feasible_minimum:
        return _no(
            name,
            f"{gi.coverage_rows_emitted} rows emitted against an independently computed "
            f"feasible minimum of {gi.coverage_feasible_minimum}. The set cannot cover what "
            "it claims to cover, and it reported no error.",
        )
    return _ok(
        name,
        f"{gi.coverage_rows_emitted} rows at or above the independent feasible minimum "
        f"{gi.coverage_feasible_minimum}",
    )


def check_detector_target(gi: GateInputs) -> FPGateResult:
    """Mode 16: the detector was pointed at the wrong file.

    WHY THE OBVIOUS CHECK IS NOT ENOUGH: the fire rate was high, consistent and
    reproducible, which is what a working detector looks like. The catalogue's
    case: a detector measured an 81.7% fire rate because it was run against the
    PoC file instead of the source under test, and PoCs call the flagged
    accessor for their own assertions. Every number a detector produces is a
    number about whatever it was pointed at, so the target has to be recorded
    and compared with the subject.
    """
    name = "detector_target"
    if gi.detector_ran_against is None or gi.subject_under_test is None:
        return _no(
            name,
            "the detector's target or the subject under test is unrecorded, so the measurement "
            "cannot be attributed to anything.",
        )
    if gi.detector_ran_against != gi.subject_under_test:
        return _no(
            name,
            f"the detector ran against {gi.detector_ran_against!r} but the subject under test "
            f"is {gi.subject_under_test!r}. The rate measured is a rate about the wrong file; "
            "a PoC calls the flagged construct for its own assertions.",
        )
    return _ok(name, f"the detector ran against the subject {gi.subject_under_test!r}")


#: Cheapest and most decisive first, so an unrealisable candidate dies before
#: anyone invests in quantifying its impact.
MODES: tuple[Mode, ...] = (
    Mode("liveness", "false negatives, one session", check_liveness),
    Mode("own_input_echo", "FP#4, FP#5, FP#6", check_own_input_echo),
    Mode("oracle_strength", "rule A10", check_oracle_strength),
    Mode("oracle_is_a_parsed_field", "rule A5", check_oracle_is_a_parsed_field),
    Mode("rejection_vs_disclosure", "FP#1", check_rejection_vs_disclosure, ClaimKind.DISCLOSURE),
    Mode(
        "echoed_identifier_normalisation",
        "FP#2",
        check_echoed_identifier_normalisation,
        ClaimKind.DIFFERENTIAL,
    ),
    Mode("raw_artifact_read", "FP#3", check_raw_artifact_read),
    Mode("independent_control", "VOID-2 / CONFOUNDED", check_independent_control),
    Mode("poc_reachability", "the PoC-unreachability void", check_poc_reachability),
    Mode(
        "placeholder_not_real_secret",
        "rule A1, admissible oracles",
        check_placeholder_not_real_secret,
        ClaimKind.SECRET_EXPOSURE,
    ),
    Mode("detector_target", "harness FP (d)", check_detector_target),
    Mode(
        "fixture_branch_coverage",
        "the scoping false positive",
        check_fixture_branch_coverage,
    ),
    Mode(
        "identifier_novelty",
        "the false start: line vs identifier novelty",
        check_identifier_novelty,
        ClaimKind.NOVELTY,
    ),
    Mode(
        "single_source_dedup",
        "dedup rule (a): never trust a single-source zero",
        check_single_source_dedup,
        ClaimKind.NOVELTY,
    ),
    Mode("confidence_band", "harness FP (a)", check_confidence_band, ClaimKind.QUANTITATIVE_FIT),
    Mode(
        "coverage_denominator",
        "harness FP (b)",
        check_coverage_denominator,
        ClaimKind.COVERAGE,
    ),
)


# =================================================================== the runner


@dataclass(frozen=True)
class GateReport:
    results: tuple[FPGateResult, ...]

    def _count(self, state: CheckState) -> int:
        return sum(1 for r in self.results if r.state is state)

    @property
    def n_passed(self) -> int:
        return self._count(CheckState.PASSED)

    @property
    def n_failed(self) -> int:
        return self._count(CheckState.FAILED)

    @property
    def n_suppressed(self) -> int:
        return self._count(CheckState.SUPPRESSED)

    @property
    def n_not_applicable(self) -> int:
        return self._count(CheckState.NOT_APPLICABLE)

    @property
    def failures(self) -> tuple[FPGateResult, ...]:
        return tuple(r for r in self.results if r.state is CheckState.FAILED)

    @property
    def suppressed_modes(self) -> tuple[str, ...]:
        return tuple(r.mode for r in self.results if r.state is CheckState.SUPPRESSED)

    @property
    def clean(self) -> bool:
        """No failures *and* at least one mode actually passed.

        The second half matters: a run in which every mode was suppressed or
        declared inapplicable has no failures and has also gated nothing.
        """
        return self.n_failed == 0 and self.n_passed > 0

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "passed": self.n_passed,
            "failed": self.n_failed,
            "suppressed": self.n_suppressed,
            "not_applicable": self.n_not_applicable,
            "results": [
                {"mode": r.mode, "state": r.state.value, "detail": r.detail} for r in self.results
            ],
        }


def run_gate(gi: GateInputs, modes: Sequence[Mode] | None = None) -> GateReport:
    """Run every mode. Does not short-circuit, and nothing is capped or hidden.

    A check that raises is recorded as FAILED with the exception in its detail.
    A check returning anything other than an ``FPGateResult`` is also FAILED: a
    mode that cannot state its own verdict has not produced one.
    """
    table = tuple(modes) if modes is not None else MODES
    known = {m.name for m in table}
    unknown = sorted(set(gi.suppressed) - known)
    if unknown:
        raise ValueError(
            f"cannot suppress unknown mode(s) {unknown}. A typo'd suppression silently "
            f"suppresses nothing, which is the opposite of what the operator asked for. "
            f"Known modes: {sorted(known)}"
        )

    results: list[FPGateResult] = []
    for mode in table:
        reason = str(gi.suppressed.get(mode.name, "") or "").strip()
        if reason:
            results.append(
                FPGateResult(
                    mode.name,
                    CheckState.SUPPRESSED,
                    f"suppressed by the operator: {reason}",
                )
            )
            continue
        if mode.claim is not None:
            asserts = gi.asserts(mode.claim)
            if asserts is None:
                results.append(
                    _no(
                        mode.name,
                        "the claim set was not declared, so no claim-scoped mode can know "
                        "whether it applies. An undeclared claim set is not an empty one.",
                    )
                )
                continue
            if not asserts:
                results.append(
                    FPGateResult(
                        mode.name,
                        CheckState.NOT_APPLICABLE,
                        f"the candidate does not claim {mode.claim.value}",
                    )
                )
                continue
        try:
            result = mode.check(gi)
        except Exception as exc:
            result = _no(mode.name, f"the check itself raised {type(exc).__name__}: {exc}")
        if not isinstance(result, FPGateResult):
            result = _no(
                mode.name,
                f"the check returned {type(result).__name__}, not an FPGateResult. A mode that "
                "cannot state its own verdict has not produced one.",
            )
        results.append(result)
    return GateReport(tuple(results))


def summarise(report: GateReport) -> str:
    """A flat, greppable rendering. Suppressions are counted in the open."""
    lines = [f"[{r.state.value}] {r.mode}: {r.detail}" for r in report.results]
    lines.append(
        f"\nfp gate: {report.n_passed}/{len(report.results)} passed, "
        f"{report.n_failed} failed, {report.n_suppressed} suppressed, "
        f"{report.n_not_applicable} not applicable -- "
        f"{'CLEAN' if report.clean else 'NOT CLEAN'}"
    )
    return "\n".join(lines)
