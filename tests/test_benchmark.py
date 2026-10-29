"""The benchmark's self-consistency checks.

A benchmark is an instrument, and an instrument that is never calibrated is the
thing the harness exists to refuse. So these tests do not check that the gates
are good. They check that the *measurement* is honest:

* every false-positive shape has both members of its pair, in both corpora;
* no case is unlabelled, and no label contradicts its own member;
* the sixteen catalogued shapes are all present by name, so a quiet deletion
  fails the build instead of improving the score;
* the gates cannot read the label, enforced by re-running every case with
  decoy label keys injected into the observation;
* the committed results reproduce exactly, over both transports;
* and a deliberately broken scorer **fails** -- without that last one, the
  reproduction test only proves the file was written by this code, not that the
  code measures anything.
"""

from __future__ import annotations

import copy
import json

import pytest
from benchmarks import gates
from benchmarks.fp_corpus import (
    LABEL_KEYS,
    REQUIRED_FIELDS,
    VERDICT_CLASS,
    Case,
    load_cases,
    load_critic,
    load_holdout,
    pairs,
)
from benchmarks.run_benchmark import (
    RESULTS,
    _adjudicate_all,
    _comparable,
    build,
    fisher_two_sided,
    measure_c2,
)
from benchmarks.scoring import CLASSES, Score, classify_result, confusion, score
from examples.local_target.app import (
    MODES,
    PLACEHOLDER_TOKEN,
    Target,
    fetch_host,
    guard_host,
    serve,
)

CASES = load_cases()
HOLDOUT = load_holdout()
CRITIC = load_critic()
ALL_CASES = CASES + HOLDOUT + CRITIC

#: The sixteen catalogued false verdicts, by the shape id each is filed under.
#: Named here so that removing a hard case from the corpus breaks the build
#: rather than raising the score.
CATALOGUED_SHAPES = (
    "fp01-echo-in-4xx-read-as-disclosure",
    "fp02-differential-on-an-echoed-identifier",
    "fp03-secret-inside-a-refusal",
    "fp04-marker-in-the-source-we-submitted",
    "fp05-substring-hit-on-the-listeners-own-config",
    "fp06-nonce-inside-the-url-we-supplied",
    "fs07-line-novelty-mistaken-for-identifier-novelty",
    "void08-negative-from-a-probe-that-never-reached-the-app",
    "void09-control-and-treatment-share-the-containment",
    "fn10-the-field-under-test-was-never-rendered",
    "fn11-colour-escapes-defeated-the-oracle-string",
    "fn12-literal-control-bytes-written-into-the-oracle",
    "scope13-a-fixture-pinned-a-field-the-target-branches-on",
    "self14-a-fit-worse-than-the-mean-reported-as-a-growth-law",
    "self15-a-covering-array-below-its-own-feasible-minimum",
    "self16-blank-lines-flagged-as-hard-wraps",
)

#: The two documented near-misses. They are the corpus's only evidence that the
#: gates' false-negative rate is not zero, so they are pinned by name.
NEAR_MISS_SHAPES = (
    "hard18-a-true-finding-nearly-retracted-for-poc-unreachability",
    "hard19-a-second-code-path-wrongly-cleared",
)


# ------------------------------------------------------------ corpus integrity


def test_the_sixteen_catalogued_shapes_are_all_present():
    present = {c.shape for c in CASES}
    missing = [s for s in CATALOGUED_SHAPES if s not in present]
    assert not missing, f"the corpus is missing catalogued shapes: {missing}"
    assert len(CATALOGUED_SHAPES) == 16


def test_both_documented_near_misses_are_present_and_are_the_hard_cases():
    present = {c.shape for c in CASES}
    for shape in NEAR_MISS_SHAPES:
        assert shape in present, f"{shape} is the evidence that recall is not 1.0 by construction"
    for case in CASES:
        if case.shape in NEAR_MISS_SHAPES:
            assert case.label_basis, f"{case.id}: a hard case must carry its label_basis"


@pytest.mark.parametrize("corpus_name", ["cases", "holdout", "critic"])
def test_every_shape_has_both_members_of_its_pair(corpus_name):
    corpus = {"cases": CASES, "holdout": HOLDOUT, "critic": CRITIC}[corpus_name]
    incomplete = {
        shape: sorted(members) for shape, members in pairs(corpus).items() if len(members) != 2
    }
    assert not incomplete, f"shapes without a complete pair: {incomplete}"
    for shape, members in pairs(corpus).items():
        assert set(members) == {"false", "genuine"}, shape


def test_no_case_is_unlabelled():
    for case in ALL_CASES:
        assert case.member in ("false", "genuine"), case.id
        assert case.correct_decision in ("REFUSED", "SUPPORTED"), case.id
        assert case.correct_verdict in VERDICT_CLASS, case.id
        assert case.note.strip(), f"{case.id} has no note on why a naive check gets it wrong"
        assert case.catalogue_ref.strip(), case.id
        assert case.shape_title.strip(), case.id
        assert 0 <= case.naive_oracle_strength <= 4, case.id
        assert 0 <= case.gated_oracle_strength <= 4, case.id
        assert isinstance(case.asserts_absence, bool), case.id
        assert isinstance(case.conclusion_in_fixture, bool), case.id
        assert case.label_rule.strip(), f"{case.id} does not say which rule its label claims"


def test_the_decision_label_follows_from_the_member():
    """``false`` must be refused and ``genuine`` must be supported, with no exceptions.

    This is the invariant that makes the labels defensible rather than a matter
    of taste: the pair structure fixes the expected decision, so the only
    judgement left in a label is which member a fixture is -- which is what the
    ``note`` and ``label_basis`` fields argue.
    """
    for case in ALL_CASES:
        expected = "REFUSED" if case.member == "false" else "SUPPORTED"
        assert case.correct_decision == expected, case.id


def test_case_ids_are_unique():
    ids = [c.id for c in ALL_CASES]
    assert len(ids) == len(set(ids))


def test_every_observation_kind_is_implemented():
    for case in ALL_CASES:
        assert case.observation["kind"] in gates.known_kinds(), case.id


def test_the_holdout_is_never_folded_into_the_headline_corpus():
    for held in (HOLDOUT, CRITIC):
        assert not ({c.id for c in CASES} & {c.id for c in held})
        assert not ({c.shape for c in CASES} & {c.shape for c in held})
    assert not ({c.id for c in HOLDOUT} & {c.id for c in CRITIC})


# ------------------------------------------------------------- label isolation


def test_gates_cannot_see_the_label():
    """Re-adjudicate with decoy labels injected, and demand identical answers.

    The decoys are deliberately *wrong*: if any gate ever reads a label key, it
    reads the opposite of the truth and the decision moves.
    """
    for case in ALL_CASES:
        for enabled in (True, False):
            clean = gates.adjudicate(copy.deepcopy(case.observation), gates_enabled=enabled)
            poisoned = copy.deepcopy(case.observation)
            flip = "SUPPORTED" if case.correct_decision == "REFUSED" else "REFUSED"
            for key in LABEL_KEYS:
                poisoned[key] = flip
            poisoned["member"] = "genuine" if case.member == "false" else "false"
            tainted = gates.adjudicate(poisoned, gates_enabled=enabled)
            assert (clean.decision, clean.verdict) == (tainted.decision, tainted.verdict), case.id


def test_the_loader_refuses_a_case_whose_observation_carries_a_label(tmp_path):
    (tmp_path / "bad.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "x",
                        "shape": "x",
                        "shape_title": "x",
                        "catalogue_ref": "x",
                        "member": "false",
                        "correct_decision": "REFUSED",
                        "correct_verdict": "KILL",
                        "naive_oracle_strength": 0,
                        "gated_oracle_strength": 3,
                        "note": "x",
                        "label_rule": "A2",
                        "asserts_absence": False,
                        "conclusion_in_fixture": False,
                        "observation": {"kind": "numeric_claim", "member": "genuine"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="leaks label keys"):
        load_cases(tmp_path)


def test_the_loader_refuses_an_unlabelled_case(tmp_path):
    (tmp_path / "bad.json").write_text(
        json.dumps({"cases": [{"id": "x", "observation": {"kind": "numeric_claim"}}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="is missing"):
        load_cases(tmp_path)


# --------------------------------------------------- the committed results file


def test_the_committed_results_exist_and_parse():
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    assert payload["corpus"]["cases"] == len(CASES)
    assert (RESULTS / "fp_corpus.md").read_text(encoding="utf-8").startswith("# Benchmark results")


@pytest.mark.parametrize("use_http", [False, True])
def test_the_scorer_reproduces_the_committed_results_exactly(use_http):
    committed = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    fresh, _ = build(use_http=use_http)
    assert _comparable(fresh) == _comparable(committed)


def test_a_broken_scorer_fails_the_reproduction_check(monkeypatch):
    """Without this test the one above only proves the file was written by this code."""
    committed = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(
        gates,
        "adjudicate",
        lambda observation, *, gates_enabled=True, arm=None: gates.GateResult(
            "SUPPORTED", "CANDIDATE", "broken", "always supports"
        ),
    )
    broken, _ = build(use_http=False)
    assert _comparable(broken) != _comparable(committed)
    assert broken["c2"]["overall"]["gated"]["precision"] == pytest.approx(0.5)


def test_a_broken_scorer_is_detected_per_shape(monkeypatch):
    """A scorer that always refuses must show recall 0.0, not a silent pass."""
    monkeypatch.setattr(
        gates,
        "adjudicate",
        lambda observation, *, gates_enabled=True, arm=None: gates.GateResult(
            "REFUSED", "KILL", "broken", "always refuses"
        ),
    )
    results = _adjudicate_all(CASES)
    c2 = measure_c2(CASES, results)
    assert c2["overall"]["gated"]["recall"] == 0.0
    assert c2["overall"]["gated"]["precision"] is None  # nothing was ever supported


def test_a_broken_verdict_classifier_moves_the_c1_matrix(monkeypatch):
    committed = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    monkeypatch.setattr("benchmarks.run_benchmark.classify_result", lambda d, v: "NO_BUG")
    broken, _ = build(use_http=False)
    assert broken["c1"] != committed["c1"]


# ------------------------------------------------------------------- the scorer


def test_score_arithmetic():
    s = score([("genuine", "SUPPORTED"), ("genuine", "REFUSED"), ("false", "REFUSED")])
    assert (s.tp, s.fn, s.tn, s.fp) == (1, 1, 1, 0)
    assert s.recall == pytest.approx(0.5)
    assert s.precision == pytest.approx(1.0)
    assert s.f1 == pytest.approx(2 / 3)


def test_an_empty_score_reports_none_rather_than_one():
    """A rate with no denominator is not 1.0, and must not render as a pass."""
    assert Score().precision is None
    assert Score().recall is None
    assert Score().accuracy is None


def test_confusion_rejects_a_class_it_does_not_know():
    with pytest.raises(ValueError, match="not one of"):
        confusion([("FINDING", "MAYBE")])


def test_classify_result_keeps_void_apart_from_no_bug():
    assert classify_result("REFUSED", "VOID") == "UNINTERPRETABLE"
    assert classify_result("REFUSED", "CONFOUNDED") == "UNINTERPRETABLE"
    assert classify_result("REFUSED", "KILL") == "NO_BUG"
    assert classify_result("SUPPORTED", "no-bug") == "NO_BUG"
    assert classify_result("SUPPORTED", "CANDIDATE") == "FINDING"
    assert set(CLASSES) == {"FINDING", "NO_BUG", "UNINTERPRETABLE"}


def test_verdict_class_covers_every_verdict_a_case_can_declare():
    assert {c.correct_verdict for c in ALL_CASES} <= set(VERDICT_CLASS)


# ------------------------------------------------------- the near-miss contract


def test_the_near_misses_must_not_be_called_findings_or_clean_negatives():
    """The whole of C1 in one assertion.

    For the two recorded near-misses the correct answer is neither "no bug" nor
    "a finding". A gate that scores them as either is wrong in one of the two
    ways that actually cost something: it buries a real finding, or it invents
    one.
    """
    for case in CASES:
        if case.shape not in NEAR_MISS_SHAPES or case.member != "false":
            continue
        result = gates.adjudicate(case.observation)
        assert classify_result(result.decision, result.verdict) == "UNINTERPRETABLE", case.id
        unguarded = gates.adjudicate(case.observation, gates_enabled=False)
        assert classify_result(unguarded.decision, unguarded.verdict) != "UNINTERPRETABLE", (
            f"{case.id}: the unguarded baseline cannot emit UNINTERPRETABLE, so if it did, "
            "the baseline is not actually unguarded"
        )


def test_adjudicate_refuses_an_unknown_observation_kind():
    with pytest.raises(ValueError, match="unknown observation kind"):
        gates.adjudicate({"kind": "no-such-kind"})


# --------------------------------------------------------------- the local target


def test_the_target_refuses_to_bind_anything_but_loopback():
    with pytest.raises(ValueError, match="loopback only"):
        serve("0.0.0.0")
    with pytest.raises(ValueError, match="loopback only"):
        serve("192.0.2.10")


def test_the_target_rejects_an_unknown_mode():
    with pytest.raises(ValueError, match="mode must be one of"):
        Target("whatever")
    assert MODES == ("flawed", "patched", "refuse-all", "unauthorized-all")


def test_the_authorization_flaw_and_its_enforced_sibling_disagree():
    t = Target("flawed")
    flawed = t.respond("GET", "/v1/documents/doc_2002", headers={"X-Tenant": "t_alpha"})
    control = t.respond("GET", "/v1/invoices/inv_2002", headers={"X-Tenant": "t_alpha"})
    assert flawed.status == 200 and flawed.body["owner_tenant"] == "t_beta"
    assert control.status == 403


def test_patching_closes_the_flaw_and_leaves_the_control_alone():
    t = Target("patched")
    assert t.respond("GET", "/v1/documents/doc_2002", headers={"X-Tenant": "t_alpha"}).status == 403
    assert t.respond("GET", "/v1/invoices/inv_2002", headers={"X-Tenant": "t_alpha"}).status == 403
    assert t.respond("GET", "/v1/invoices/inv_1001", headers={"X-Tenant": "t_alpha"}).status == 200


def test_the_existence_oracle_survives_echo_normalisation_and_the_echo_route_does_not():
    t = Target("flawed")
    exists = t.respond("GET", "/v1/exists/doc_1001")
    absent = t.respond("GET", "/v1/exists/doc_9999")
    assert (exists.status, absent.status) == (400, 404)
    echo_a = t.respond("GET", "/v1/echo", "value=doc_1001")
    echo_b = t.respond("GET", "/v1/echo", "value=doc_9999")
    assert echo_a.status == echo_b.status == 400
    assert echo_a.body["echo"] != echo_b.body["echo"]
    strip = lambda b, v: json.dumps(b, sort_keys=True).replace(v, "<X>")
    assert strip(echo_a.body, "doc_1001") == strip(echo_b.body, "doc_9999")


def test_only_the_placeholder_token_fails_to_authenticate():
    t = Target("flawed")
    placeholder = t.respond("GET", "/v1/config/token").body["api_token"]
    session = t.respond("GET", "/v1/config/session").body["api_token"]
    assert placeholder == PLACEHOLDER_TOKEN
    assert placeholder != session
    auth = lambda tok: t.respond("GET", "/v1/whoami", headers={"Authorization": f"Bearer {tok}"})
    assert auth(placeholder).status == 401
    assert auth(session).status == 200


def test_the_two_url_parsers_disagree_which_is_the_whole_flaw():
    url = "https://allowed.example\\@listener.invalid/p"
    assert guard_host(url) == "allowed.example"
    assert fetch_host(url) == "listener.invalid"
    body = json.dumps({"url": url}).encode()
    flawed = Target("flawed").respond("POST", "/v1/fetch", body=body)
    patched = Target("patched").respond("POST", "/v1/fetch", body=body)
    assert flawed.status == 200 and flawed.body["final_host"] == "listener.invalid"
    assert patched.status == 403


def test_the_injected_tool_description_breaks_its_registered_digest():
    import hashlib

    flawed = Target("flawed")
    served = {t["name"]: t["description"] for t in flawed.respond("GET", "/v1/tools").body["tools"]}
    approved = flawed.respond("GET", "/v1/tools/registry").body["approved_sha256"]
    digest = lambda s: hashlib.sha256(s.encode()).hexdigest()
    assert digest(served["lookup_shipment"]) != approved["lookup_shipment"]
    assert digest(served["match_carrier"]) == approved["match_carrier"]
    patched = Target("patched")
    served = {
        t["name"]: t["description"] for t in patched.respond("GET", "/v1/tools").body["tools"]
    }
    assert digest(served["lookup_shipment"]) == approved["lookup_shipment"]


@pytest.mark.parametrize(("mode", "status"), [("refuse-all", 403), ("unauthorized-all", 401)])
def test_the_degenerate_modes_answer_every_route_identically_health_included(mode, status):
    t = Target(mode)
    for path in ("/v1/health", "/v1/documents/doc_1001", "/v1/invoices/inv_1001", "/v1/tools"):
        assert t.respond("GET", path, headers={"X-Tenant": "t_alpha"}).status == status


def test_the_degenerate_modes_void_the_run_rather_than_clearing_the_target():
    """The C1 effect, measured against the live target rather than a fixture."""
    from benchmarks.oracle_experiment import Client, _lattice

    from controlarm.controls.run import Verdict

    for mode in ("refuse-all", "unauthorized-all"):
        verdict, _ = _lattice(Client(Target(mode)))
        assert verdict is Verdict.VOID, mode
    for mode in ("flawed", "patched"):
        verdict, _ = _lattice(Client(Target(mode)))
        assert verdict is not Verdict.VOID, mode


# ------------------------------------------------- the measured claims, pinned


def test_c1_prediction_is_pinned_so_a_regression_is_visible():
    """Pin the *shape* of the C1 result, not a hoped-for value.

    If the guarded configuration ever starts calling an untrustworthy negative
    "no bug", that is the single most important regression this repository can
    have, and it must fail the build rather than quietly change a markdown file.
    """
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    un = payload["c1"]["untrustworthy_negatives"]
    assert un["gated"]["called_no_bug"] == 0
    assert un["gated"]["called_finding"] == 0
    # The provenance arm calls every one of them "no bug", which is what the
    # corpus records happening. It is not the comparison: it cannot emit a
    # refusal verdict at all, so this assertion is about history, not effect.
    assert un["naive"]["called_no_bug"] == un["naive"]["cases"]
    # The arm that matters. This is deliberately a floor and not an equality:
    # if a future fair baseline gets every case right, the measured advantage of
    # the gates over a competent engineer is zero and the published claim has to
    # say so rather than this test hiding it.
    assert un["fair"]["called_no_bug"] >= 0
    assert un["fair"]["called_no_bug"] <= un["naive"]["called_no_bug"]


def test_the_holdout_failures_are_published_rather_than_fixed():
    """The holdout must keep failing, or it has stopped being a holdout.

    If someone repairs the gates until this passes, the honest move is to write
    a new holdout against the repaired implementation and let this assertion
    change along with the published numbers -- not to delete it.
    """
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    holdout = payload["c2_holdout"]
    assert holdout["failures"], (
        "the adversarial holdout now passes. Either the gates genuinely encode the rules, in "
        "which case write a harder holdout and update this test, or the holdout was weakened."
    )
    assert holdout["overall"]["gated"]["recall"] < 1.0
    for failure in holdout["failures"]:
        assert failure["why_the_gate_was_wrong"].strip(), failure["id"]


def test_the_oracle_experiment_varies_only_the_oracle():
    """Both arms must see the same lattice verdict for the same probe and mode."""
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    by_key: dict[tuple[str, str], set[str]] = {}
    for row in payload["oracle_experiment"]["rows"]:
        by_key.setdefault((row["probe"], row["mode"]), set()).add(row["lattice_verdict"])
    for key, verdicts in by_key.items():
        assert len(verdicts) == 1, f"{key} saw different lattice verdicts per oracle: {verdicts}"


def test_the_oracle_experiment_includes_a_probe_the_strong_oracle_gets_wrong():
    """A benchmark in which the favoured configuration never errs is a brochure."""
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    mech = payload["oracle_experiment"]["determinate"]["mechanical"]
    assert mech["false_verdicts"] > 0, (
        "the mechanical oracle now scores perfectly on the determinate modes. Add a probe it "
        "cannot answer before publishing the comparison."
    )


def test_cases_are_loaded_in_a_stable_order():
    assert [c.id for c in load_cases()] == [c.id for c in CASES]
    assert isinstance(CASES[0], Case)


# ------------------------------------------- the external critique set, pinned


def test_the_external_critique_set_is_a_permanent_fixture():
    """Twelve cases somebody else wrote. They may not be deleted or weakened.

    Four of the six failures they found were implementation defects and are
    repaired; two are limits of the rule and are published unfixed. All twelve
    stay, either way, because a repair is only auditable next to the case that
    forced it.
    """
    assert len(CRITIC) == 12
    assert {c.id for c in CRITIC} == {
        f"c0{n}-{m}" for n in range(1, 7) for m in ("false", "genuine")
    }
    assert (benchmarks_critic_dir := (RESULTS.parent / "fp_corpus" / "critic")).is_dir()
    assert (benchmarks_critic_dir / "run_critic.py").is_file()


def test_the_four_repaired_critique_cases_stay_repaired():
    """The named implementation defects, each pinned to the case that found it.

    These were the gates failing their own documented rules, so repairing them
    is correct and a regression is a regression. The ``label_rule`` assertion
    below separately guarantees each one is repaired through the right gate.
    """
    repaired = {
        "c01-false": "an echo reflected into a JSON key name",
        "c01-genuine": "the same key-name echo, with a key the echo cannot explain",
        "c02-false": "LISTENER.invalid against listener.invalid",
        "c02-genuine": "a control inside the allowlist",
        "c05-false": "a positive control that names no observable",
        "c06-false": "a markdown list read as hard wraps",
    }
    by_id = {c.id: c for c in CRITIC}
    for case_id, why in repaired.items():
        case = by_id[case_id]
        result = gates.adjudicate(case.observation)
        assert result.decision == case.correct_decision, f"{case_id} regressed: {why}"


def test_the_two_published_failures_of_the_external_set_are_still_published():
    """A failure published as a limit of the rule must not be quietly papered over.

    If somebody does find a mechanical statement of rule A6 that keeps FP#3 and
    releases ``c03-genuine``, or a provenance record that settles ``c04-false``,
    the honest move is to change this test along with the published numbers --
    not to delete it.
    """
    by_id = {c.id: c for c in CRITIC}
    for case_id in ("c03-genuine", "c04-false"):
        case = by_id[case_id]
        result = gates.adjudicate(case.observation)
        assert result.decision != case.correct_decision, (
            f"{case_id} now passes. Either rule A6 or rule A5 has been given a mechanical "
            "statement that was previously thought impossible, in which case update GAPS.md "
            "G2c and this test, or the case was weakened."
        )


# ------------------------------------------------- a case passes through its own gate


def test_every_passing_case_passes_through_the_gate_its_label_names():
    """No case may pass for a different reason than the one it was written to test.

    This is the assertion that would have caught the adversarial holdout's
    ``h01-false``, whose ``label_basis`` claimed the A3 canonicalisation branch
    refused it when in fact A9 did -- so one of the holdout's two passes was an
    accident and the defect the case targeted was never exercised. A case the
    gate gets *wrong* is exempt: it is already published as a failure.
    """
    wrong_gate = []
    for case in ALL_CASES:
        result = gates.adjudicate(case.observation)
        if result.decision != case.correct_decision:
            continue
        tokens = set(result.rule.split("+")) | set(result.fired)
        if case.label_rule not in tokens:
            wrong_gate.append(
                f"{case.id}: label_rule={case.label_rule!r} but the gate decided it with "
                f"rule={result.rule!r} fired={result.fired!r}"
            )
    assert not wrong_gate, "cases passing through the wrong gate:\n" + "\n".join(wrong_gate)


def test_a_label_rule_on_a_passing_case_is_a_rule_the_gate_can_emit():
    """``h03-false`` names ``B-route``, which is deliberately not implemented.

    That is the finding, and the case fails because of it. But no *passing* case
    may name a rule the implementation does not have, or the assertion above
    would be satisfiable by inventing a rule id.
    """
    emitted = set()
    for case in ALL_CASES:
        result = gates.adjudicate(case.observation)
        emitted |= set(result.rule.split("+")) | set(result.fired)
    for case in ALL_CASES:
        result = gates.adjudicate(case.observation)
        if result.decision == case.correct_decision:
            assert case.label_rule in emitted, case.id


def test_the_unimplemented_rule_the_holdout_names_is_still_unimplemented():
    """``B-route`` is a named gap, not a typo. Keep it visible."""
    h03 = next(c for c in HOLDOUT if c.id == "h03-false")
    assert h03.label_rule == "B-route"
    emitted = set()
    for case in ALL_CASES:
        result = gates.adjudicate(case.observation)
        emitted |= set(result.rule.split("+")) | set(result.fired)
    assert "B-route" not in emitted, (
        "a B-route rule now exists. Update h03-false's label_basis and GAPS.md rather than "
        "leaving a published gap that has been closed."
    )


# ------------------------------------- the gate derives rather than reads


POISON = [
    # (case id, observation key, a value that would flip the verdict if read)
    ("void08-false", "reached_application_layer", True),
    ("void08-false", "control_recorded_in_run", True),
    ("self15-false", "independent_minimum", 1),
]


@pytest.mark.parametrize(("case_id", "key", "poison"), POISON)
def test_the_gate_derives_its_conclusion_rather_than_reading_it(case_id, key, poison):
    """Poison the summary field and demand the verdict stay put.

    An external reviewer found that for 6 of the 11 cases the C1 headline was
    computed over, the fixture stated the gate's conclusion as a literal field
    -- and that the only two committed cases where the gates beat a fair
    baseline were both from that set. Five of the six are re-expressed so the
    gate has to derive the conclusion from raw records. The legacy summary
    fields are retained because external artifacts read them, which means the
    only way to *show* that the gate no longer depends on them is to set each
    one to the value that would produce the wrong answer and check that nothing
    moves.
    """
    case = next(c for c in ALL_CASES if c.id == case_id)
    clean = gates.adjudicate(copy.deepcopy(case.observation))
    poisoned = copy.deepcopy(case.observation)
    assert key in poisoned, f"{case_id} no longer carries {key}; drop this row"
    poisoned[key] = poison
    tainted = gates.adjudicate(poisoned)
    # ``fired`` is compared as well as the verdict, and that is the load-bearing
    # half. void08-false trips three lattice preconditions, so a gate that had
    # gone back to reading ``reached_application_layer`` would still return
    # REFUSED/VOID on the strength of B-artifact and nothing would notice. The
    # set of rules that fired is what actually changes.
    assert (clean.decision, clean.verdict, clean.fired) == (
        tainted.decision,
        tainted.verdict,
        tainted.fired,
    ), (
        f"{case_id}: setting {key}={poison!r} moved the result from "
        f"{clean.decision}/{clean.verdict}/{clean.fired} to "
        f"{tainted.decision}/{tainted.verdict}/{tainted.fired}, so the gate is reading the "
        "summary field rather than deriving from the records."
    )
    assert clean.decision == case.correct_decision


def test_a_positive_control_with_no_recorded_observable_raises():
    """A missing measurement is not an empty one, and must not be defaulted.

    Critic case ``c05`` showed the softer half: an *empty* ``expected_observable``
    short-circuited the expressivity check. The harder half is a control that
    claims ``ran: true`` and records no observable at all. Reading that as the
    empty string would silently reproduce the same defect, so it raises.
    """
    base = {
        "kind": "oracle_expressivity",
        "claim": "clean-negative",
        "positive_control": {"ran": True, "expected_observable": "M", "observed": "M seen"},
        "treatment_observed": "",
    }
    assert gates.adjudicate(copy.deepcopy(base)).decision == "SUPPORTED"
    for key in ("expected_observable", "observed"):
        broken = copy.deepcopy(base)
        del broken["positive_control"][key]
        with pytest.raises(ValueError, match=f"has no {key!r}"):
            gates.adjudicate(broken)


def test_an_impossible_covering_array_strength_raises_rather_than_scoring():
    """A 3-way array over two factors is not a thing, and guessing is worse than raising."""
    with pytest.raises(ValueError, match="exceeds the 2 factors recorded"):
        gates.adjudicate(
            {
                "kind": "numeric_claim",
                "claim": "3-way-coverage-complete",
                "metric": "coverage",
                "rows": 10,
                "strength": 3,
                "factors": {"a": 2, "b": 2},
            }
        )


def test_void09_cannot_be_decided_by_comparing_its_two_target_labels():
    """The decisive case. Equality over the declared labels gives the wrong answer.

    ``void09-false`` is one of the two cases that carried the entire pre-repair
    margin over a fair baseline, and it carried it by ``str.__eq__`` on two
    labels the fixture's author chose. The two arms now target two *different*
    hosts, so equality says "independent" while the truth is "one containment":
    the gate has to read the recorded egress allowlist and find that it covers
    neither. Deleting that derivation flips the case to "no bug".
    """
    case = next(c for c in CASES if c.id == "void09-false")
    obs = case.observation
    assert obs["control_target"] != obs["treatment_target"]
    assert obs["egress_allowlist"]
    result = gates.adjudicate(obs)
    assert (result.decision, result.verdict, result.rule) == (
        "REFUSED",
        gates.CONFOUNDED,
        "B-independence",
    )
    # Widen the allowlist to cover the control and the case must stop being
    # confounded -- which is what proves the allowlist is what decided it.
    widened = copy.deepcopy(obs)
    widened["egress_allowlist"] = [*obs["egress_allowlist"], "control-probe.invalid"]
    assert gates.adjudicate(widened).rule != "B-independence"


def test_the_covering_array_bound_is_computed_from_the_factor_model():
    """8 x 8 x 6 = 384, computed rather than declared."""
    case = next(c for c in CASES if c.id == "self15-false")
    obs = case.observation
    assert gates._covering_array_lower_bound(obs) == 384
    assert obs["independent_minimum"] == 384, "the declared cross-check has drifted"
    trimmed = copy.deepcopy(obs)
    trimmed["strength"] = 2
    assert gates._covering_array_lower_bound(trimmed) == 64


def test_every_lattice_and_oracle_rule_is_exercised_by_the_corpus():
    """The reviewer's census found two of five lattice rules firing zero times.

    ``void08-false`` trips three preconditions at once and the gate used to
    return on the first, so ``B-stale-control`` and ``B-reachability`` were dead
    code while the results file reported catalogue coverage as complete. The
    lattice now evaluates every precondition and records every one that fired.
    """
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    census = payload["c2"]["gated_fired_rule_census"]
    for rule in ("B-artifact", "B-stale-control", "B-independence", "B-reachability"):
        assert census.get(rule, 0) > 0, f"{rule} fires on no committed case"


# ------------------------------------------------------ the three arms


def test_there_are_three_arms_and_the_fair_one_can_express_every_class():
    """The reviewer's central objection, turned into an assertion.

    The old comparison arm could emit only ``CANDIDATE`` and ``no-bug``, so its
    score on every case whose correct answer is a refusal was fixed before any
    fixture was read. A comparison arm that cannot express the right answer is
    not a comparison, so the primary arm must be able to emit all three classes.
    """
    assert gates.ARMS == ("gated", "fair", "naive")
    seen = {arm: set() for arm in gates.ARMS}
    for case in ALL_CASES:
        for arm in gates.ARMS:
            r = gates.adjudicate(case.observation, arm=arm)
            seen[arm].add(classify_result(r.decision, r.verdict))
    assert seen["fair"] == set(CLASSES), seen["fair"]
    assert "UNINTERPRETABLE" not in seen["naive"], (
        "the provenance arm has started emitting a refusal class. Its predicates are frozen on "
        "purpose; if they have changed it is no longer the check that produced the catalogue."
    )


def test_the_fair_arm_matches_the_reviewers_own_baseline_on_the_reviewers_cases():
    """One implementation, two homes, pinned to each other.

    ``gates._fair`` is the reviewer's ``competent()`` promoted into the scored
    module so the benchmark's primary arm is a real code path rather than a
    side script. The reviewer's own file stays in the tree and runs; this test
    stops the two from drifting. It is asserted over the reviewer's cases, which
    were not re-expressed -- on the committed corpus the two differ wherever a
    fixture was re-expressed to make the gate derive a conclusion, and the
    results file says where and why.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_critic", RESULTS.parent / "fp_corpus" / "critic" / "run_critic.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for case in CRITIC:
        mine = gates.adjudicate(case.observation, arm="fair")
        theirs = module.competent(copy.deepcopy(case.observation))
        assert (mine.decision, mine.verdict) == (theirs.decision, theirs.verdict), case.id


def test_the_provenance_arm_is_frozen():
    """Pin every naive verdict, so "frozen" is enforced rather than asserted.

    This arm's only value is that it is the historical record. An edit that
    improved it would silently relabel the corpus's own history, and the 7-of-7
    provenance number would stop meaning what it says.
    """
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    for case in CASES:
        recorded = payload["c2"]["per_case"][case.id]["naive"]
        fresh = gates.adjudicate(case.observation, arm="naive")
        assert (fresh.decision, fresh.verdict) == (
            recorded["decision"],
            recorded["verdict"],
        ), case.id


def test_an_unknown_arm_is_refused():
    with pytest.raises(ValueError, match="unknown arm"):
        gates.adjudicate({"kind": "numeric_claim", "metric": "r2", "value": 1.0}, arm="best")


# --------------------------------------------- the corrected denominator


def test_the_headline_denominator_is_only_actual_negatives_that_the_gate_must_derive():
    """Work the reviewer did by hand, pinned by name.

    The published count used all eleven ``UNINTERPRETABLE`` cases. Four of them
    make non-negative claims -- a finding, an over-broad finding and two claims
    about a metric -- and one of the remaining seven hands the gate the set of
    code paths the target reaches. Six remain.
    """
    headline = {c.id for c in CASES if c.is_untrustworthy_negative}
    assert headline == {
        "void08-false",
        "void09-false",
        "fn10-false",
        "fn11-false",
        "fn12-false",
        "hard18-false",
    }
    uninterpretable = {c.id for c in CASES if c.truth_class == "UNINTERPRETABLE"}
    assert len(uninterpretable) == 11
    not_negative = {
        c.id for c in CASES if c.truth_class == "UNINTERPRETABLE" and not c.asserts_absence
    }
    assert not_negative == {"ext17-false", "scope13-false", "self14-false", "self15-false"}
    excluded = {c.id for c in CASES if c.asserts_absence and c.conclusion_in_fixture}
    assert excluded == {"hard19-false", "hard19-genuine"}


def test_a_case_that_asserts_an_absence_says_so_and_is_consistent_with_its_claim():
    """``asserts_absence`` is a declared label, but it may not contradict the fixture.

    Declaring it is the point -- the old count inferred membership from a claim
    string and got the denominator wrong -- and a declaration that disagrees
    with the fixture it describes would be worse than an inference.
    """
    for case in ALL_CASES:
        if case.claim == "clean-negative":
            assert case.asserts_absence, f"{case.id} claims a clean negative but is not marked"
        else:
            assert not case.asserts_absence, (
                f"{case.id} is marked as asserting an absence but its claim is {case.claim!r}"
            )


def test_an_excluded_case_is_still_scored_and_still_published():
    """Excluding ``hard19`` from the headline must not hide it."""
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    audit = payload["c1"]["denominator_audit"]
    assert "hard19-false" in audit["excluded_conclusion_in_fixture"]
    assert "hard19-false" in payload["c2"]["per_case"]
    assert payload["c2"]["per_case"]["hard19-false"]["gated"]["agrees"] is True
    assert payload["c1"]["excluded_conclusion_in_fixture"]["gated"]["cases"] == 1


def test_the_loader_requires_the_class_membership_fields(tmp_path):
    record = {
        "id": "x",
        "shape": "x",
        "shape_title": "x",
        "catalogue_ref": "x",
        "member": "false",
        "correct_decision": "REFUSED",
        "correct_verdict": "KILL",
        "naive_oracle_strength": 0,
        "gated_oracle_strength": 3,
        "note": "x",
        "label_rule": "A2",
        "asserts_absence": False,
        "conclusion_in_fixture": False,
        "observation": {"kind": "numeric_claim"},
    }
    assert set(REQUIRED_FIELDS) <= set(record)
    for omitted in ("asserts_absence", "conclusion_in_fixture", "label_rule"):
        trimmed = {k: v for k, v in record.items() if k != omitted}
        (tmp_path / "bad.json").write_text(json.dumps({"cases": [trimmed]}), encoding="utf-8")
        with pytest.raises(ValueError, match="is missing"):
            load_cases(tmp_path)


# ------------------------------------------------- the significance arithmetic


@pytest.mark.parametrize(
    ("table", "expected", "why"),
    [
        ((2, 5, 0, 7), 0.4615, "the pre-repair C1 margin, 2 of 7 against 0 of 7"),
        ((1, 5, 0, 6), 1.0, "the post-repair C1 margin, 1 of 6 against 0 of 6"),
        ((12, 12, 1, 23), 0.0007, "the oracle experiment at the row level"),
        ((7, 5, 1, 11), 0.0272, "the oracle experiment with the probe as the unit"),
        ((0, 6, 0, 6), 1.0, "two arms that agree on everything"),
        ((6, 0, 0, 6), 0.0022, "two arms that disagree on everything"),
    ],
)
def test_fisher_two_sided_against_known_values(table, expected, why):
    """The number that says the headline is not significant has to be checkable.

    These are the figures quoted in `README.md`, `GAPS.md` and the critique, so
    the helper that produces them is pinned against them rather than trusted.
    """
    assert fisher_two_sided(*table) == pytest.approx(expected, abs=5e-4), why


def test_fisher_is_symmetric_and_bounded():
    assert fisher_two_sided(1, 5, 0, 6) == pytest.approx(fisher_two_sided(0, 6, 1, 5))
    for table in ((1, 5, 0, 6), (3, 3, 1, 5), (0, 1, 1, 0)):
        assert 0.0 <= fisher_two_sided(*table) <= 1.0


def test_fisher_returns_one_for_a_degenerate_table():
    """An empty margin is not evidence, and must not render as p = 0."""
    assert fisher_two_sided(0, 0, 0, 0) == 1.0
    assert fisher_two_sided(0, 0, 3, 3) == 1.0


def test_the_published_c1_significance_is_the_one_the_results_file_reports():
    """And it is not significant. That is the point of publishing it."""
    payload = json.loads((RESULTS / "fp_corpus.json").read_text(encoding="utf-8"))
    fisher = payload["c1"]["fisher"]
    un = payload["c1"]["untrustworthy_negatives"]
    n = un["gated"]["cases"]
    recomputed = fisher_two_sided(
        un["fair"]["called_no_bug"],
        n - un["fair"]["called_no_bug"],
        un["gated"]["called_no_bug"],
        n - un["gated"]["called_no_bug"],
    )
    assert fisher["gated_vs_fair"] == pytest.approx(recomputed)
    assert fisher["gated_vs_fair"] > 0.05, (
        "the gated-versus-fair comparison has become significant at this n. That would be a "
        "real result and the README must be rewritten to say so, with the interval; it must "
        "not happen by a fixture gaining a field the gate can read."
    )
