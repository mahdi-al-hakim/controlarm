"""Tests for the ledger and its audit.

The ledger's one refusal is the headline: a row that asserts an absence and
carries no results artifact is rejected at write time, because an unauditable
negative is the thing the whole harness exists to prevent.

The audit's job is the opposite -- it refuses nothing and reports everything,
including rows the current rules would not have accepted. So the tests here
check two different contracts, and the sharpest ones are the arithmetic: an
empty ledger must not report perfect proportions, and a missing input must never
be scored as a passing one.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json

import pytest

from controlarm.ledger import (
    ASSERTS_ABSENCE,
    BANDS,
    MIN_ADMISSIBLE_STRENGTH,
    AuditReport,
    Band,
    Claim,
    ControlReading,
    Ledger,
    LedgerError,
    LedgerRow,
    LedgerVerdict,
    audit,
    negatives_only,
)

NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)

PASSING_CONTROL = ControlReading(
    name="honest-control",
    passed=True,
    independent=True,
    detail="plain action refused by the boundary itself",
)


def row(**overrides) -> LedgerRow:
    base = {
        "id": "r1",
        "recorded": NOW,
        "subject": "component X, encoded-input arm",
        "verdict": LedgerVerdict.KILL,
        "oracle": "parsed_field_diff",
        "control": PASSING_CONTROL,
        "results_artifact": "runs/r1/run.json",
        "assumption": "the boundary normalises before the allowlist check, as of the pinned ref",
        "next_axis": "double-encoded form",
    }
    base.update(overrides)
    return LedgerRow(**base)


def ledger(tmp_path, *rows) -> Ledger:
    store = Ledger(tmp_path / "ledger.jsonl")
    for r in rows:
        store.append(r)
    return store


def artifact(tmp_path, relative="runs/r1/run.json") -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")


# ------------------------------------------------------------- the vocabulary


def test_void_and_confounded_are_first_class_terminal_states():
    assert LedgerVerdict.VOID in LedgerVerdict
    assert LedgerVerdict.CONFOUNDED in LedgerVerdict
    assert BANDS[LedgerVerdict.VOID] is Band.NEGATIVE_UNTRUSTED
    assert BANDS[LedgerVerdict.CONFOUNDED] is Band.NEGATIVE_UNTRUSTED


def test_every_verdict_has_a_band():
    """A verdict with no band is a verdict nothing can interpret."""
    assert set(BANDS) == set(LedgerVerdict)


def test_the_ledger_vocabulary_covers_every_run_verdict():
    """The ledger has to be able to record whatever a run produced.

    ``controls.Verdict`` gained a sixth member (``CONFOUNDED``, split out of
    ``INCONCLUSIVE`` because the two call for different next actions). A ledger
    that could not name it would have to fold it back into something else at the
    one point where the distinction is supposed to survive.
    """
    from controlarm.controls.run import Verdict

    missing = [v.value for v in Verdict if v.value not in {lv.value for lv in LedgerVerdict}]
    assert not missing, f"the ledger cannot record these run verdicts: {missing}"


def test_only_a_trusted_negative_asserts_an_absence():
    """VOID is not a negative. Neither is BLOCKED.

    "The rig was not trustworthy", "we were not allowed to test it" and "we
    tested it and found nothing" are three claims, and only the third one is a
    result about the target.
    """
    assert frozenset({LedgerVerdict.KILL}) == ASSERTS_ABSENCE
    for verdict in [
        LedgerVerdict.VOID,
        LedgerVerdict.CONFOUNDED,
        LedgerVerdict.BLOCKED,
        LedgerVerdict.NO_TESTS,
    ]:
        assert verdict not in ASSERTS_ABSENCE


def test_bands_keep_trusted_and_untrusted_negatives_apart():
    assert BANDS[LedgerVerdict.KILL] is Band.NEGATIVE_TRUSTED
    assert BANDS[LedgerVerdict.BLOCKED] is Band.NOT_A_RESULT
    assert BANDS[LedgerVerdict.CANDIDATE] is Band.POSITIVE


# ------------------------------------------------------- the write-time refusal


def test_a_negative_row_with_no_results_artifact_is_rejected(tmp_path):
    """The one refusal this module exists for.

    A negative with no artifact cannot be re-read, so it is not a result -- it
    is a memory. One of the three independent grounds for voiding a recorded
    negative in the source corpus was exactly this: every other probe wrote a
    results file and that one did not.
    """
    store = Ledger(tmp_path / "ledger.jsonl")
    with pytest.raises(LedgerError) as exc:
        store.append(row(results_artifact=None))
    assert "results artifact" in str(exc.value)
    assert not (tmp_path / "ledger.jsonl").exists()


@pytest.mark.parametrize("empty", ["", "   ", "\t"])
def test_an_empty_artifact_path_is_not_an_artifact(tmp_path, empty):
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "ledger.jsonl").append(row(results_artifact=empty))


def test_a_negative_row_with_no_assumption_is_rejected(tmp_path):
    """A negative is a claim about the rig, and the claim has to be stated.

    Without the assumption written down, the row cannot be reopened on a named
    new perspective -- which is the only thing that licenses a re-attack -- and
    it cannot be refuted either.
    """
    with pytest.raises(LedgerError) as exc:
        Ledger(tmp_path / "ledger.jsonl").append(row(assumption=None))
    assert "assumption" in str(exc.value)


def test_a_void_row_needs_no_artifact_because_it_claims_nothing(tmp_path):
    """VOID is published, not discarded -- and it asserts no absence, so the
    artifact requirement does not apply to it."""
    store = ledger(
        tmp_path, row(verdict=LedgerVerdict.VOID, results_artifact=None, assumption=None)
    )
    assert len(store.rows()) == 1


def test_a_row_with_no_named_oracle_is_rejected(tmp_path):
    for bad in [None, "", "  "]:
        with pytest.raises(LedgerError) as exc:
            Ledger(tmp_path / "ledger.jsonl").append(row(oracle=bad))
        assert "oracle" in str(exc.value)


def test_a_row_with_no_subject_is_rejected(tmp_path):
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "ledger.jsonl").append(row(subject=""))


def test_a_row_with_a_naive_timestamp_is_rejected(tmp_path):
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "ledger.jsonl").append(row(recorded=dt.datetime(2026, 10, 25)))


def test_a_duplicate_row_id_is_rejected(tmp_path):
    store = ledger(tmp_path, row())
    with pytest.raises(LedgerError) as exc:
        store.append(row(subject="something else"))
    assert "r1" in str(exc.value)


def test_a_supersedes_pointer_to_an_unknown_row_is_rejected(tmp_path):
    store = Ledger(tmp_path / "ledger.jsonl")
    with pytest.raises(LedgerError) as exc:
        store.append(row(id="r2", supersedes="r1"))
    assert "r1" in str(exc.value)


def test_a_row_cannot_supersede_itself(tmp_path):
    """And it is refused *for that reason*, not as a dangling pointer.

    The two guards catch different mistakes -- a self-reference and a reference
    to a row that was never written -- and a reader needs to be told which.
    """
    with pytest.raises(LedgerError) as exc:
        Ledger(tmp_path / "ledger.jsonl").append(row(supersedes="r1"))
    assert "cannot supersede itself" in str(exc.value)


def test_a_control_reading_is_required(tmp_path):
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "ledger.jsonl").append(row(control=None))


def test_a_control_reading_may_record_that_no_control_ran(tmp_path):
    """Recording "there was no control" is allowed and is what the audit counts.

    Refusing it at write time would push the honest rows out of the ledger and
    leave only the flattering ones, which is how an audit becomes decorative.
    """
    store = ledger(
        tmp_path,
        row(control=ControlReading(name="none", passed=None, independent=None, detail="not run")),
    )
    assert store.rows()[0].control.passed is None


# ------------------------------------------------------------- append-only


def test_rows_round_trip_through_jsonl(tmp_path):
    original = row(
        claims=(Claim("the boundary normalises first", "https://example.invalid/docs#norm"),),
        dedup_score="P_found=0.50 (E4 R2 A2 C3 P3 D2 V3)",
    )
    store = ledger(tmp_path, original)
    assert store.rows() == (original,)


def test_the_file_is_one_json_object_per_line(tmp_path):
    ledger(tmp_path, row(), row(id="r2", subject="another arm"))
    lines = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        assert isinstance(json.loads(line), dict)


def test_appending_never_rewrites_an_earlier_line(tmp_path):
    store = ledger(tmp_path, row())
    first = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    store.append(row(id="r2", subject="another arm"))
    after = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    assert after.startswith(first)


def test_there_is_no_api_for_editing_or_deleting_a_row():
    """Amendment is an append that supersedes. There is no other path."""
    for forbidden in ["update", "delete", "edit", "remove", "replace", "set"]:
        assert not hasattr(Ledger, forbidden), f"Ledger exposes {forbidden}"


def test_a_superseding_row_records_what_it_replaces(tmp_path):
    store = ledger(tmp_path, row())
    store.supersede(
        "r1",
        row(
            id="r2",
            results_artifact="runs/r2/run.json",
            assumption="re-run with a passing in-run control",
        ),
    )
    rows = store.rows()
    assert rows[1].supersedes == "r1"
    assert store.current_rows() == (rows[1],)
    assert store.superseded_ids() == frozenset({"r1"})


def test_superseding_an_unknown_row_is_rejected(tmp_path):
    store = Ledger(tmp_path / "ledger.jsonl")
    with pytest.raises(LedgerError):
        store.supersede("nope", row(id="r2"))


def test_a_corrupt_line_fails_loudly_rather_than_reading_as_an_empty_ledger(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text('{"id": "r1"\nnot json\n', encoding="utf-8")
    with pytest.raises(LedgerError) as exc:
        Ledger(path).rows()
    assert "line 1" in str(exc.value)


def test_an_unknown_verdict_on_disk_fails_loudly(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text(json.dumps({**row().as_dict(), "verdict": "PROBABLY-FINE"}), encoding="utf-8")
    with pytest.raises(LedgerError) as exc:
        Ledger(path).rows()
    assert "PROBABLY-FINE" in str(exc.value)


def test_an_absent_ledger_reads_as_no_rows(tmp_path):
    assert Ledger(tmp_path / "never-written.jsonl").rows() == ()


def test_a_row_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        row().verdict = LedgerVerdict.CANDIDATE  # type: ignore[misc]


# ------------------------------------------------------------------ the audit


def test_the_audit_reports_a_present_artifact(tmp_path):
    artifact(tmp_path)
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    assert report.findings[0].artifact_exists
    assert report.artifact_rate == 1.0


def test_the_audit_reports_an_artifact_that_was_promised_and_is_absent(tmp_path):
    """The row was accepted because it named an artifact. The audit checks the
    artifact is actually there, which is a different question."""
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    assert not report.findings[0].artifact_exists
    assert report.artifact_rate == 0.0
    assert any("artifact" in n for n in report.findings[0].notes)


def test_the_audit_reports_a_passing_independent_control(tmp_path):
    artifact(tmp_path)
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    assert report.findings[0].control_passed
    assert report.control_rate == 1.0


def test_a_control_that_passed_but_was_not_independent_does_not_count(tmp_path):
    """Defect: the control pointed at a host that was itself outside the
    allowlist, so control and treatment tested the same containment."""
    store = ledger(
        tmp_path,
        row(
            control=ControlReading(
                name="positive-control",
                passed=True,
                independent=False,
                detail="control shared the containment under test",
            )
        ),
    )
    report = audit(store.rows(), root=tmp_path)
    assert not report.findings[0].control_passed
    assert any("independent" in n for n in report.findings[0].notes)


def test_a_control_that_was_not_recorded_does_not_count_as_passing(tmp_path):
    store = ledger(
        tmp_path,
        row(control=ControlReading(name="none", passed=None, independent=None, detail="not run")),
    )
    report = audit(store.rows(), root=tmp_path)
    assert not report.findings[0].control_passed
    assert report.control_rate == 0.0


@pytest.mark.parametrize(
    "oracle,admissible",
    [
        ("source_diff", True),
        ("parsed_field_diff", True),
        ("assertion_only", True),
        ("revert_or_crash", False),
        ("model_text", False),
        ("string_co_occurrence", False),
        ("a feeling", False),
    ],
)
def test_the_audit_reports_oracle_admissibility(tmp_path, oracle, admissible):
    store = ledger(tmp_path, row(oracle=oracle))
    report = audit(store.rows(), root=tmp_path)
    assert report.findings[0].oracle_admissible is admissible


def test_an_unknown_oracle_is_inadmissible_rather_than_unscored(tmp_path):
    """Fail closed: an oracle nobody scored is not an oracle that passed."""
    report = audit(ledger(tmp_path, row(oracle="bespoke heuristic")).rows(), root=tmp_path)
    assert not report.findings[0].oracle_admissible
    assert report.admissible_oracle_rate == 0.0
    assert MIN_ADMISSIBLE_STRENGTH == 2


def test_the_audit_reports_uncited_claims(tmp_path):
    store = ledger(
        tmp_path,
        row(
            claims=(
                Claim("the boundary normalises first", "https://example.invalid/docs#norm"),
                Claim("every server-side fetcher is https-only", None),
            )
        ),
    )
    report = audit(store.rows(), root=tmp_path)
    assert report.findings[0].uncited_claims == ("every server-side fetcher is https-only",)
    assert report.uncited_claim_count == 1


@pytest.mark.parametrize("citation", ["", "   "])
def test_a_blank_citation_is_an_uncited_claim(tmp_path, citation):
    store = ledger(tmp_path, row(claims=(Claim("an inherited claim", citation),)))
    report = audit(store.rows(), root=tmp_path)
    assert report.uncited_claim_count == 1


def test_an_empty_ledger_does_not_report_perfect_proportions():
    """The sharpest arithmetic guard in the module.

    Zero of zero is not one. A fresh ledger reporting 100% artifact coverage
    would be the harness committing the exact error it audits for, and
    ``0/0 == 1.0`` is the shape that error takes in code.
    """
    report = audit((), root=None)
    assert report.n_rows == 0
    assert report.artifact_rate is None
    assert report.control_rate is None
    assert report.admissible_oracle_rate is None


def test_the_three_proportions_are_computed_over_the_rows_given(tmp_path):
    artifact(tmp_path, "runs/r1/run.json")
    store = ledger(
        tmp_path,
        row(),  # artifact present, control passes, oracle admissible
        row(
            id="r2",
            subject="second arm",
            results_artifact="runs/r2/run.json",  # absent on disk
            oracle="model_text",
            control=ControlReading(name="none", passed=None, independent=None, detail="not run"),
        ),
    )
    report = audit(store.rows(), root=tmp_path)
    assert report.n_rows == 2
    assert report.artifact_rate == 0.5
    assert report.control_rate == 0.5
    assert report.admissible_oracle_rate == 0.5


def test_the_audit_can_be_restricted_to_the_negatives(tmp_path):
    store = ledger(
        tmp_path,
        row(),
        row(
            id="r2",
            subject="a candidate",
            verdict=LedgerVerdict.CANDIDATE,
            results_artifact=None,
            assumption=None,
        ),
    )
    assert len(negatives_only(store.rows())) == 1
    report = audit(negatives_only(store.rows()), root=tmp_path)
    assert report.n_rows == 1
    assert report.findings[0].row_id == "r1"


def test_the_audit_refuses_nothing(tmp_path):
    """It reports, it does not refuse. A row the current rules would reject
    still has to be auditable, or the audit only ever sees clean rows."""
    path = tmp_path / "ledger.jsonl"
    hand_written = {
        **row().as_dict(),
        "results_artifact": None,
        "assumption": None,
        "oracle": "model_text",
    }
    path.write_text(json.dumps(hand_written) + "\n", encoding="utf-8")
    report = audit(Ledger(path).rows(), root=tmp_path)
    assert report.n_rows == 1
    assert not report.findings[0].artifact_exists
    assert not report.findings[0].oracle_admissible
    assert any("assumption" in n for n in report.findings[0].notes)


def test_the_audit_notes_a_superseded_row(tmp_path):
    store = ledger(tmp_path, row())
    store.supersede("r1", row(id="r2", results_artifact="runs/r2/run.json"))
    report = audit(store.rows(), root=tmp_path)
    assert any("superseded" in n for n in report.findings[0].notes)
    assert report.findings[1].supersedes == "r1"


def test_the_audit_report_is_immutable(tmp_path):
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    assert isinstance(report, AuditReport)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.n_rows = 0  # type: ignore[misc]


def test_the_audit_renders_the_three_proportions_as_markdown(tmp_path):
    artifact(tmp_path)
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    text = report.as_markdown()
    assert "results artifact" in text
    assert "independent positive control" in text
    assert "admissible oracle" in text
    assert "r1" in text


def test_the_markdown_says_so_when_there_is_nothing_to_report():
    text = audit((), root=None).as_markdown()
    assert "no rows" in text.lower()
    assert "100" not in text


def test_the_audit_serialises(tmp_path):
    report = audit(ledger(tmp_path, row()).rows(), root=tmp_path)
    text = json.dumps(report.as_dict())
    assert "artifact_rate" in text and "r1" in text


def test_nothing_in_the_library_prints(tmp_path, capsys):
    store = ledger(tmp_path, row())
    audit(store.rows(), root=tmp_path).as_markdown()
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
