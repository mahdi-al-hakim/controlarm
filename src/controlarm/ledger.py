"""The ledger, and the audit that makes its negatives checkable.

A negative result is a claim about the rig as much as about the target, so a row
recording one has to carry enough to reconstruct the claim: the named oracle,
the control reading, the artifact the verdict was read out of, and the
assumption the absence rests on. The ledger refuses exactly one thing -- a row
asserting an absence with no results artifact -- because such a row cannot be
re-read and is therefore a memory rather than a result.

``audit`` is the other half and refuses nothing at all. It re-reads the ledger
and reports, per row: does the results artifact exist; is a passing
*independent* positive control recorded; is the named oracle admissible; is any
claim uncited. Then it returns the three proportions. That asymmetry is
deliberate: a store that rejected every imperfect row would leave an audit that
only ever sees flattering ones.

Numbered items are the wrong verdicts the design prevents. All five are
recorded failures of the method this implements:

  1  a negative with no results artifact        -> one recorded negative was
     voided on three independent grounds, and this was one of them: every other
     probe wrote a results file and that one did not, so nothing could be
     re-read. Refused at write time.
  2  VOID folded into the negative band         -> "the rig was not trustworthy"
     is not "we found nothing". ``VOID`` and ``CONFOUNDED`` are first-class
     terminal states in their own band, and neither asserts an absence.
  3  a control that passed but was not          -> the control pointed at a host
     independent of the treatment                  itself outside the allowlist,
     so control and treatment tested the same containment. The audit counts a
     control only when it is recorded as both passing and independent.
  4  an uncited inherited claim                 -> two rows were downgraded on
     an uncited assertion that turned out false. A claim with no citation is a
     lead, not a fact, and the audit counts them.
  5  an empty ledger reporting perfection       -> ``0/0`` is not ``1.0``. With
     no rows the three proportions are ``None``, never a rate.
"""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from controlarm.gates.fp import ORACLE_STRENGTH, STRENGTH_FLOOR

__all__ = [
    "ASSERTS_ABSENCE",
    "BANDS",
    "MIN_ADMISSIBLE_STRENGTH",
    "AuditReport",
    "Band",
    "Claim",
    "ControlReading",
    "Ledger",
    "LedgerError",
    "LedgerRow",
    "LedgerVerdict",
    "RowFinding",
    "audit",
    "negatives_only",
]

#: Reuses the strength table the false-positive gate enforces, so "admissible"
#: means the same thing in both places. Two copies of this table would drift,
#: and the drift would be silent.
MIN_ADMISSIBLE_STRENGTH = STRENGTH_FLOOR


class LedgerError(Exception):
    """Raised when a row cannot be recorded, or when the store cannot be read."""


class LedgerVerdict(str, Enum):
    """The verdict vocabulary, banded rather than flat."""

    VOID = "VOID"
    """The rig was not trustworthy. No absence in that run is interpretable."""

    CONFOUNDED = "CONFOUNDED"
    """Control and treatment were not independent, so neither arm is evidence."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """Something failed for a named unrelated reason. Remove it and re-run."""

    BLOCKED = "BLOCKED"
    """Not permitted, not provisioned, not reached. Not a result."""

    NO_TESTS = "NO-TESTS"
    """Controls ran and no test arm was defined."""

    KILL = "KILL"
    """A trusted negative: the arms ran, the control fired, nothing happened."""

    CANDIDATE = "CANDIDATE"
    """Something executed. Not a finding until re-run from fresh state."""

    CONFIRMED = "CONFIRMED"
    """Re-run, controlled, and gated."""

    REFUTED = "REFUTED"
    """A previous positive, withdrawn on evidence."""

    DUPLICATE = "DUPLICATE"
    """Real, and already known. A ruling, not a measurement."""


class Band(str, Enum):
    """Which kind of claim a verdict makes. Item 2 lives here."""

    NEGATIVE_TRUSTED = "negative-trusted"
    NEGATIVE_UNTRUSTED = "negative-untrusted"
    NOT_A_RESULT = "not-a-result"
    POSITIVE = "positive"
    REVERSAL = "reversal"


BANDS: Mapping[LedgerVerdict, Band] = {
    LedgerVerdict.KILL: Band.NEGATIVE_TRUSTED,
    LedgerVerdict.VOID: Band.NEGATIVE_UNTRUSTED,
    LedgerVerdict.CONFOUNDED: Band.NEGATIVE_UNTRUSTED,
    LedgerVerdict.INCONCLUSIVE: Band.NEGATIVE_UNTRUSTED,
    LedgerVerdict.BLOCKED: Band.NOT_A_RESULT,
    LedgerVerdict.NO_TESTS: Band.NOT_A_RESULT,
    LedgerVerdict.CANDIDATE: Band.POSITIVE,
    LedgerVerdict.CONFIRMED: Band.POSITIVE,
    LedgerVerdict.REFUTED: Band.REVERSAL,
    LedgerVerdict.DUPLICATE: Band.REVERSAL,
}

#: The verdicts that assert the target does not do the thing. Only these carry
#: the artifact and assumption requirements, because only these make a claim
#: that a reader might later need to check.
ASSERTS_ABSENCE = frozenset({LedgerVerdict.KILL})


@dataclass(frozen=True)
class Claim:
    """A sentence in a report, and the citation that makes it a fact.

    ``citation`` may be a URL or a quoted sentence. ``None`` or blank means the
    claim is inherited, which the audit counts: an inherited claim with no
    citation is a lead, not a fact.
    """

    text: str
    citation: str | None = None

    @property
    def cited(self) -> bool:
        return bool((self.citation or "").strip())


@dataclass(frozen=True)
class ControlReading:
    """What the run's control actually did.

    ``passed=None`` means no control was recorded, which is allowed at write
    time and counted by the audit. ``independent`` is the second half and the
    one that gets forgotten: a control that passed while testing the same
    containment as the treatment has not separated the hypotheses.
    """

    name: str
    passed: bool | None
    independent: bool | None
    detail: str = ""

    @property
    def is_a_passing_independent_control(self) -> bool:
        return self.passed is True and self.independent is True

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "independent": self.independent,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class LedgerRow:
    """One row: one variant tried, one verdict, and why it is believable."""

    id: str
    recorded: dt.datetime
    subject: str
    verdict: LedgerVerdict
    oracle: str
    control: ControlReading
    results_artifact: str | None = None
    assumption: str | None = None
    supersedes: str | None = None
    next_axis: str | None = None
    #: The seven digits that reconstruct a dedup estimate, recorded verbatim.
    dedup_score: str | None = None
    claims: tuple[Claim, ...] = ()

    @property
    def asserts_absence(self) -> bool:
        return self.verdict in ASSERTS_ABSENCE

    @property
    def band(self) -> Band:
        return BANDS[self.verdict]

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "recorded": self.recorded.isoformat(),
            "subject": self.subject,
            "verdict": self.verdict.value,
            "band": self.band.value,
            "oracle": self.oracle,
            "control": self.control.as_dict(),
            "results_artifact": self.results_artifact,
            "assumption": self.assumption,
            "supersedes": self.supersedes,
            "next_axis": self.next_axis,
            "dedup_score": self.dedup_score,
            "claims": [{"text": c.text, "citation": c.citation} for c in self.claims],
        }

    @classmethod
    def from_dict(cls, data: Mapping, where: str) -> LedgerRow:
        try:
            verdict = LedgerVerdict(data["verdict"])
        except ValueError as exc:
            raise LedgerError(
                f"{where}: unknown verdict {data.get('verdict')!r}. The vocabulary is "
                f"{[v.value for v in LedgerVerdict]}; an unrecognised verdict cannot be banded, "
                "and an unbanded verdict cannot be interpreted."
            ) from exc
        except KeyError as exc:
            raise LedgerError(f"{where}: row has no verdict") from exc
        control = data.get("control") or {}
        try:
            return cls(
                id=data["id"],
                recorded=dt.datetime.fromisoformat(data["recorded"]),
                subject=data["subject"],
                verdict=verdict,
                oracle=data["oracle"],
                control=ControlReading(
                    name=control.get("name", ""),
                    passed=control.get("passed"),
                    independent=control.get("independent"),
                    detail=control.get("detail", ""),
                ),
                results_artifact=data.get("results_artifact"),
                assumption=data.get("assumption"),
                supersedes=data.get("supersedes"),
                next_axis=data.get("next_axis"),
                dedup_score=data.get("dedup_score"),
                claims=tuple(
                    Claim(c.get("text", ""), c.get("citation")) for c in data.get("claims", ())
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise LedgerError(f"{where}: row is missing or malformed ({exc})") from exc


# ------------------------------------------------------------------- the store


class Ledger:
    """An append-only JSONL row store.

    There is no update, delete or edit method, and that is the API: an amendment
    is a new row carrying a ``supersedes`` pointer, so the superseded belief
    stays readable. ``current_rows`` hides what has been superseded without
    losing it.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    # ------------------------------------------------------------------ reading

    def rows(self) -> tuple[LedgerRow, ...]:
        """Every row, in the order written.

        A malformed line raises. A corrupt ledger is not an empty ledger, and
        reading one as empty would make every proportion the audit computes a
        statement about a file it could not parse.
        """
        if not self.path.exists():
            return ()
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LedgerError(f"{self.path}: unreadable ({exc})") from exc
        out: list[LedgerRow] = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            where = f"{self.path}: line {number}"
            try:
                data = json.loads(line)
            except ValueError as exc:
                raise LedgerError(f"{where}: not valid JSON ({exc})") from exc
            if not isinstance(data, dict):
                raise LedgerError(f"{where}: expected a JSON object")
            out.append(LedgerRow.from_dict(data, where))
        return tuple(out)

    def superseded_ids(self) -> frozenset[str]:
        return frozenset(r.supersedes for r in self.rows() if r.supersedes)

    def current_rows(self) -> tuple[LedgerRow, ...]:
        superseded = self.superseded_ids()
        return tuple(r for r in self.rows() if r.id not in superseded)

    # ------------------------------------------------------------------ writing

    def append(self, row: LedgerRow) -> LedgerRow:
        """Validate and append one row. Raises rather than writing a bad row."""
        existing = self.rows()
        self._validate(row, existing)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row.as_dict(), sort_keys=True) + "\n")
        return row

    def supersede(self, old_id: str, row: LedgerRow) -> LedgerRow:
        """Append ``row`` as the replacement for ``old_id``."""
        if row.supersedes not in (None, old_id):
            raise LedgerError(
                f"row {row.id!r} already supersedes {row.supersedes!r}, not {old_id!r}"
            )
        import dataclasses as _dc

        return self.append(_dc.replace(row, supersedes=old_id))

    # ------------------------------------------------------------------ the gate

    @staticmethod
    def _validate(row: LedgerRow, existing: Sequence[LedgerRow]) -> None:
        if not isinstance(row, LedgerRow):
            raise LedgerError(f"expected a LedgerRow, got {type(row).__name__}")
        for name in ("id", "subject", "oracle"):
            if not str(getattr(row, name) or "").strip():
                raise LedgerError(
                    f"row {name} is empty. Every row carries a named oracle and a named "
                    "subject; a row without them cannot be re-litigated or re-run."
                )
        if row.oracle and row.oracle.strip() != row.oracle:
            raise LedgerError("oracle must not carry leading or trailing whitespace")
        if not isinstance(row.control, ControlReading):
            raise LedgerError(
                "control must be a ControlReading. Recording that no control ran is allowed "
                "and is what the audit counts; omitting the field is not."
            )
        if row.recorded.tzinfo is None or row.recorded.tzinfo.utcoffset(row.recorded) is None:
            raise LedgerError(
                "recorded must be timezone-aware. A naive timestamp cannot be ordered against "
                "a run artifact without assuming a timezone."
            )
        ids = {r.id for r in existing}
        if row.id in ids:
            raise LedgerError(
                f"row id {row.id!r} is already in the ledger. An amendment is a new row with a "
                "supersedes pointer, not a reused id."
            )
        if row.supersedes is not None:
            if row.supersedes == row.id:
                raise LedgerError(f"row {row.id!r} cannot supersede itself")
            if row.supersedes not in ids:
                raise LedgerError(
                    f"row {row.id!r} supersedes {row.supersedes!r}, which is not in the ledger. "
                    "A dangling supersedes pointer makes the superseded belief unreadable."
                )
        if row.asserts_absence:
            if not str(row.results_artifact or "").strip():
                raise LedgerError(
                    f"row {row.id!r} records {row.verdict.value}, which asserts an absence, and "
                    "names no results artifact. A negative with nothing to re-read is not a "
                    "result; it is a memory. Write the run artifact and name it here."
                )
            if not str(row.assumption or "").strip():
                raise LedgerError(
                    f"row {row.id!r} records {row.verdict.value} and states no assumption. A "
                    "negative is a claim about the rig as much as the target: state the "
                    "assumption it rests on so it can be reopened on a named new perspective, "
                    "or refuted."
                )


# ------------------------------------------------------------------- the audit


@dataclass(frozen=True)
class RowFinding:
    row_id: str
    verdict: LedgerVerdict
    band: Band
    artifact_exists: bool
    control_passed: bool
    oracle_admissible: bool
    uncited_claims: tuple[str, ...] = ()
    supersedes: str | None = None
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "row_id": self.row_id,
            "verdict": self.verdict.value,
            "band": self.band.value,
            "artifact_exists": self.artifact_exists,
            "control_passed": self.control_passed,
            "oracle_admissible": self.oracle_admissible,
            "uncited_claims": list(self.uncited_claims),
            "supersedes": self.supersedes,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class AuditReport:
    """The three proportions, and the per-row findings they are computed from.

    Each rate is ``None`` when there are no rows. Item 5: zero of zero is not
    one, and a fresh ledger reporting full coverage would be this harness making
    exactly the claim it audits against.
    """

    findings: tuple[RowFinding, ...] = ()
    n_rows: int = 0
    artifact_rate: float | None = None
    control_rate: float | None = None
    admissible_oracle_rate: float | None = None
    uncited_claim_count: int = 0
    generated: dt.datetime | None = field(default=None)

    def as_dict(self) -> dict:
        return {
            "n_rows": self.n_rows,
            "artifact_rate": self.artifact_rate,
            "control_rate": self.control_rate,
            "admissible_oracle_rate": self.admissible_oracle_rate,
            "uncited_claim_count": self.uncited_claim_count,
            "generated": self.generated.isoformat() if self.generated else None,
            "findings": [f.as_dict() for f in self.findings],
        }

    def as_markdown(self) -> str:
        """The ``audit-<date>.md`` artifact. Returns text; prints nothing."""
        if not self.n_rows:
            return (
                "# Ledger audit\n\n"
                "The ledger holds no rows, so there is nothing to audit and no proportion to "
                "report. An empty denominator is not a passing score.\n"
            )
        lines = [
            "# Ledger audit",
            "",
            f"Rows audited: {self.n_rows}",
            "",
            "| proportion | value |",
            "|---|---|",
            f"| rows whose results artifact exists | {_pct(self.artifact_rate)} |",
            f"| rows with a passing independent positive control | {_pct(self.control_rate)} |",
            f"| rows with an admissible oracle (strength >= "
            f"{MIN_ADMISSIBLE_STRENGTH}) | {_pct(self.admissible_oracle_rate)} |",
            "",
            f"Uncited claims across all rows: {self.uncited_claim_count}",
            "",
            "## Per row",
            "",
            "| row | verdict | artifact | control | oracle | uncited | notes |",
            "|---|---|---|---|---|---|---|",
        ]
        for f in self.findings:
            lines.append(
                f"| {f.row_id} | {f.verdict.value} | {_tick(f.artifact_exists)} | "
                f"{_tick(f.control_passed)} | {_tick(f.oracle_admissible)} | "
                f"{len(f.uncited_claims)} | {'; '.join(f.notes)} |"
            )
        lines.append("")
        lines.append(
            "This report refuses nothing. A row scored badly here was still recorded, which is "
            "the point: a store that rejected every imperfect row would leave an audit that "
            "only ever sees flattering ones."
        )
        return "\n".join(lines) + "\n"


def audit(
    rows: Iterable[LedgerRow],
    *,
    root: str | Path | None = None,
    now: dt.datetime | None = None,
) -> AuditReport:
    """Re-read the rows and report. Refuses nothing.

    ``root`` is the directory the ``results_artifact`` paths are relative to.
    ``None`` means artifact existence cannot be checked, and an unchecked
    artifact is reported absent rather than present: the audit does not award a
    pass for something it could not look at.
    """
    materialised = tuple(rows)
    base = Path(root) if root is not None else None
    superseded = {r.supersedes for r in materialised if r.supersedes}

    findings: list[RowFinding] = []
    for row in materialised:
        notes: list[str] = []

        named = str(row.results_artifact or "").strip()
        if not named:
            artifact_exists = False
            notes.append("no results artifact is named, so the verdict cannot be re-read")
        elif base is None:
            artifact_exists = False
            notes.append(
                f"results artifact {named!r} is named but no root was given, so its existence "
                "was not checked and is reported as absent"
            )
        else:
            artifact_exists = (base / named).exists()
            if not artifact_exists:
                notes.append(f"the named results artifact {named!r} is not on disk")

        control_passed = row.control.is_a_passing_independent_control
        if row.control.passed is None:
            notes.append("no positive control is recorded for this row")
        elif row.control.passed and row.control.independent is not True:
            notes.append(
                "the control passed but is not recorded as independent of the treatment, so it "
                "cannot separate the hypothesis from a containment both arms share"
            )
        elif not row.control.passed:
            notes.append("the recorded positive control did not pass")

        strength = ORACLE_STRENGTH.get(row.oracle)
        oracle_admissible = strength is not None and strength >= MIN_ADMISSIBLE_STRENGTH
        if strength is None:
            notes.append(
                f"the named oracle {row.oracle!r} is not in the strength table, so it is "
                "unscored -- which is reported as inadmissible, not as unknown"
            )
        elif not oracle_admissible:
            notes.append(
                f"the named oracle {row.oracle!r} is strength {strength}, below "
                f"{MIN_ADMISSIBLE_STRENGTH}"
            )

        uncited = tuple(c.text for c in row.claims if not c.cited)
        if uncited:
            notes.append(f"{len(uncited)} claim(s) carry no citation")

        if row.asserts_absence and not str(row.assumption or "").strip():
            notes.append("asserts an absence and states no assumption to reconstruct it from")

        if row.id in superseded:
            notes.append("superseded by a later row")

        findings.append(
            RowFinding(
                row_id=row.id,
                verdict=row.verdict,
                band=row.band,
                artifact_exists=artifact_exists,
                control_passed=control_passed,
                oracle_admissible=oracle_admissible,
                uncited_claims=uncited,
                supersedes=row.supersedes,
                notes=tuple(notes),
            )
        )

    total = len(findings)
    return AuditReport(
        findings=tuple(findings),
        n_rows=total,
        artifact_rate=_rate(sum(1 for f in findings if f.artifact_exists), total),
        control_rate=_rate(sum(1 for f in findings if f.control_passed), total),
        admissible_oracle_rate=_rate(sum(1 for f in findings if f.oracle_admissible), total),
        uncited_claim_count=sum(len(f.uncited_claims) for f in findings),
        generated=now or dt.datetime.now(dt.timezone.utc),
    )


def negatives_only(rows: Iterable[LedgerRow]) -> tuple[LedgerRow, ...]:
    """The rows that assert an absence -- the ones the headline claim is about."""
    return tuple(r for r in rows if r.asserts_absence)


def _rate(numerator: int, denominator: int) -> float | None:
    """``None`` on an empty denominator. Item 5, in one place."""
    if denominator <= 0:
        return None
    return numerator / denominator


def _pct(rate: float | None) -> str:
    return "n/a (no rows)" if rate is None else f"{rate:.0%} ({rate:.3f})"


def _tick(value: bool) -> str:
    return "yes" if value else "NO"
