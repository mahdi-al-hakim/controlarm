"""The false-positive catalogue as executable checks, plus two comparison arms.

This module is the thing being measured. It is kept in ``benchmarks/`` rather
than ``src/controlarm/gates/`` on purpose for now: a gate that lives in the
package would be scored by a benchmark that imports it, and the benchmark's
first job is to be auditable by someone who does not trust the package.
Promoting it is a follow-up, and until then the benchmark says which
implementation it scored (see ``results/fp_corpus.md``).

Three adjudicators, one signature
---------------------------------
:func:`adjudicate` takes ``arm=``:

``"gated"``
    The catalogue, enforced. The thing being measured.

``"fair"``
    **The primary comparison arm.** A competent engineer with no library, who
    reads the status code, looks at whether their own positive control fired,
    looks at the number they are about to report, and is allowed to answer "I
    cannot tell". It has no echo normalisation, no refusal spans, no
    field-provenance logic, no independence check and no coverage check. This
    arm exists because an external reviewer established that the arm below
    could not express the correct answer for the cases the headline is computed
    over, which made the headline a restatement of two output alphabets rather
    than a comparison. The implementation is the reviewer's, transcribed from
    ``fp_corpus/critic/run_critic.py:competent`` and extended only where a
    fixture was re-expressed so that the gate had to derive a conclusion it
    used to read; ``tests/test_benchmark.py`` pins the two to agreement on the
    reviewer's own cases.

``"naive"``
    The check that actually produced each catalogued false verdict: a
    substring, a raw byte diff, an arm that executed. This is **provenance, not
    a comparison**: it is the real history of the corpus, every branch of it
    shipped and fired and was believed, and its predicates are frozen for that
    reason. It can emit only ``CANDIDATE`` and ``no-bug``, so its score on any
    case whose correct answer is a refusal is fixed before the fixture is read.
    It is reported as a third arm and is no longer the headline.

``gates_enabled=True/False`` is kept as an alias for ``"gated"``/``"naive"``.

The adjudicators receive **only** the ``observation`` dict. They never see the
case's label, its shape id, or its expected verdict.
``tests/test_benchmark.py::test_gates_cannot_see_the_label`` enforces that by
re-running every case with decoy label keys injected and asserting the
decisions are byte-identical.

Rule ids (``A2``, ``A3`` ...) are the oracle-admissibility and control-validity
rules from the methodology extraction. The numbered defects they discharge are
named in each docstring so a rule cannot be deleted without deleting its reason.

Repairs made after the external critique, each with the case that found it
---------------------------------------------------------------------------
``A3``/``A9``  key names are normalised, not only values (critic ``c01``). The
    body was canonicalised and the key-set was not, so an echo reflected into a
    key name was erased from one half of the differential and survived in the
    other. The rule says canonicalise *before any differential*; a key-set is a
    differential.
``B-independence``  host comparison is case-insensitive, and derives shared
    containment from the recorded allowlist where one exists (critic ``c02``).
    DNS is case-insensitive, so ``LISTENER.invalid`` and ``listener.invalid``
    are one host and one containment.
``O-control``  a positive control that names no observable is refused, and a
    control claimed to have run with its observable keys absent raises (critic
    ``c05``). An empty string is a missing input, and a missing input must never
    pass.
``T-eol``  a wrap candidate must sit inside a paragraph (critic ``c06``). The
    old predicate flagged every markdown list item, table row and fenced code
    line, which is the catalogued 3.6(c) false positive in a new costume.

Two of the reviewer's failures are **published unfixed**, because they are
limits of the rule rather than of this implementation. See
``results/fp_corpus.md`` and ``GAPS.md`` G2c: critic ``c03-genuine`` (bare
``denied``/``blocked`` in ordinary proxy logs manufacture a false negative; the
rule cannot be stated mechanically without re-opening FP#3) and critic
``c04-false`` (a config field named ``host``; rule A5 is about provenance and no
fixture can record provenance the rig did not capture).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from controlarm.controls.run import Outcome, Role, Run, Verdict

__all__ = [
    "ARMS",
    "CONFIG_FIELDS",
    "CONFOUNDED",
    "RECEIVING_FIELDS",
    "REFUSAL_MARKERS",
    "GateResult",
    "adjudicate",
    "known_kinds",
]

#: The three adjudicators, in the order the results file reports them. ``fair``
#: is the primary comparison arm; ``naive`` is provenance.
ARMS = ("gated", "fair", "naive")

#: Field names whose value the *caller* or the *rig* put there. A match under one
#: of these is never evidence about the target. (FP#4 submitted source, FP#5 the
#: listener's own ``expected_token`` config, FP#6 the URL the tester supplied.)
CONFIG_FIELDS = frozenset(
    {
        "allowed",
        "allowed_hosts",
        "allowlist",
        "config",
        "echo",
        "echo_url",
        "expected",
        "expected_token",
        "input",
        "payload",
        "request",
        "request_url",
        "source",
        "submitted",
        "submitted_source",
    }
)

#: Field names that record what the target *produced* or what a listener
#: *received*. Only a match under one of these can be an oracle.
RECEIVING_FIELDS = frozenset(
    {
        "authorization",
        "final_host",
        "host",
        "observed_headers",
        "received",
        "received_headers",
        "response_body",
        "sink_output",
        "stderr",
        "stdout",
    }
)

#: Text that marks the surrounding span as a refusal rather than a result.
#: A refusal quotes back the very token a leak detector hunts for. (FP#3)
REFUSAL_MARKERS = (
    r"\bi (can'?t|cannot|won'?t|will not)\b",
    r"\bnot going to\b",
    r"\brefus(e|ed|ing)\b",
    r"\bdeclin(e|ed|ing)\b",
    r"\bdenied\b",
    r"\bblocked\b",
    r"\bpolicy (violation|prohibits)\b",
)
_REFUSAL_RX = re.compile("|".join(REFUSAL_MARKERS), re.IGNORECASE)

#: Below this, a through-origin fit is not a growth law, it is a shape. (3.6a)
R2_FLOOR = 0.90

#: ``CONFOUNDED`` is a first-class terminal state in the ledger vocabulary, but
#: ``controlarm.controls.run.Verdict`` has only five members and collapses it
#: into ``VOID``. The two are not the same answer -- VOID says "the rig did not
#: work", CONFOUNDED says "the rig worked and the comparison was invalid" -- and
#: the recorded remedies differ (re-run versus redesign as a 2x2). Until the
#: enum carries it, the gate emits the token directly and the results file
#: reports the divergence rather than hiding it.
CONFOUNDED = "CONFOUNDED"


@dataclass(frozen=True)
class GateResult:
    """``decision`` is the scored output; ``verdict`` is what a ledger would record."""

    decision: str  # "SUPPORTED" | "REFUSED"
    verdict: str  # a verdict token: CANDIDATE / KILL / VOID / CONFOUNDED / INCONCLUSIVE
    rule: str  # the rule id that decided it, or "naive" / "none"
    why: str
    fired: tuple[str, ...] = field(default=())

    @property
    def supported(self) -> bool:
        return self.decision == "SUPPORTED"


def _supported(verdict: str, rule: str, why: str) -> GateResult:
    return GateResult("SUPPORTED", verdict, rule, why)


def _refused(verdict: str, rule: str, why: str, fired: tuple[str, ...] = ()) -> GateResult:
    return GateResult("REFUSED", verdict, rule, why, fired or (rule,))


# --------------------------------------------------------------------- helpers


def _leaves(node: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    """Every scalar in a nested structure, with the key path that reaches it."""
    if isinstance(node, dict):
        out: list[tuple[tuple[str, ...], Any]] = []
        for k, v in node.items():
            out.extend(_leaves(v, (*path, str(k))))
        return out
    if isinstance(node, list):
        out = []
        for i, v in enumerate(node):
            out.extend(_leaves(v, (*path, f"[{i}]")))
        return out
    return [(path, node)]


def _supplied_strings(request: dict | None) -> set[str]:
    """Every string value the caller put into the request, at any depth."""
    if not request:
        return set()
    return {str(v) for _, v in _leaves(request) if isinstance(v, str) and v}


def _strip_supplied(text: str, supplied: set[str]) -> str:
    """Replace every string the caller supplied with a single placeholder.

    Longest-first, so ``doc_2002`` is replaced before ``doc_``.
    """
    for s in sorted(supplied, key=len, reverse=True):
        text = text.replace(s, "<SUPPLIED>")
    return text


def _normalise(body: Any, supplied: set[str]) -> str:
    """Canonicalise a response with the caller's own strings removed.

    A3: strip or canonicalise every echoed identifier *before* any differential.
    """
    return _strip_supplied(json.dumps(body, sort_keys=True), supplied)


def _normalise_keys(body: Any, supplied: set[str]) -> tuple[str, ...]:
    """The key-set, with the caller's own strings removed from the key *names*.

    A3 again, and the defect critic case ``c01`` found: the body was
    canonicalised and the key-set was not, so a server that reflects the
    submitted identifier into a key name (``echo_doc_1001`` against
    ``echo_doc_9999``) produced two key-sets that differ only by the tester's
    own input. ``same_body`` then said "identical" while ``same_keys`` said
    "different", and both the A3 and the A9 branch require ``same_keys``, so
    the gate fell through to SUPPORTED. The rule says canonicalise before
    *any* differential; a key-set is a differential.
    """
    return tuple(sorted(_strip_supplied(str(k), supplied) for k in (body or {})))


def _host(value: Any) -> str:
    """Canonicalise a host for comparison. DNS is case-insensitive.

    Critic case ``c02``: ``_gate_run_lattice`` compared the control's and the
    treatment's target with ``==`` on two raw strings, so ``listener.invalid``
    and ``LISTENER.invalid`` read as two independent targets when they are one
    host and one containment. "Independent of" is not ``str.__eq__``.
    """
    return str(value or "").strip().rstrip(".").lower()


def _in_allowlist(host: str, allowlist: list[str]) -> bool:
    """Whether ``host`` is covered by an egress allowlist entry.

    Entries may be exact hosts or ``*.suffix`` wildcards, matched on labels so
    that ``evil-allowed.example`` does not match ``allowed.example``.
    """
    for entry in allowlist:
        pattern = _host(entry).lstrip("*").lstrip(".")
        if not pattern:
            continue
        if host == pattern or host.endswith("." + pattern):
            return True
    return False


def _test_arms(obs: dict) -> list[dict]:
    return [a for a in obs["arms"] if a.get("role") == Role.TEST.value]


def _reached_application_layer(obs: dict) -> bool:
    """Derive whether any treatment arm got an application-layer exchange.

    This replaces reading a ``reached_application_layer`` boolean out of the
    fixture, which an external reviewer correctly identified as the fixture
    stating the gate's conclusion: "the probe never reached the application
    layer" *is* the finding. What a run can actually record is each probe's own
    transport result and the status it got back, so that is what the fixture
    now carries and this is the inference drawn from it.

    The declared boolean is still honoured when no probe record exists, because
    a case whose source material recorded only the summary cannot be made to
    carry more than its source material had.
    """
    records = [
        a["probe_record"] for a in _test_arms(obs) if isinstance(a.get("probe_record"), dict)
    ]
    if records:
        return any(r.get("app_layer_status") is not None for r in records)
    return obs.get("reached_application_layer") is not False


def _control_recorded_in_run(obs: dict) -> bool:
    """Derive whether the asserted positive control belongs to *this* run.

    Same re-expression as :func:`_reached_application_layer`: the fixture used
    to carry ``control_recorded_in_run: false``, which is the conclusion. It now
    carries the run's own start and end stamps and the stamp on the control
    record, and the staleness is derived by comparing them.
    """
    window = obs.get("run_window") or {}
    started, ended = window.get("started"), window.get("ended")
    stamps = [
        a["recorded_at"]
        for a in obs["arms"]
        if a.get("role") == Role.HONEST_CONTROL.value and a.get("recorded_at")
    ]
    if started and ended and stamps:
        return all(started <= s <= ended for s in stamps)
    return obs.get("control_recorded_in_run") is not False


def _shared_containment(obs: dict) -> tuple[bool, str]:
    """Derive whether the positive control is independent of the treatment.

    Two readings, in order of how much the fixture has to hand the gate:

    1. The run recorded the **egress allowlist in force** and each arm's own
       target host. The gate then derives the thing that matters -- is the
       control subject to the same containment as the treatment -- by testing
       both hosts against the allowlist. Two different hosts, both outside the
       allowlist, are one containment, and a silent control cannot discriminate.
    2. Only the two target labels were recorded. They are compared as hosts,
       case-insensitively (critic ``c02``).

    Returns ``(shared, why)``; ``why`` is empty when they are independent.
    """
    allowlist = [str(x) for x in (obs.get("egress_allowlist") or [])]
    control = [
        _host(a.get("target"))
        for a in obs["arms"]
        if a.get("role") == Role.HONEST_CONTROL.value and a.get("target")
    ]
    treatment = [_host(a.get("target")) for a in _test_arms(obs) if a.get("target")]
    if allowlist and control and treatment:
        contained = [h for h in control if not _in_allowlist(h, allowlist)]
        if contained and all(not _in_allowlist(h, allowlist) for h in treatment):
            return True, (
                f"the positive control targets {contained!r}, which the recorded egress "
                f"allowlist {sorted(allowlist)!r} does not cover, and neither does it cover the "
                f"treatment's target {sorted(set(treatment))!r}. Control and treatment are "
                "subject to the same containment, so a silent control cannot distinguish "
                "'never fetches' from 'egress blocked'. Redesign as 2x2."
            )
        return False, ""

    ct, tt = obs.get("control_target"), obs.get("treatment_target")
    if ct is not None and _host(ct) == _host(tt):
        return True, (
            f"the positive control and the treatment both target {_host(ct)!r}, so they test "
            "the same containment. A silent control cannot distinguish the two hypotheses. "
            "Redesign as 2x2."
        )
    return False, ""


def _scanned_artifacts(obs: dict) -> tuple[str, ...] | None:
    """Which artifacts the detector actually read. ``None`` when nothing recorded it.

    Re-expressed after the critique: ``artifact_scanned`` was a declared label
    sitting next to the declared ``artifact_claimed``, so the comparison was
    between two assertions by the same author. What a run records is the
    detector's own invocation -- its argv and the files it opened -- so the
    scanned set is now derived from that instrument record, and only the *claim*
    side remains a declaration. The two halves then have different provenance,
    which is what makes the comparison a measurement.

    A set rather than a single path, because a detector that opened several
    files has measured the claimed one if the claimed one is among them, and
    collapsing the record to one path would make that answer depend on sort
    order.
    """
    invocation = obs.get("scanner_invocation")
    if isinstance(invocation, dict):
        opened = tuple(str(f) for f in (invocation.get("files_opened") or []))
        if opened:
            return opened
    scanned = obs.get("artifact_scanned")
    return None if scanned is None else (str(scanned),)


def _untested_branch_fields(obs: dict) -> list[str]:
    """Fields the target branches on that the PoC drove at only one value.

    Re-expressed after the critique: ``fields_branched_on`` was one dict that
    mapped each branched field straight to the values the fixture used, i.e. the
    rule's antecedent written down as a literal. It is now two separately
    sourced records -- ``target_branch_fields``, read off the target's own
    dispatch, and ``fixture_values``, read off the PoC's recorded runs -- and
    the gate derives the intersection. The merged form is still accepted for
    cases whose source material recorded only the merged summary.
    """
    branch_fields = obs.get("target_branch_fields")
    values = obs.get("fixture_values")
    if branch_fields is not None and values is not None:
        return sorted(
            str(f) for f in branch_fields if len({str(v) for v in (values.get(f) or [])}) < 2
        )
    branched = obs.get("fields_branched_on") or {}
    return sorted(k for k, vals in branched.items() if len(set(vals)) < 2)


def _refusal_spans(raw: str) -> list[tuple[int, int]]:
    """Line ranges that sit inside a refusal.

    A refusal marker claims its own line and the line after it, because the
    quoted thing being refused is routinely on the next line.
    """
    lines = raw.splitlines(keepends=True)
    spans: list[tuple[int, int]] = []
    offset = 0
    marked: set[int] = set()
    bounds: list[tuple[int, int]] = []
    for line in lines:
        bounds.append((offset, offset + len(line)))
        offset += len(line)
    for i, line in enumerate(lines):
        if _REFUSAL_RX.search(line):
            marked.update({i, i + 1})
    for i in sorted(marked):
        if i < len(bounds):
            spans.append(bounds[i])
    return spans


# ------------------------------------------------------------ the gated checks


def _gate_http_differential(obs: dict) -> GateResult:
    """A2, A3, A9 over a set of HTTP arms.

    A2 (FP#1): a 4xx is a rejection by definition, so it cannot carry a
    disclosure verdict however foreign the bytes in it look.
    A3 (FP#2): normalise every string the caller supplied out of both arms
    before diffing -- out of the key names as well as the values, or you are
    measuring your own echo in whichever half you forgot.
    A9: the discriminating observable is the key-set and the status class, not
    the error text, which varies for boring reasons.
    """
    claim = obs["claim"]
    arms = obs["arms"]
    fired: list[str] = []

    if claim == "disclosure":
        bad = [a["label"] for a in arms if 400 <= a["response"]["status"] < 500]
        if bad:
            return _refused(
                Verdict.KILL.value,
                "A2",
                f"arms {bad} returned 4xx. An error that echoes your own input is a rejection, "
                "not a disclosure. A disclosure verdict needs a 2xx carrying foreign data.",
            )

    normalised = {}
    for arm in arms:
        supplied = _supplied_strings(arm.get("request"))
        normalised[arm["label"]] = {
            "body": _normalise(arm["response"].get("body"), supplied),
            "status": arm["response"]["status"],
            "keys": _normalise_keys(arm["response"].get("body"), supplied),
        }

    labels = list(normalised)
    if len(labels) >= 2:
        first = normalised[labels[0]]
        same_body = all(normalised[x]["body"] == first["body"] for x in labels[1:])
        same_status = all(normalised[x]["status"] == first["status"] for x in labels[1:])
        same_keys = all(normalised[x]["keys"] == first["keys"] for x in labels[1:])
        if same_body and same_status and same_keys:
            return _refused(
                Verdict.KILL.value,
                "A3",
                "after normalising the identifiers the caller supplied, every arm is "
                "byte-identical in body, status class and key-set. The differential was the echo.",
            )
        if claim == "existence-oracle" and same_status and same_keys:
            return _refused(
                Verdict.KILL.value,
                "A9",
                "the arms differ only in error text, not in status class or key-set. Error text "
                "varies for boring reasons; it is not an existence oracle.",
            )
        fired.append("A3-passed")

    if claim == "disclosure":
        # The surviving requirement: some leaf in a 2xx arm that no arm's caller
        # supplied and that the other arm did not also return.
        foreign = []
        for arm in arms:
            if not (200 <= arm["response"]["status"] < 300):
                continue
            supplied = _supplied_strings(arm.get("request"))
            others = {
                str(v)
                for other in arms
                if other is not arm
                for _, v in _leaves(other["response"].get("body"))
                if isinstance(v, str)
            }
            for path, value in _leaves(arm["response"].get("body")):
                if isinstance(value, str) and value not in supplied and value not in others:
                    foreign.append("/".join(path))
        if not foreign:
            return _refused(
                Verdict.KILL.value,
                "A4",
                "no leaf in any 2xx arm carries a value the caller did not supply and the "
                "sibling arm did not also return. Nothing foreign was disclosed.",
            )
        return _supported(
            Verdict.CANDIDATE.value,
            "A2+A3+A4",
            f"a 2xx arm carries foreign leaves {sorted(set(foreign))} that survive normalisation.",
        )

    return _supported(
        Verdict.CANDIDATE.value,
        "A3+A9",
        "the arms still differ in status class or key-set after echo normalisation.",
    )


def _gate_parsed_field(obs: dict) -> GateResult:
    """A4 and A5: the oracle is a parsed field, never a substring.

    Discharges FP#4 (a marker that was a literal in the source we submitted),
    FP#5 (a hit on the listener's own ``expected_token`` configuration key) and
    FP#6 (a nonce counted as a redirect hop when it sat in the allowlisted URL
    path the tester himself supplied).
    """
    needle = obs["needle"]
    artifact = obs["artifact"]
    if isinstance(artifact, str):
        try:
            artifact = json.loads(artifact)
        except json.JSONDecodeError:
            return _refused(
                Verdict.KILL.value,
                "A5",
                "the artifact does not parse, so the only available check is a substring over "
                "bytes. There is no parsed field to read and therefore no oracle.",
            )

    hits = [path for path, value in _leaves(artifact) if isinstance(value, str) and needle in value]
    if not hits:
        return _refused(
            Verdict.KILL.value, "A5", f"the needle {needle!r} appears in no parsed field."
        )

    receiving = [p for p in hits if any(seg in RECEIVING_FIELDS for seg in p)]
    configured = [p for p in hits if any(seg in CONFIG_FIELDS for seg in p)]
    if not receiving:
        where = sorted("/".join(p) for p in (configured or hits))
        return _refused(
            Verdict.KILL.value,
            "A4",
            f"every occurrence sits under a field the caller or the rig populated ({where}). "
            "When the string you hunt is inside something you control, a match is not an oracle.",
        )
    return _supported(
        Verdict.CANDIDATE.value,
        "A5",
        f"the needle is present in a receiving field ({sorted('/'.join(p) for p in receiving)}).",
    )


def _gate_artifact_envelope(obs: dict) -> GateResult:
    """A6: read the raw bytes, not the detector's summary.

    Refusal text, code strings and config fields routinely contain the exact
    tokens a leak heuristic flags. (FP#3)
    """
    raw: str = obs["raw"]
    needle: str = obs["needle"]
    spans = _refusal_spans(raw)
    occurrences = [m.start() for m in re.finditer(re.escape(needle), raw)]
    if not occurrences:
        return _refused(
            Verdict.KILL.value, "A6", f"the needle {needle!r} is absent from the raw bytes."
        )
    outside = [o for o in occurrences if not any(lo <= o < hi for lo, hi in spans)]
    if not outside:
        return _refused(
            Verdict.KILL.value,
            "A6",
            f"all {len(occurrences)} occurrences lie inside a refusal span. A refusal quotes back "
            "the thing it is refusing; that is not an exfiltration.",
        )
    return _supported(
        Verdict.CANDIDATE.value,
        "A6",
        f"{len(outside)} of {len(occurrences)} occurrences lie outside every refusal span.",
    )


def _gate_token_novelty(obs: dict) -> GateResult:
    """A7: novelty is a per-artifact token set-difference. A new line can hold an old name."""
    old = set(obs["old_tokens"])
    new = set(obs["new_tokens"])
    claimed = list(obs["claimed_new"])
    genuinely_new = new - old
    stale = [c for c in claimed if c not in genuinely_new]
    if stale:
        return _refused(
            Verdict.KILL.value,
            "A7",
            f"{stale} are present in the prior artifact's token set. Grepping new *lines* for a "
            "substring measures line novelty, not identifier novelty.",
        )
    return _supported(
        Verdict.CANDIDATE.value,
        "A7",
        f"every claimed identifier is in the per-artifact set difference "
        f"({len(genuinely_new)} new).",
    )


def _gate_run_lattice(obs: dict) -> GateResult:
    """The arm lattice, plus the three VOID triggers the lattice alone misses.

    (b) the control must be independent of the treatment -- a control pointed at
    a host that was itself outside the allowlist tested the *same* containment,
    so a silent control could not distinguish "never fetches" from "egress
    blocked". (VOID-2)

    (d) a probe with no results artifact makes its own negative unauditable, and
    that was one of three independent grounds for voiding VOID-1.

    A control recorded before the run is not a control for this run. VOID-1's
    asserted positive control was a loopback self-test against a different port,
    five days earlier.

    Three of the four preconditions are now **derived** rather than read. The
    fixtures used to carry ``reached_application_layer``,
    ``control_recorded_in_run`` and a pair of target labels compared with
    ``==``; an external reviewer pointed out that those fields *are* the
    conclusions, so a gate handed them is a lookup table. They are derived
    instead from each probe's own transport record, from the run's start and end
    stamps against the control record's stamp, and from the recorded egress
    allowlist against each arm's target host. See :func:`_reached_application_layer`,
    :func:`_control_recorded_in_run` and :func:`_shared_containment`.
    """
    run = Run(obs.get("title", "benchmark case"))
    for spec in obs["arms"]:
        outcome = Outcome(spec["outcome"])
        detail = spec.get("detail", "")
        fn = lambda o=outcome, d=detail: (o is Outcome.EXECUTED, d)
        role = Role(spec["role"])
        if role is Role.LIVENESS:
            run.liveness(fn, spec["name"])
        elif role is Role.HONEST_CONTROL:
            run.honest_control(fn, spec["name"])
        else:
            run.arm(spec["name"], fn, role=role)
    verdict, why = run.decide()

    # Every precondition is evaluated, not only the first that fires. The
    # reviewer's fired-rule census showed B-stale-control and B-reachability
    # firing zero times across all 38 cases, because void08-false trips all
    # three and the old code returned on B-artifact before reaching the other
    # two. The verdict is still decided by the first in this fixed order -- the
    # remedies differ and an operator needs one next action -- but every rule
    # that fired is recorded in ``fired`` so coverage can be audited.
    triggered: list[tuple[str, str, str]] = []
    if not obs.get("results_artifact", True):
        triggered.append(
            (
                Verdict.VOID.value,
                "B-artifact",
                "no results artifact was written, so the negative is unauditable and cannot be "
                "re-derived. Every other probe in the same batch wrote one.",
            )
        )
    if not _control_recorded_in_run(obs):
        triggered.append(
            (
                Verdict.VOID.value,
                "B-stale-control",
                "the asserted positive control is stamped outside this run's own window. A "
                "control from an earlier run against a different endpoint proves nothing about "
                "this one.",
            )
        )
    shared, shared_why = _shared_containment(obs)
    if shared:
        triggered.append((CONFOUNDED, "B-independence", shared_why))
    if not _reached_application_layer(obs):
        triggered.append(
            (
                Verdict.VOID.value,
                "B-reachability",
                "no treatment arm recorded an application-layer exchange, so there were zero "
                "app-layer hits to be absent. This is VOID, not a negative.",
            )
        )
    if triggered:
        decided, rule, reason = triggered[0]
        return _refused(decided, rule, reason, tuple(r for _, r, _ in triggered))

    if verdict in (Verdict.VOID, Verdict.INCONCLUSIVE, Verdict.NO_TESTS):
        return _refused(verdict.value, "lattice", why)
    claim = obs["claim"]
    if claim == "clean-negative":
        if verdict is Verdict.KILL:
            return _supported(verdict.value, "lattice", why)
        return _refused(verdict.value, "lattice", why)
    if verdict is Verdict.CANDIDATE:
        return _supported(verdict.value, "lattice", why)
    return _refused(verdict.value, "lattice", why)


def _gate_oracle_expressivity(obs: dict) -> GateResult:
    """4.6: a negative is only as strong as the PoC's ability to express the positive.

    Four mechanisms, one rule. The planted positive must actually appear in the
    bytes the oracle reads:

      * the listing command did not render the field under test, so the field's
        absence read as the feature's absence; (3.4a)
      * colour escapes survived the suppression variable, so the oracle string
        could never match the rendered bytes; (3.4b)
      * string surgery wrote literal control bytes into the regex; (3.4c)
      * the detector was pointed at the PoC file instead of the source under
        test, and PoCs call the accessor for their own assertions. (3.6d)
    """
    scanned = _scanned_artifacts(obs)
    claimed = obs.get("artifact_claimed")
    if scanned is not None and claimed is not None and str(claimed) not in scanned:
        return _refused(
            Verdict.VOID.value,
            "O-target",
            f"the detector opened {sorted(scanned)!r} and the claim is about {claimed!r}, which "
            "it never read. A rate measured against the PoC is a measurement of the PoC.",
        )

    pc = obs.get("positive_control") or {}
    if not pc:
        return _refused(
            Verdict.VOID.value,
            "O-control",
            "no positive control is recorded, so the oracle was never shown to be able to "
            "express the result it failed to find.",
        )
    if not pc.get("ran", False):
        return _refused(
            Verdict.VOID.value,
            "O-control",
            "the positive control did not execute. The rig was never shown to produce a "
            "positive, so no absence in this run is interpretable. This is VOID, not KILL.",
        )
    # A control that claims to have run but records neither what it looked for
    # nor what it saw is a malformed input, not a passing check, and a malformed
    # input must raise rather than be defaulted to the empty string. Critic case
    # ``c05`` found the softer half of this: the guard was
    # ``if expected and expected not in observed``, so an *empty*
    # ``expected_observable`` made the only check that the control proved
    # anything unreachable, and the gate written to catch VOID-1 accepted
    # VOID-1's own failure mode.
    for key in ("expected_observable", "observed"):
        if key not in pc:
            raise ValueError(
                f"positive_control claims ran=true but has no {key!r}. A control whose "
                "observable was never recorded cannot be adjudicated; the gate will not "
                "substitute an empty string for a missing measurement."
            )
    expected, observed = str(pc["expected_observable"]), str(pc["observed"])
    if not expected.strip():
        return _refused(
            Verdict.VOID.value,
            "O-control",
            "the positive control names no expected observable, so it cannot fail and is "
            "therefore not a control. This is the same condition as 'no positive control was "
            "recorded', wearing a ran=true flag.",
        )
    if expected not in observed:
        return _refused(
            Verdict.VOID.value,
            "O-expressivity",
            f"a positive was planted and the oracle still did not see {expected!r} in the bytes "
            f"it reads ({observed[:60]!r}). The oracle cannot express the positive, so its "
            "silence on the treatment arm is not evidence.",
        )

    under_test = set(obs.get("paths_under_test") or [])
    in_target = set(obs.get("paths_in_target") or [])
    missed = sorted(in_target - under_test)
    if missed:
        return _refused(
            Verdict.INCONCLUSIVE.value,
            "O-coverage",
            f"the PoC exercises {sorted(under_test)} but the target also reaches {missed}. "
            "A negative is scoped to the paths the PoC can actually drive.",
        )

    untested = _untested_branch_fields(obs)
    if untested:
        return _refused(
            Verdict.INCONCLUSIVE.value,
            "O-fixture",
            f"the fixture pins {untested} to a single value, and the target branches on each. "
            "State the configuration the result is scoped to, or test both values.",
        )

    if obs["claim"] == "clean-negative":
        return _supported(
            Verdict.KILL.value,
            "O-expressivity",
            "the planted positive was observed by this oracle, every reachable path is "
            "exercised, and every branched field is tested on both values.",
        )
    return _supported(
        Verdict.CANDIDATE.value, "O-expressivity", "the oracle can express the positive."
    )


def _covering_array_lower_bound(obs: dict) -> int:
    """The feasible minimum row count for a t-way covering array, computed.

    Re-expressed after the critique, which observed that the fixture supplied
    ``independent_minimum: 384`` and the gate merely compared against it -- the
    hard step having been done by whoever wrote the JSON. The bound is not hard:
    a t-way covering array must contain every combination of values for every
    choice of t factors, so it needs at least as many rows as the largest such
    product, which is the product of the t largest factor cardinalities. The
    fixture now records the **factor model** -- the parameters and how many
    values each takes, which is a property of the system under test -- and the
    gate computes the bound from it.

    The declared minimum is still accepted when no factor model was recorded.
    """
    factors = obs.get("factors")
    if isinstance(factors, dict) and factors:
        strength = int(obs.get("strength", 3))
        cardinalities = sorted((int(v) for v in factors.values()), reverse=True)
        if strength > len(cardinalities):
            raise ValueError(
                f"strength {strength} exceeds the {len(cardinalities)} factors recorded; a "
                f"{strength}-way array over fewer than {strength} factors is not a thing."
            )
        bound = 1
        for value in cardinalities[:strength]:
            bound *= value
        return bound
    return int(obs["independent_minimum"])


def _gate_numeric_claim(obs: dict) -> GateResult:
    """3.6(a) and 3.6(b): a fit worse than the mean is not a growth law, and a
    covering array smaller than the feasible minimum is not a covering array."""
    metric = obs["metric"]
    if metric == "r2":
        value = float(obs["value"])
        if value < R2_FLOOR:
            return _refused(
                "INCONCLUSIVE",
                "N-fit",
                f"r2={value} is below the {R2_FLOOR} floor. A through-origin fit worse than the "
                "mean cannot be reported as a confident growth law.",
            )
        return _supported("CANDIDATE", "N-fit", f"r2={value} clears the {R2_FLOOR} floor.")
    if metric == "coverage":
        rows = int(obs["rows"])
        minimum = _covering_array_lower_bound(obs)
        errors = int(obs.get("constraint_eval_errors", 0))
        if errors:
            return _refused(
                "INCONCLUSIVE",
                "N-denominator",
                f"{errors} constraint evaluations read an unbound variable, so legal rows were "
                "rejected and the coverage denominator is itself unverified.",
            )
        if rows < minimum:
            return _refused(
                "INCONCLUSIVE",
                "N-denominator",
                f"{rows} rows is below the independently computed feasible minimum of {minimum}, "
                "so this is not the covering array it reports itself to be.",
            )
        return _supported(
            "CANDIDATE", "N-denominator", f"{rows} rows meets the independent minimum {minimum}."
        )
    raise ValueError(f"unknown metric {metric!r}")


#: Markdown block-structure line openers. A line that starts one of these ends
#: where its author ended it: the break is the document's structure, not a wrap.
_BLOCK_OPENERS = re.compile(
    r"""^\s*(?:
          [-*+]\s          # bullet list item
        | \d+[.)]\s        # ordered list item
        | \|               # table row or delimiter
        | \#{1,6}\s        # ATX heading
        | >                # block quote
        | (?:```|~~~)      # fence delimiter
        | (?:=+|-{2,}|:?-{3,}:?)\s*$   # setext underline / thematic break
    )""",
    re.VERBOSE,
)


def _paragraph_lines(lines: list[str]) -> list[bool]:
    """Which lines are running prose inside a paragraph.

    A hard wrap is by definition a break *inside a paragraph*, so a line that is
    not in a paragraph cannot be one. Fenced regions are excluded wholesale and
    every block opener is excluded individually. This is markdown's block
    grammar, not a word list: the test is the line's structural role, which is
    why it does not re-open the vocabulary problem the catalogue warns about.
    """
    out: list[bool] = []
    in_fence = False
    for line in lines:
        is_fence = bool(re.match(r"^\s*(?:```|~~~)", line))
        if is_fence:
            in_fence = not in_fence
            out.append(False)
            continue
        out.append(bool(line.strip()) and not in_fence and not _BLOCK_OPENERS.match(line))
    return out


def _gate_text_measurement(obs: dict) -> GateResult:
    """3.6(c): normalise line endings, and measure wraps only inside paragraphs.

    Email line endings leave a bare carriage return on otherwise-blank lines, so
    a wrapped-line linter flagged every paragraph break. That artifact produced
    a false positive on first use.

    Critic case ``c06`` then showed that normalising the carriage return fixed
    the symptom and left the cause: the predicate flagged index ``i`` whenever
    ``lines[i]`` and ``lines[i+1]`` were both non-blank and ``lines[i]`` was
    short, which is every list item, every table row and every line of a code
    fence. The verdict text already claimed "no line is a mid-paragraph hard
    wrap" while the predicate never tested "mid-paragraph". It does now.
    """
    raw: str = obs["raw"]
    width = int(obs["max_width"])
    lines = [ln.replace("\r", "") for ln in raw.replace("\r\n", "\n").split("\n")]
    prose = _paragraph_lines(lines)
    wrapped = [
        i for i in range(len(lines) - 1) if prose[i] and prose[i + 1] and len(lines[i]) < width
    ]
    if not wrapped:
        return _refused(
            Verdict.KILL.value,
            "T-eol",
            "after normalising line endings and dropping bare carriage returns, no line inside a "
            "paragraph is followed by another paragraph line, so there is no mid-paragraph hard "
            "wrap. The hits were blank lines carrying a lone CR, or markdown block structure.",
        )
    return _supported(
        Verdict.CANDIDATE.value,
        "T-eol",
        f"{len(wrapped)} genuine hard wraps survive normalisation.",
    )


# --------------------------------------------------------------- naive baseline


def _naive(obs: dict) -> GateResult:
    """The check that produced each catalogued false verdict. Provenance, not a baseline.

    Every branch here is a check that shipped, fired, and was believed, and the
    predicates are **frozen** for exactly that reason: this arm's value is that
    it is the corpus's own history, and a history that gets edited to look
    better is no longer evidence of anything.

    It is therefore no longer the headline comparison. An external reviewer
    established that it cannot emit a refusal verdict at all -- only
    ``CANDIDATE`` and ``no-bug`` -- so its score on any case whose correct
    answer is a refusal is fixed before the fixture is read, and three of its
    branches decline to look at data they already hold:

      * ``run_lattice`` filters to ``role == TEST`` and never reads the
        liveness or honest-control arms;
      * ``oracle_expressivity`` has the positive control's bytes in hand and the
        ``clean-negative`` branch does not consult them;
      * ``numeric_claim`` returns ``CANDIDATE`` unconditionally, without looking
        at the value it is reporting.

    Those three are what :func:`_fair` exists to repair. It is the arm that now
    carries the comparative claim; this one carries the provenance, and
    ``tests/test_benchmark.py`` pins its outputs so it cannot drift into being a
    second fair arm.
    """
    kind = obs["kind"]
    if kind == "http_differential":
        arms = obs["arms"]
        bodies = {a["label"]: json.dumps(a["response"].get("body"), sort_keys=True) for a in arms}
        if obs["claim"] == "disclosure":
            planted = [s for a in arms for s in _supplied_strings(a.get("request"))]
            hit = [b for b in bodies.values() if any(p in b for p in planted)]
            if hit:
                return _supported("CANDIDATE", "naive", "the identifier under test is in the body.")
            return _refused("no-bug", "naive", "the identifier is not in the body.")
        distinct = len(set(bodies.values()))
        if distinct > 1:
            return _supported("CANDIDATE", "naive", f"{distinct} distinct response bodies.")
        return _refused("no-bug", "naive", "the arms are byte-identical.")
    if kind == "parsed_field":
        blob = obs["artifact"] if isinstance(obs["artifact"], str) else json.dumps(obs["artifact"])
        if obs["needle"] in blob:
            return _supported("CANDIDATE", "naive", "the needle is present in the captured bytes.")
        return _refused("no-bug", "naive", "the needle is absent.")
    if kind == "artifact_envelope":
        if obs["needle"] in obs["raw"]:
            return _supported("CANDIDATE", "naive", "the needle is present in the artifact.")
        return _refused("no-bug", "naive", "the needle is absent.")
    if kind == "token_novelty":
        new_lines = "\n".join(obs.get("new_lines") or [])
        hit = [c for c in obs["claimed_new"] if c in new_lines]
        if hit:
            return _supported("CANDIDATE", "naive", f"{hit} appear in the newly added lines.")
        return _refused("no-bug", "naive", "no claimed identifier appears in a new line.")
    if kind == "run_lattice":
        executed = [
            a["name"]
            for a in obs["arms"]
            if a["outcome"] == Outcome.EXECUTED.value and a["role"] == Role.TEST.value
        ]
        if obs["claim"] == "clean-negative":
            if executed:
                return _refused("CANDIDATE", "naive", f"arms executed: {executed}.")
            return _supported("no-bug", "naive", "no test arm executed, so there is no bug here.")
        if executed:
            return _supported("CANDIDATE", "naive", f"arms executed: {executed}.")
        return _refused("no-bug", "naive", "no test arm executed.")
    if kind == "oracle_expressivity":
        marker = obs.get("treatment_observed", "")
        if obs["claim"] == "clean-negative":
            # The positive control's bytes are in ``obs`` and this branch does
            # not read them. That is the historical check and the reason four of
            # the seven "no bug" calls in the old headline existed. ``_fair``
            # reads them.
            if marker:
                return _refused("CANDIDATE", "naive", "the treatment arm produced the marker.")
            return _supported(
                "no-bug", "naive", "the oracle string never matched, so the behaviour is absent."
            )
        observed = (obs.get("positive_control") or {}).get("observed") or ""
        if marker or observed:
            return _supported("CANDIDATE", "naive", "the marker was seen.")
        return _refused("no-bug", "naive", "the marker was not seen.")
    if kind == "numeric_claim":
        # No predicate: the value is not consulted. Frozen as recorded.
        return _supported("CANDIDATE", "naive", "the metric was computed and reported as stated.")
    if kind == "text_measurement":
        raw: str = obs["raw"]
        width = int(obs["max_width"])
        lines = raw.split("\n")
        wrapped = [i for i, ln in enumerate(lines[:-1]) if len(ln) < width]
        if wrapped:
            return _supported("CANDIDATE", "naive", f"{len(wrapped)} short lines before a newline.")
        return _refused("no-bug", "naive", "no short lines.")
    raise ValueError(f"unknown observation kind {kind!r}")


# ------------------------------------------------- the fair comparison arm
#
# An external reviewer wrote this and it is the primary comparison arm, because
# the arm above cannot express the answer the headline is about. It is
# transcribed from ``fp_corpus/critic/run_critic.py:competent``; that file stays
# in the tree as the reviewer's own runnable artifact and
# ``tests/test_benchmark.py::test_the_fair_arm_matches_the_reviewers_own_baseline``
# pins the two to agreement on the reviewer's cases.
#
# Three licences the historical check is denied, and nothing more: look at your
# own positive control, look at the number you are reporting, and be allowed to
# say "I cannot tell". It has no echo normalisation, no refusal spans, no
# field-provenance logic, no independence check and no coverage check -- those
# are the gates, and they are what the comparison is *of*.
#
# Where a fixture was re-expressed so the gated arm had to derive a conclusion
# it used to read, this arm uses the same derivation helpers. Those helpers are
# parsers of raw records -- "was an application-layer status recorded", "is this
# stamp inside the run's window", "what is the product of the three largest
# factor cardinalities" -- not rules, and withholding them from the comparison
# arm would make the gates look better by deleting data rather than by deciding
# better.


def _fair(obs: dict) -> GateResult:
    kind = obs["kind"]

    if kind == "run_lattice":
        # An engineer who wrote a positive control looks at it.
        control = [a for a in obs["arms"] if a["role"] == Role.HONEST_CONTROL.value]
        liveness = [a for a in obs["arms"] if a["role"] == Role.LIVENESS.value]
        tests = _test_arms(obs)
        executed = [a["name"] for a in tests if a["outcome"] == Outcome.EXECUTED.value]
        if liveness and all(a["outcome"] != Outcome.EXECUTED.value for a in liveness):
            return GateResult("REFUSED", "VOID", "fair", "liveness never ran")
        if control and all(a["outcome"] != Outcome.REFUSED.value for a in control):
            return GateResult("REFUSED", "VOID", "fair", "the control did not behave")
        if not _reached_application_layer(obs):
            return GateResult("REFUSED", "VOID", "fair", "never reached the app layer")
        if obs["claim"] == "clean-negative":
            if executed:
                return GateResult("REFUSED", "CANDIDATE", "fair", f"arms ran: {executed}")
            return GateResult("SUPPORTED", "KILL", "fair", "silent, control behaved")
        if executed:
            return GateResult("SUPPORTED", "CANDIDATE", "fair", "an arm executed")
        return GateResult("REFUSED", "no-bug", "fair", "no arm executed")

    if kind == "oracle_expressivity":
        # One comparison: did the planted positive actually show up?
        pc = obs.get("positive_control") or {}
        if not pc or not pc.get("ran", False):
            return GateResult("REFUSED", "VOID", "fair", "no control, or it did not run")
        exp, got = str(pc.get("expected_observable", "")), str(pc.get("observed", ""))
        if exp and exp not in got:
            return GateResult("REFUSED", "VOID", "fair", "the planted positive did not show up")
        marker = obs.get("treatment_observed", "")
        if obs["claim"] == "clean-negative":
            if marker:
                return GateResult("REFUSED", "CANDIDATE", "fair", "the treatment fired")
            return GateResult("SUPPORTED", "KILL", "fair", "silent, control proved")
        if marker:
            return GateResult("SUPPORTED", "CANDIDATE", "fair", "the marker was seen")
        return GateResult("REFUSED", "no-bug", "fair", "no marker")

    if kind == "numeric_claim":
        # An engineer who reports a number has looked at the number.
        if obs["metric"] == "r2":
            v = float(obs["value"])
            if v < 0.0:
                return GateResult(
                    "REFUSED", "INCONCLUSIVE", "fair", f"r2={v} is worse than the mean"
                )
            return GateResult("SUPPORTED", "CANDIDATE", "fair", f"r2={v}")
        if int(obs.get("constraint_eval_errors", 0)):
            return GateResult("REFUSED", "INCONCLUSIVE", "fair", "the generator reported errors")
        if int(obs["rows"]) < _covering_array_lower_bound(obs):
            return GateResult(
                "REFUSED", "INCONCLUSIVE", "fair", "fewer rows than the feasible minimum"
            )
        return GateResult("SUPPORTED", "CANDIDATE", "fair", "rows meet the minimum")

    if kind == "http_differential":
        # An engineer who reads the status code before the body.
        arms = obs["arms"]
        if obs["claim"] == "disclosure":
            if all(not 200 <= a["response"]["status"] < 300 for a in arms):
                return GateResult("REFUSED", "KILL", "fair", "no 2xx: it was rejected")
            return GateResult("SUPPORTED", "CANDIDATE", "fair", "a 2xx carries the id")
        bodies = {a["label"]: json.dumps(a["response"].get("body"), sort_keys=True) for a in arms}
        if len(set(bodies.values())) > 1:
            return GateResult("SUPPORTED", "CANDIDATE", "fair", "the bodies differ")
        return GateResult("REFUSED", "no-bug", "fair", "identical")

    # Everything else: the historical check, unchanged. The reviewer drew the
    # line here and it is kept, because an arm that was extended case by case
    # until it lost would be the same defect in the other direction.
    return _naive(obs)


_GATED = {
    "http_differential": _gate_http_differential,
    "parsed_field": _gate_parsed_field,
    "artifact_envelope": _gate_artifact_envelope,
    "token_novelty": _gate_token_novelty,
    "run_lattice": _gate_run_lattice,
    "oracle_expressivity": _gate_oracle_expressivity,
    "numeric_claim": _gate_numeric_claim,
    "text_measurement": _gate_text_measurement,
}


def known_kinds() -> frozenset[str]:
    return frozenset(_GATED)


def adjudicate(
    observation: dict, *, gates_enabled: bool = True, arm: str | None = None
) -> GateResult:
    """Decide whether this observation supports its own claim.

    ``observation`` is the only input. No label, no shape id, no expected
    verdict is read from anywhere.

    ``arm`` selects one of :data:`ARMS`. ``gates_enabled`` is the older
    two-valued spelling and maps to ``"gated"`` / ``"naive"``; it is kept so
    that the external reviewer's own script keeps running unchanged.
    """
    kind = observation.get("kind")
    if kind not in _GATED:
        raise ValueError(f"unknown observation kind {kind!r}; known: {sorted(_GATED)}")
    if arm is None:
        arm = "gated" if gates_enabled else "naive"
    if arm == "gated":
        return _GATED[kind](observation)
    if arm == "fair":
        return _fair(observation)
    if arm == "naive":
        return _naive(observation)
    raise ValueError(f"unknown arm {arm!r}; known: {sorted(ARMS)}")
