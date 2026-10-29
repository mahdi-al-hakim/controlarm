"""Execute the probes and adjudicate each run under every configuration.

The harness is used here exactly as a user would use it: a :class:`Run`, a
``liveness`` arm, an ``honest_control`` arm, and one test ``arm``. Nothing about
the lattice is reimplemented, and nothing about the verdict is decided here.

The three configurations
------------------------
``gated``
    ``gates.adjudicate(arm="gated")`` -- the full control lattice. The thing
    being measured.

``fair``
    The competent baseline. The callable is
    ``benchmarks/fp_corpus/critic/run_critic.py:competent`` **itself**, the
    external reviewer's own code, rather than a reimplementation: a baseline
    written by the party being measured is not a baseline. ``gates._fair`` is a
    transcription of the same function, so this module runs both and records
    whether they agreed. A disagreement would be a finding about the repository,
    not a detail, so it is reported rather than resolved silently.

``naive``
    The historical check, kept only as provenance. It cannot emit a refusal
    verdict at all, so its score on any case whose correct answer is a refusal
    is fixed before the probe runs. It is **not** a comparison and the headline
    does not use it.

How a run becomes an observation
--------------------------------
``claim="clean-negative"`` is the right framing for this study: the question is
whether a configuration will endorse the proposition "this probe found nothing".
Under that claim a lattice verdict of ``KILL`` is an endorsement -- the
configuration has said "no bug" -- and that is the answer ground truth can
convict.

``reached_application_layer`` is **derived**, not declared, by the same
``gates._reached_application_layer`` helper the gated arm uses, from the probe's
own record of whether the target's code was actually entered. It is passed
explicitly only because the reviewer's frozen ``competent`` reads that field
rather than deriving it. Handing it a declared conclusion would have rigged the
comparison in the gates' favour, so it is handed a derivation instead.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks import gates
from benchmarks.fp_corpus.critic.run_critic import competent
from benchmarks.scoring import classify_result
from controlarm.controls.run import Outcome, Run

from . import acquire
from .breakage import BreakageMode, by_name
from .targets import Target

__all__ = [
    "CONFIGS",
    "SENSITIVITY",
    "ProbeRun",
    "adjudicate_record",
    "execute",
    "observation_for",
    "readjudicate",
]

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DRIVER = HERE / "_driver.py"

#: ``gated`` is measured, ``fair`` is the comparison, ``naive`` is provenance.
CONFIGS = ("gated", "fair", "naive")

#: A **sensitivity analysis, not a comparison arm.** The primary result below is
#: null: the gated lattice and the fair baseline agree everywhere. That null is
#: only interpretable once you know *why*, and the why is a single record.
#:
#: The fair baseline refuses a broken rig because it is given the derived answer
#: to "did the treatment arm reach the target at all". Withholding that would
#: have made the gates look better by deleting data rather than by deciding
#: better, which is why the primary comparison does not withhold it.
#:
#: But plenty of real harnesses never record it. This arm is the same reviewer
#: callable run against an observation with that record removed, and it answers
#: a different and narrower question: how much of the lattice's value is
#: carried by the reachability record alone? It is reported in its own section,
#: it is labelled, and it is never averaged into the headline.
SENSITIVITY = ("fair_no_reachability",)

#: The fixed instant the observation's run window is built around. The verdict
#: must not depend on when the study was run, and ``tests/test_clock.py``'s rule
#: for the package applies here by choice: a result a test cannot pin is not a
#: result. The stale-control breakage mode moves the control's stamp relative to
#: this window rather than waiting for real time to pass.
EPOCH = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@dataclass
class ProbeRun:
    """One (CVE, version, breakage) execution and what every configuration said."""

    cve: str
    package: str
    version: str
    phase: str
    breakage: str
    verdict: str
    verdict_reason: str
    arms: list[dict]
    predictions: dict[str, str] = field(default_factory=dict)
    verdicts: dict[str, str] = field(default_factory=dict)
    rules: dict[str, str] = field(default_factory=dict)
    fair_agrees_with_reviewer: bool = True
    exploit_reached_target: bool = False

    @property
    def key(self) -> str:
        return f"{self.cve}|{self.phase}|{self.breakage}"

    def as_dict(self) -> dict:
        return {
            "cve": self.cve,
            "package": self.package,
            "version": self.version,
            "phase": self.phase,
            "breakage": self.breakage,
            "lattice_verdict": self.verdict,
            "lattice_reason": self.verdict_reason,
            "exploit_reached_target": self.exploit_reached_target,
            "predictions": self.predictions,
            "verdicts": self.verdicts,
            "rules": self.rules,
            "fair_agrees_with_reviewer": self.fair_agrees_with_reviewer,
            "arms": self.arms,
        }


def _run_driver(target: Target, version: str, mode: BreakageMode | None) -> dict:
    """Run the probe once in its own interpreter and return the arm report."""
    workdir = Path(tempfile.mkdtemp(prefix="cve-study-"))
    (workdir / "rig-ready").write_text("rig scratch marker\n", encoding="utf-8")
    config = {
        "repo_root": str(REPO_ROOT),
        "support_dir": str(acquire.support_dir()),
        "pin_dir": str(acquire.pin_dir(target.package, version)),
        "probe": target.probe,
        "package": target.package,
        "version": version,
        "workdir": str(workdir),
        "action": mode.action if mode else None,
    }
    executable = sys.executable
    if mode is not None and mode.action == "spawn_fails":
        executable = str(workdir / "python-that-does-not-exist")
    try:
        try:
            proc = subprocess.run(
                [executable, str(DRIVER), json.dumps(config)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except OSError as exc:
            detail = f"<exception {type(exc).__name__}: {exc}>"
            return {
                "arms": {a: [False, detail] for a in ("liveness", "control", "exploit")},
                "exploit_reached_target": False,
            }
        line = proc.stdout.strip().splitlines()
        if proc.returncode != 0 or not line:
            detail = (
                f"<probe process exited {proc.returncode} without reporting; "
                f"stderr={proc.stderr.strip()[-300:] or 'empty'}>"
            )
            return {
                "arms": {a: [False, detail] for a in ("liveness", "control", "exploit")},
                "exploit_reached_target": False,
            }
        return json.loads(line[-1])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def observation_for(run: Run, record: dict, mode: BreakageMode | None) -> dict:
    """Turn a finished :class:`Run` into the ``run_lattice`` observation."""
    verdict_record = run.verdict(now=EPOCH)
    control_stamp = EPOCH
    if mode is not None and mode.action == "stamp_control_before_window":
        control_stamp = EPOCH - timedelta(days=5)

    arms: list[dict] = []
    for arm in verdict_record["arms"]:
        entry = {
            "name": arm["name"],
            "role": arm["role"],
            "outcome": arm["outcome"],
            "detail": arm["detail"],
            "reason": arm["reason"],
        }
        if arm["role"] == "honest-control":
            entry["recorded_at"] = control_stamp.isoformat()
        if arm["role"] == "test":
            # The transport record the gate derives reachability from: whether
            # the target's own code was entered at all. A rig precondition that
            # failed first means there was no exchange to be absent.
            entry["probe_record"] = {
                "app_layer_status": "entered" if record["exploit_reached_target"] else None
            }
        arms.append(entry)

    observation = {
        "kind": "run_lattice",
        "title": verdict_record["title"],
        "claim": "clean-negative",
        "arms": arms,
        "results_artifact": True,
        "run_window": {
            "started": (EPOCH - timedelta(minutes=5)).isoformat(),
            "ended": (EPOCH + timedelta(minutes=5)).isoformat(),
        },
    }
    # Derived with the gates' own helper, then handed to the reviewer's frozen
    # baseline, which reads the field rather than deriving it. See the module
    # docstring: a declared conclusion here would have rigged the comparison.
    observation["reached_application_layer"] = gates._reached_application_layer(observation)
    return observation


def adjudicate_record(
    *,
    cve: str,
    package: str,
    version: str,
    phase: str,
    mode: BreakageMode | None,
    arm_results: dict,
    exploit_reached_target: bool,
) -> ProbeRun:
    """Everything one run becomes once its probe has reported. No subprocess.

    Split out of :func:`execute` on purpose. The probe's three
    ``(executed, detail)`` reports and whether the exploit reached the target
    are the whole of what running the probe produces; *every number this study
    publishes* is derived from them here -- the failure classification, the
    lattice verdict and its reason, and what each of the four configurations
    said. That split is what lets :func:`readjudicate` regenerate the committed
    results from the committed arm reports in an environment that does not have
    the fixture cache, which is the only environment CI has. See ``GAPS.md`` G7.
    """
    label = mode.name if mode else "none"
    run = Run(f"{cve}: {package} {version} ({phase}, breakage={label})")
    run.liveness(lambda: tuple(arm_results["liveness"]), name="LIVENESS: pinned version works")
    run.honest_control(
        lambda: tuple(arm_results["control"]),
        name="HONEST-CONTROL: oracle silent on benign input",
    )
    run.arm(f"ORACLE: {cve}", lambda: tuple(arm_results["exploit"]))

    verdict, why = run.decide()
    observation = observation_for(run, {"exploit_reached_target": exploit_reached_target}, mode)

    predictions: dict[str, str] = {}
    verdicts: dict[str, str] = {}
    rules: dict[str, str] = {}
    for config in CONFIGS:
        result = gates.adjudicate(observation, arm=config)
        predictions[config] = classify_result(result.decision, result.verdict)
        verdicts[config] = result.verdict
        rules[config] = result.rule

    reviewer = competent(observation)
    reviewer_class = classify_result(reviewer.decision, reviewer.verdict)
    agrees = reviewer_class == predictions["fair"]

    # The sensitivity arm: the same reviewer callable, denied only the record of
    # whether the treatment arm reached the target.
    blinded = dict(observation)
    blinded.pop("reached_application_layer", None)
    blinded["arms"] = [
        {k: v for k, v in arm.items() if k != "probe_record"} for arm in observation["arms"]
    ]
    blind = competent(blinded)
    predictions["fair_no_reachability"] = classify_result(blind.decision, blind.verdict)
    verdicts["fair_no_reachability"] = blind.verdict
    rules["fair_no_reachability"] = "sensitivity"

    return ProbeRun(
        cve=cve,
        package=package,
        version=version,
        phase=phase,
        breakage=label,
        verdict=verdict.value,
        verdict_reason=why,
        arms=observation["arms"],
        predictions=predictions,
        verdicts=verdicts,
        rules=rules,
        fair_agrees_with_reviewer=agrees,
        exploit_reached_target=bool(exploit_reached_target),
    )


def execute(target: Target, version: str, phase: str, mode: BreakageMode | None) -> ProbeRun:
    """Run one probe and adjudicate it under every configuration."""
    record = _run_driver(target, version, mode)
    return adjudicate_record(
        cve=target.cve,
        package=target.package,
        version=version,
        phase=phase,
        mode=mode,
        arm_results=record["arms"],
        exploit_reached_target=bool(record["exploit_reached_target"]),
    )


#: Arm role, as the committed observation records it, back to the key the probe
#: driver reports that arm under. :func:`readjudicate` inverts the recording.
_ROLE_TO_PROBE_KEY = {"liveness": "liveness", "honest-control": "control", "test": "exploit"}


def readjudicate(committed: dict) -> ProbeRun:
    """Re-derive one committed run from the arm reports committed beside it.

    The committed record is read only for the three ``(executed, detail)``
    reports the probe produced and for whether the exploit reached the target.
    Those four facts are what executing the probe against the pinned
    distribution establishes, and reproducing them needs the 187MB gitignored
    fixture cache. Everything else in the committed record -- the per-arm
    failure classification, ``lattice_verdict``, ``lattice_reason``,
    ``predictions``, ``verdicts``, ``rules`` and
    ``fair_agrees_with_reviewer`` -- is recomputed here by the live code, so a
    committed result that no longer matches what the code produces fails rather
    than agreeing with itself.
    """
    arm_results: dict[str, list] = {}
    for arm in committed["arms"]:
        key = _ROLE_TO_PROBE_KEY.get(arm["role"])
        if key is None:
            raise KeyError(
                f"{committed['cve']} has a committed arm with role {arm['role']!r}, which no "
                "probe reports under any key, so the run cannot be re-derived"
            )
        arm_results[key] = [arm["outcome"] == Outcome.EXECUTED.value, arm["detail"]]
    missing = sorted(set(_ROLE_TO_PROBE_KEY.values()) - set(arm_results))
    if missing:
        raise KeyError(f"{committed['cve']} commits no arm report for {missing}")
    breakage = committed["breakage"]
    return adjudicate_record(
        cve=committed["cve"],
        package=committed["package"],
        version=committed["version"],
        phase=committed["phase"],
        mode=None if breakage == "none" else by_name(breakage),
        arm_results=arm_results,
        exploit_reached_target=bool(committed["exploit_reached_target"]),
    )
