"""The declarative plan: a probe you have to name the oracle of before firing.

*"If you cannot name the oracle before firing, you are fishing, not hunting."*
That sentence is the entire reason this format exists, and it is enforced by the
type rather than by a checklist: ``Plan`` takes ``oracle``, ``control`` and
``liveness`` as constructor arguments with **no defaults**, so a plan with no
named oracle, no honest control or no liveness arm cannot be constructed at all.
There is no override, no ``--force``, and no "skip the control" flag, because a
flag to skip the control is the only flag anybody would ever use.

The format is strict JSON. Unknown keys are refused rather than ignored, wrong
types are refused at load time, and every callable the plan names is resolved
**before any arm runs**, so a plan that cannot execute fails loudly and early
instead of halfway through a lattice.

A plan file is code. ``call`` names a dotted ``module:attribute`` path which
this module imports and invokes. Treat a plan file with exactly the trust you
would give a Python file, because that is what it is.

Numbered items are the wrong verdicts this design prevents. Each is a recorded
failure of the practice this implements:

  1  a probe fired with no oracle named          -> the hunt became a search for
     anything surprising, and the first surprising thing found was the rig's own
     echo. ``oracle`` is a required non-nullable field and its ``kind`` must
     clear the strength floor before a single arm is allowed to run.
  2  a negative with no positive control         -> a silent treatment beside a
     silent control is a VOID run, not a negative, and two runs were voided for
     lacking one. ``control`` and ``liveness`` are required non-nullable fields.
  3  an optional field that defaulted to passing -> a missing input must never
     be scored as a passing input. Nothing in this schema defaults to a value a
     gate would accept: the optional fields are prose, and the required ones
     raise when absent, blank or null.
  4  a lenient loader                            -> a mistyped key read as a
     default is the fail-open direction, and it fails late and confusingly. An
     unknown key is refused by name, at load time, with the known set printed.
  5  a plan half-executed                        -> an unimportable probe in arm
     three left arms one and two recorded and the run unusable, which looks
     exactly like a target that stopped answering. Every callable is resolved
     up front; an unresolvable one refuses the whole plan.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from controlarm.controls.run import Role, Run
from controlarm.gates.fp import ORACLE_STRENGTH, STRENGTH_FLOOR

__all__ = [
    "ARM_KEYS",
    "ORACLE_KEYS",
    "PLAN_KEYS",
    "ArmSpec",
    "OracleSpec",
    "Plan",
    "PlanError",
    "execute",
]


class PlanError(Exception):
    """Raised when a plan is malformed, under-specified, or unexecutable.

    One exception type for every way a plan can be refused, because every one
    of them is the same outcome from the caller's side: the gate read the plan
    and would not run it. The *reason* is what differs, and the reason is always
    in the message.
    """


#: The top-level keys. ``notes`` is the only optional one, and it is prose: no
#: gate consumes it, so it cannot default to something a gate would accept.
PLAN_KEYS = frozenset({"id", "subject", "oracle", "control", "liveness", "arms", "notes"})
_REQUIRED_PLAN_KEYS = ("id", "subject", "oracle", "control", "liveness", "arms")

ORACLE_KEYS = frozenset({"kind", "observable"})
ARM_KEYS = frozenset({"name", "call", "args", "expectation"})


@dataclass(frozen=True)
class OracleSpec:
    """The named oracle. Both fields are required and neither may be blank.

    ``kind`` is looked up in the strength table the false-positive gate
    enforces, so "admissible" means the same thing here as it does there. Two
    copies of that table would drift and the drift would be silent.

    ``observable`` is the parsed field the oracle reads. It is required because
    a kind on its own does not say what will be looked at, and "I will know it
    when I see it" is the interpretive judgement the strength table exists to
    keep out.
    """

    kind: str
    observable: str

    def __post_init__(self) -> None:
        for name in ("kind", "observable"):
            if not str(getattr(self, name) or "").strip():
                raise PlanError(
                    f"oracle.{name} is empty. If you cannot name the oracle before firing, "
                    "you are fishing, not hunting."
                )

    @property
    def strength(self) -> int | None:
        """``None`` when the kind is not in the table. Unscored, not unknown."""
        return ORACLE_STRENGTH.get(self.kind)

    @property
    def admissible(self) -> bool:
        strength = self.strength
        return strength is not None and strength >= STRENGTH_FLOOR

    def as_dict(self) -> dict:
        return {"kind": self.kind, "observable": self.observable, "strength": self.strength}


@dataclass(frozen=True)
class ArmSpec:
    """One arm: a name, a callable to invoke, and what it is expected to do."""

    name: str
    call: str
    args: Mapping[str, Any]
    expectation: str

    def __post_init__(self) -> None:
        for name in ("name", "call"):
            if not str(getattr(self, name) or "").strip():
                raise PlanError(f"arm {name!r} is empty")
        if ":" not in self.call:
            raise PlanError(
                f"arm {self.name!r}: call {self.call!r} is not a dotted path of the form "
                "'package.module:attribute'. A plan names the callable it fires; it does not "
                "describe it."
            )

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "call": self.call,
            "args": dict(self.args),
            "expectation": self.expectation,
        }


@dataclass(frozen=True)
class Plan:
    """A plan, validated.

    The five required fields are positional and have no defaults. Item 1 and
    item 2 live in that signature: ``Plan(id, subject)`` is a ``TypeError``, not
    a plan with an absent oracle, so no amount of later checking can be skipped
    because there is nothing to skip.

    The file format::

        {
          "id": "fetch-allowlist-backslash",
          "subject": "the fetch allowlist cannot be reached past",
          "notes": "free text; no gate reads this",
          "oracle":  {"kind": "parsed_field_diff",
                      "observable": "the host the fetcher actually reached"},
          "liveness": {"name": "LIVENESS",
                       "call": "examples.local_target.probes:route_works",
                       "args": {"url": "https://allowed.example/ok"}},
          "control":  {"name": "HONEST-CONTROL",
                       "call": "examples.local_target.probes:reached_off_list",
                       "args": {"url": "https://listener.invalid/c"}},
          "arms": [{"name": "off-list host behind a backslash authority",
                    "call": "examples.local_target.probes:reached_off_list",
                    "args": {"url": "https://allowed.example\\\\@listener.invalid/c"},
                    "expectation": "refused"}]
        }
    """

    id: str
    subject: str
    oracle: OracleSpec
    control: ArmSpec
    liveness: ArmSpec
    arms: tuple[ArmSpec, ...]
    notes: str = ""
    source: str = "<text>"

    def __post_init__(self) -> None:
        for name in ("id", "subject"):
            if not str(getattr(self, name) or "").strip():
                raise PlanError(f"plan {name!r} is empty")
        # Item 2, said in the type system and said again here: the constructor
        # cannot be reached without these, and None cannot sneak past a
        # dataclass with no validation.
        if not isinstance(self.oracle, OracleSpec):
            raise PlanError(
                "plan.oracle must be an OracleSpec. A plan with no named oracle is not a "
                "plan with a weak oracle; it is a plan that cannot be answered."
            )
        for name in ("control", "liveness"):
            if not isinstance(getattr(self, name), ArmSpec):
                raise PlanError(
                    f"plan.{name} must be an ArmSpec. A negative with no positive control is "
                    "uninterpretable: if the control never fired, you tested nothing."
                )

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_path(cls, path: str | Path) -> Plan:
        """Load one plan.

        An unreadable file raises ``OSError``, which the CLI maps to a **tool
        failure**, not to a refusal: being pointed at nothing is the instrument
        breaking. Everything the loader can actually read and then reject is a
        ``PlanError``, which the CLI maps to a refusal.
        """
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        return cls.from_text(text, source=str(p))

    @classmethod
    def from_text(cls, text: str, source: str = "<text>") -> Plan:
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise PlanError(f"{source}: not valid JSON ({exc})") from exc
        if not isinstance(raw, dict):
            raise PlanError(f"{source}: top level must be a JSON object, got {_kind(raw)}")

        unknown = sorted(set(raw) - PLAN_KEYS)
        if unknown:
            raise PlanError(
                f"{source}: unknown key(s) {unknown}. A mistyped key read as a default is the "
                f"fail-open direction. Known keys: {sorted(PLAN_KEYS)}"
            )
        missing = [k for k in _REQUIRED_PLAN_KEYS if k not in raw]
        if missing:
            raise PlanError(
                f"{source}: missing required key(s) {missing}. Nothing here defaults: a plan "
                "that omits its oracle, its control or its liveness arm is not a cautious "
                "plan, it is an unfinished one."
            )
        for k in _REQUIRED_PLAN_KEYS:
            if raw[k] is None:
                raise PlanError(
                    f"{source}: {k} is null. A missing input must never be scored as a "
                    "passing input, so null is refused rather than defaulted."
                )

        return cls(
            id=_text(raw["id"], "id", source),
            subject=_text(raw["subject"], "subject", source),
            oracle=_oracle(raw["oracle"], source),
            control=_arm(raw["control"], "control", source, default_expectation="refused"),
            liveness=_arm(raw["liveness"], "liveness", source, default_expectation="executes"),
            arms=_arms(raw["arms"], source),
            notes=_text(raw.get("notes", ""), "notes", source, allow_empty=True),
            source=source,
        )

    # ------------------------------------------------------------------ records

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "subject": self.subject,
            "notes": self.notes,
            "source": self.source,
            "oracle": self.oracle.as_dict(),
            "liveness": self.liveness.as_dict(),
            "control": self.control.as_dict(),
            "arms": [a.as_dict() for a in self.arms],
        }


# ----------------------------------------------------------------- execution


def execute(plan: Plan, *, resolver: Callable[[str], Callable[..., Any]] | None = None) -> Run:
    """Resolve every callable, then run the lattice.

    Item 5: resolution happens for *all* arms before the first one fires, so a
    typo in the last arm refuses the plan rather than producing a half-run whose
    silence is indistinguishable from a target that stopped answering.

    Item 1: the oracle's admissibility is checked here too, before anything is
    fired, because an inadmissible oracle makes every arm's result unreadable
    and firing the arms anyway spends the budget to learn nothing.
    """
    if not plan.oracle.admissible:
        strength = plan.oracle.strength
        if strength is None:
            raise PlanError(
                f"oracle kind {plan.oracle.kind!r} is not in the strength table, so it is "
                f"unscored -- which is refused, not treated as unknown. Known kinds: "
                f"{sorted(ORACLE_STRENGTH)}"
            )
        raise PlanError(
            f"oracle {plan.oracle.kind!r} is strength {strength}, below the floor of "
            f"{STRENGTH_FLOOR}. Nothing below the floor reaches the operator: it is what "
            "stops probe volume from becoming noise."
        )

    resolve = resolver or _resolve
    bound = [(spec, resolve(spec.call)) for spec in (plan.liveness, plan.control, *plan.arms)]

    run = Run(plan.subject)
    liveness_spec, liveness_fn = bound[0]
    control_spec, control_fn = bound[1]
    run.liveness(_thunk(liveness_fn, liveness_spec.args), name=liveness_spec.name)
    run.honest_control(_thunk(control_fn, control_spec.args), name=control_spec.name)
    for spec, fn in bound[2:]:
        run.arm(spec.name, _thunk(fn, spec.args), expectation=spec.expectation, role=Role.TEST)
    return run


def _thunk(fn: Callable[..., Any], args: Mapping[str, Any]) -> Callable[[], Any]:
    kwargs = dict(args)
    return lambda: fn(**kwargs)


def _resolve(path: str) -> Callable[..., Any]:
    """Import ``module:attribute``.

    The current working directory is prepended to ``sys.path`` so a plan can
    name a probe that lives beside it in a checkout rather than only one that
    has been installed. That is a deliberate widening and it is documented in
    ``docs/cli.md``: a plan file is code, and this is how it gets reached.
    """
    module_name, _, attr = path.partition(":")
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise PlanError(
            f"call {path!r}: could not import {module_name!r} ({type(exc).__name__}: {exc}). "
            "Resolution happens before any arm runs, so nothing was fired."
        ) from exc
    try:
        fn = getattr(module, attr)
    except AttributeError as exc:
        raise PlanError(f"call {path!r}: {module_name!r} has no attribute {attr!r}") from exc
    if not callable(fn):
        raise PlanError(f"call {path!r}: {attr!r} is a {_kind(fn)}, not a callable")
    return fn


# ---------------------------------------------------------------- schema helpers


def _kind(value: Any) -> str:
    return type(value).__name__


def _text(value: Any, key: str, source: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise PlanError(f"{source}: {key} must be a string, got {_kind(value)}")
    if not allow_empty and not value.strip():
        raise PlanError(f"{source}: {key} is empty")
    return value


def _oracle(value: Any, source: str) -> OracleSpec:
    if not isinstance(value, dict):
        raise PlanError(f"{source}: oracle must be an object, got {_kind(value)}")
    unknown = sorted(set(value) - ORACLE_KEYS)
    if unknown:
        raise PlanError(f"{source}: oracle has unknown key(s) {unknown}")
    missing = sorted(ORACLE_KEYS - set(value))
    if missing:
        raise PlanError(
            f"{source}: oracle is missing {missing}. Both halves are required: the kind says "
            "how strong the oracle is and the observable says what it reads."
        )
    return OracleSpec(
        kind=_text(value["kind"], "oracle.kind", source),
        observable=_text(value["observable"], "oracle.observable", source),
    )


def _arm(value: Any, key: str, source: str, *, default_expectation: str) -> ArmSpec:
    if not isinstance(value, dict):
        raise PlanError(f"{source}: {key} must be an object, got {_kind(value)}")
    unknown = sorted(set(value) - ARM_KEYS)
    if unknown:
        raise PlanError(f"{source}: {key} has unknown key(s) {unknown}")
    for required in ("name", "call"):
        if required not in value:
            raise PlanError(f"{source}: {key} is missing required key {required!r}")
    args = value.get("args", {})
    if not isinstance(args, dict):
        raise PlanError(f"{source}: {key}.args must be an object, got {_kind(args)}")
    return ArmSpec(
        name=_text(value["name"], f"{key}.name", source),
        call=_text(value["call"], f"{key}.call", source),
        args=dict(args),
        expectation=_text(
            value.get("expectation", default_expectation),
            f"{key}.expectation",
            source,
        ),
    )


def _arms(value: Any, source: str) -> tuple[ArmSpec, ...]:
    if not isinstance(value, list):
        raise PlanError(f"{source}: arms must be a list, got {_kind(value)}")
    return tuple(
        _arm(item, f"arms[{i}]", source, default_expectation="refused")
        for i, item in enumerate(value)
    )
