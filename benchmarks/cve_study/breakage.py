"""Seeded rig breakage, applied to the pre-fix version where the bug is really there.

This is the arm that makes the study bite. On a pre-fix pin the vulnerability is
present by the vendor's own account, so a configuration that answers "no bug"
is **wrong**, and it is wrong for a reason that has nothing to do with the
target: its own instrument failed. Ground truth here is not a judgement call.

Every probe runs behind three rig preconditions, because a real harness has
them: a scratch directory it can write to, a helper process it can start, and a
service token it can present. In an unbroken run all three pass and cost
nothing. Each breakage mode breaks exactly one thing, so the mode name is also
the diagnosis.

Real versus injected, and why the distinction is the honest half
---------------------------------------------------------------
``realism="real"``
    The failure is produced by actually breaking the rig, and the text the
    classifier sees is written by CPython or the operating system. Nobody chose
    those words to match a pattern table, so these modes can embarrass the
    gates, and :mod:`benchmarks.cve_study.score` reports them as the defensible
    headline.

``realism="injected"``
    There is no external service here to genuinely break -- every probe is
    deliberately network-free -- so the failure is injected at the boundary as
    the response such a service would return. The wording is therefore *chosen*,
    and a confound table authored in this repository being good at recognising
    strings also authored in this repository is close to circular. These modes
    are measured and published, and they are reported separately from the real
    ones rather than averaged into them.

Scope
-----
``scope="rig"``
    The whole run is broken, liveness included. Both configurations ought to
    refuse, and a configuration that does not is badly wrong.
``scope="exploit"``
    Liveness and the honest control both still pass, and only the arm that
    would have found the bug fails. This is the case an unguarded harness
    reports as a clean negative, and it is the one worth measuring.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["MODES", "BreakageMode", "by_name", "injected_modes", "real_modes"]


@dataclass(frozen=True)
class BreakageMode:
    name: str
    scope: str
    realism: str
    description: str
    #: What the rig precondition does when this mode is active. Interpreted by
    #: the probe driver; see ``runner._DRIVER``.
    action: str


MODES: tuple[BreakageMode, ...] = (
    BreakageMode(
        name="interpreter_missing",
        scope="rig",
        realism="real",
        description=(
            "the probe runner is pointed at an interpreter that does not exist, so no arm "
            "runs at all. The text comes from the operating system's failure to spawn."
        ),
        action="spawn_fails",
    ),
    BreakageMode(
        name="target_package_absent",
        scope="rig",
        realism="real",
        description=(
            "the pinned distribution is not on the path, so importing the target raises. "
            "This is the shape of a half-finished environment build."
        ),
        action="omit_pin_from_path",
    ),
    BreakageMode(
        name="probe_process_killed",
        scope="rig",
        realism="real",
        description=(
            "the probe process exits before it reports anything, the way an out-of-memory "
            "kill or a crashed worker would leave it."
        ),
        action="exit_before_reporting",
    ),
    BreakageMode(
        name="scratch_dir_deleted",
        scope="exploit",
        realism="real",
        description=(
            "the rig's scratch directory is removed after the controls pass and before the "
            "exploit arm, so the arm's precondition check raises a real OSError."
        ),
        action="delete_scratch",
    ),
    BreakageMode(
        name="helper_binary_absent",
        scope="exploit",
        realism="real",
        description=(
            "the helper process the exploit step starts is not installed, so starting it "
            "raises. The text comes from the operating system's loader."
        ),
        action="helper_missing",
    ),
    BreakageMode(
        name="expired_credential",
        scope="exploit",
        realism="injected",
        description=(
            "the service the exploit step authenticates against answers 401 with an expired "
            "token. Injected: there is no real service here to expire a token."
        ),
        action="auth_401",
    ),
    BreakageMode(
        name="rate_limited",
        scope="exploit",
        realism="injected",
        description=(
            "the service answers 429 before the exploit arm reaches the target. Injected, "
            "for the same reason as the credential mode."
        ),
        action="auth_429",
    ),
    BreakageMode(
        name="stale_positive_control",
        scope="control-record",
        realism="injected",
        description=(
            "the honest control's record is stamped outside this run's own window, so the "
            "control that is being relied on belongs to an earlier run. Produced by "
            "stamping the record, not by waiting, which is why it is marked injected."
        ),
        action="stamp_control_before_window",
    ),
)


def by_name(name: str) -> BreakageMode:
    for mode in MODES:
        if mode.name == name:
            return mode
    raise KeyError(name)


def real_modes() -> tuple[BreakageMode, ...]:
    return tuple(m for m in MODES if m.realism == "real")


def injected_modes() -> tuple[BreakageMode, ...]:
    return tuple(m for m in MODES if m.realism == "injected")
