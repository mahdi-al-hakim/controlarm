"""Turn the probe runs into the measurement, with ground truth fixed externally.

Ground truth here is not a label anyone in this repository wrote:

* **pre-fix, rig intact.** The vendor shipped a fix, so the vulnerability is
  present. ``FINDING`` is correct, ``NO_BUG`` is a **false negative**, and a
  refusal is neither -- it is the configuration declining to answer, which is
  counted as its own class and never folded into either error.
* **post-fix, rig intact.** The vendor's fix is in. ``NO_BUG`` is correct,
  ``FINDING`` is a **false positive**, a refusal is again its own class.
* **pre-fix, rig broken.** The bug is still there, so ``NO_BUG`` is **wrong**.
  ``FINDING`` is unobtainable, because the arm that would have found it never
  reached the target. The only defensible answer is a refusal, so the number
  that matters is how often each configuration says "no bug" anyway.

Three classes, never two. A study that scored refusals as negatives would be
measuring the thing this repository exists to argue against.

The ``naive`` arm is tabulated and is **not** a comparison: it cannot emit a
refusal verdict at all, so its score wherever the correct answer is a refusal is
fixed before any probe runs. It is the provenance of the idea, kept visible for
that reason and excluded from every headline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .breakage import by_name
from .runner import CONFIGS, SENSITIVITY, ProbeRun
from .stats import Rate, fisher_two_sided, rate

__all__ = ["Measurement", "measure"]

#: The three predicted classes, from ``benchmarks.scoring.CLASSES``.
FINDING, NO_BUG, REFUSED = "FINDING", "NO_BUG", "UNINTERPRETABLE"


@dataclass(frozen=True)
class Measurement:
    data: dict

    def as_dict(self) -> dict:
        return self.data


def _tally(runs: list[ProbeRun], config: str) -> Counter:
    return Counter(run.predictions[config] for run in runs)


def _block(runs: list[ProbeRun], config: str, wrong: str) -> dict:
    """Counts for one configuration over one set, with ``wrong`` as the error."""
    tally = _tally(runs, config)
    total = len(runs)
    return {
        "n": total,
        "finding": tally[FINDING],
        "no_bug": tally[NO_BUG],
        "refused": tally[REFUSED],
        "error_class": wrong,
        "error_rate": rate(tally[wrong], total).as_dict(),
    }


def _fisher(runs: list[ProbeRun], wrong: str, left: str, right: str) -> dict:
    """Two-by-two on ``wrong`` versus everything else, for two configurations."""
    a = sum(1 for r in runs if r.predictions[left] == wrong)
    b = len(runs) - a
    c = sum(1 for r in runs if r.predictions[right] == wrong)
    d = len(runs) - c
    return {
        "table": {f"{left}_wrong": a, f"{left}_other": b, f"{right}_wrong": c, f"{right}_other": d},
        "p_two_sided": fisher_two_sided(a, b, c, d),
    }


def _by_mode(runs: list[ProbeRun]) -> dict:
    out: dict = {}
    for mode_name in sorted({r.breakage for r in runs}):
        subset = [r for r in runs if r.breakage == mode_name]
        mode = by_name(mode_name)
        out[mode_name] = {
            "scope": mode.scope,
            "realism": mode.realism,
            "description": mode.description,
            "n_per_config": len(subset),
            "configs": {c: _block(subset, c, NO_BUG) for c in (*CONFIGS, *SENSITIVITY)},
        }
    return out


def measure(runs: list[ProbeRun]) -> Measurement:
    clean_pre = [r for r in runs if r.phase == "pre" and r.breakage == "none"]
    clean_post = [r for r in runs if r.phase == "post" and r.breakage == "none"]
    broken = [r for r in runs if r.breakage != "none"]
    broken_real = [r for r in broken if by_name(r.breakage).realism == "real"]
    broken_injected = [r for r in broken if by_name(r.breakage).realism == "injected"]
    broken_exploit_only = [
        r for r in broken if by_name(r.breakage).scope in ("exploit", "control-record")
    ]

    data: dict = {
        "cves_reached": len({r.cve for r in clean_pre}),
        "runs_total": len(runs),
        "fair_disagreements_with_reviewer_baseline": [
            r.key for r in runs if not r.fair_agrees_with_reviewer
        ],
        "prefix_clean": {
            "ground_truth": "the vulnerability is present; NO_BUG is a false negative",
            "n": len(clean_pre),
            "configs": {c: _block(clean_pre, c, NO_BUG) for c in CONFIGS},
            "fisher_gated_vs_fair": _fisher(clean_pre, NO_BUG, "gated", "fair"),
        },
        "postfix_clean": {
            "ground_truth": "the fix is in; FINDING is a false positive",
            "n": len(clean_post),
            "configs": {c: _block(clean_post, c, FINDING) for c in CONFIGS},
            "fisher_gated_vs_fair": _fisher(clean_post, FINDING, "gated", "fair"),
        },
        "sensitivity_fair_without_reachability": {
            "note": (
                "NOT a comparison arm. The same reviewer callable, denied only the derived "
                "record of whether the treatment arm reached the target. It answers how much "
                "of the lattice's value that one record carries, and it is never averaged "
                "into any headline."
            ),
            "prefix_clean": {c: _block(clean_pre, c, NO_BUG) for c in SENSITIVITY},
            "postfix_clean": {c: _block(clean_post, c, FINDING) for c in SENSITIVITY},
            "seeded_breakage_all": {c: _block(broken, c, NO_BUG) for c in SENSITIVITY},
            "seeded_breakage_real_modes": {c: _block(broken_real, c, NO_BUG) for c in SENSITIVITY},
            "fisher_gated_vs_fair_no_reachability_on_breakage": _fisher(
                broken, NO_BUG, "gated", "fair_no_reachability"
            ),
            "fisher_gated_vs_fair_no_reachability_on_real_breakage": _fisher(
                broken_real, NO_BUG, "gated", "fair_no_reachability"
            ),
        },
        "seeded_breakage": {
            "ground_truth": (
                "pre-fix under a broken rig: the bug is present, so NO_BUG is wrong and a "
                "refusal is the only defensible answer"
            ),
            "all": {
                "n": len(broken),
                "configs": {c: _block(broken, c, NO_BUG) for c in CONFIGS},
                "fisher_gated_vs_fair": _fisher(broken, NO_BUG, "gated", "fair"),
            },
            "real_modes_only": {
                "note": (
                    "the headline for this arm. The failure text is written by CPython or the "
                    "operating system, so no wording in this repository decided the outcome."
                ),
                "n": len(broken_real),
                "configs": {c: _block(broken_real, c, NO_BUG) for c in CONFIGS},
                "fisher_gated_vs_fair": _fisher(broken_real, NO_BUG, "gated", "fair"),
            },
            "injected_modes_only": {
                "note": (
                    "reported separately and NOT averaged into the headline: the failure text "
                    "is chosen in this repository, and a confound table authored here "
                    "recognising strings authored here is close to circular."
                ),
                "n": len(broken_injected),
                "configs": {c: _block(broken_injected, c, NO_BUG) for c in CONFIGS},
                "fisher_gated_vs_fair": _fisher(broken_injected, NO_BUG, "gated", "fair"),
            },
            "controls_intact_only": {
                "note": (
                    "the case that matters operationally: liveness and the honest control both "
                    "pass and only the arm that would have found the bug fails."
                ),
                "n": len(broken_exploit_only),
                "configs": {c: _block(broken_exploit_only, c, NO_BUG) for c in CONFIGS},
                "fisher_gated_vs_fair": _fisher(broken_exploit_only, NO_BUG, "gated", "fair"),
            },
            "by_mode": _by_mode(broken),
        },
    }
    return Measurement(data)


def format_rate(payload: dict) -> str:
    """``3/11 = 0.27 [0.06, 0.61]`` from a serialised :class:`Rate`."""
    return str(
        Rate(
            payload["successes"],
            payload["total"],
            payload["ci95"][0],
            payload["ci95"][1],
        )
    )
