"""Run the CVE study, or check that the committed numbers still reproduce.

    python benchmarks/cve_study/run_study.py --acquire   # fetch the pins (network)
    python benchmarks/cve_study/run_study.py             # measure and write results/
    python benchmarks/cve_study/run_study.py --check     # recompute and diff

``--acquire`` is the only step that needs the network. ``--check`` is offline and
exits non-zero if any committed number moved, which is what makes the results
file evidence rather than decoration.

``--check`` is **not** run by CI, and this docstring used to say it was.
:func:`collect` refuses to measure against pins whose bytes it has not verified,
and those bytes are the 187MB gitignored ``benchmarks/cve_study/.cache/``. What
CI runs instead is ``tests/test_cve_study.py``, which re-derives every committed
run from the probe reports committed beside it and asserts the published
measurement comes out of them -- everything but the probe execution. ``GAPS.md``
G14 states what that leaves unpinned and how to close it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from benchmarks.cve_study import acquire  # noqa: E402
from benchmarks.cve_study.breakage import MODES  # noqa: E402
from benchmarks.cve_study.runner import CONFIGS, SENSITIVITY, execute  # noqa: E402
from benchmarks.cve_study.score import format_rate, measure  # noqa: E402
from benchmarks.cve_study.targets import (  # noqa: E402
    REACHED,
    TARGETS,
    support_requirements,
)

RESULTS = Path(__file__).resolve().parent / "results"
JSON_PATH = RESULTS / "cve_study.json"
MD_PATH = RESULTS / "cve_study.md"


# --------------------------------------------------------------------- acquire


def do_acquire() -> int:
    print(f"support libraries (unpinned scaffolding): {support_requirements()}")
    acquire.ensure_support(support_requirements())
    for target in REACHED:
        for package, version in target.pins:
            entry = acquire.acquire(package, version, sdist_subtree=target.sdist_subtree)
            print(f"  {package}=={version}  sha256={entry['sha256'][:16]}  {entry['installed_by']}")
    print(f"\nlock written to {acquire.LOCKFILE}")
    return 0


# ----------------------------------------------------------------------- run


def collect() -> list:
    """Every (CVE, version, breakage) run the study is made of."""
    missing = [k for k, v in acquire.verify_lock().items() if v in ("absent", "unlocked")]
    if missing:
        raise SystemExit(
            f"{len(missing)} pinned artefact(s) are not in the cache: {missing[:4]}...\n"
            "Run with --acquire first. The study refuses to measure against pins whose "
            "bytes it has not verified."
        )
    runs = []
    total = len(REACHED) * (2 + len(MODES))
    done = 0
    for target in REACHED:
        for phase, version in (("pre", target.pre), ("post", target.post)):
            runs.append(execute(target, version, phase, None))
            done += 1
        # Seeded breakage is applied to the PRE-fix pin only: that is where
        # ground truth is unambiguous, because the bug is really there.
        for mode in MODES:
            runs.append(execute(target, target.pre, "pre", mode))
            done += 1
        print(f"  {target.cve:16s} {done}/{total} runs", file=sys.stderr)
    return runs


def build_payload(runs: list) -> dict:
    measurement = measure(runs)
    return {
        "study": "known-fixed public CVEs, pre-fix and post-fix",
        "ground_truth": (
            "the vendor's released fix, not a label written in this repository. See "
            "SELECTION_RULE.md for what was eligible and docs/cve-study.md for the design."
        ),
        "configurations": {
            "gated": "the full control lattice (benchmarks/gates.py, arm='gated')",
            "fair": (
                "the competent baseline; the callable is the external reviewer's own "
                "fp_corpus/critic/run_critic.py:competent, cross-checked against gates._fair"
            ),
            "naive": (
                "the historical check. Provenance, NOT a comparison: it cannot emit a refusal "
                "verdict at all, so its score wherever the answer is a refusal is fixed before "
                "any probe runs."
            ),
        },
        "selection": {
            "targets_considered": len(TARGETS),
            "reached": len(REACHED),
            "unreached": [t.cve for t in TARGETS if t.status == "UNREACHED"],
            "rejected": [t.cve for t in TARGETS if t.status == "REJECTED"],
        },
        "targets": [
            {
                "cve": t.cve,
                "package": t.package,
                "pre": t.pre,
                "post": t.post,
                "class": t.vuln_class,
                "status": t.status,
                "advisory_url": t.advisory_url,
                "fix_release_url": t.fix_release_url,
                "fix_evidence": t.fix_evidence,
                "oracle": t.oracle,
                "reachability": t.reachability,
                "support_requirements": list(t.support_requirements),
                "notes": t.notes,
            }
            for t in TARGETS
        ],
        "fixtures_lock": acquire.load_lock(),
        "measurement": measurement.as_dict(),
        "runs": [r.as_dict() for r in runs],
    }


# -------------------------------------------------------------------- report


def _config_table(block: dict, error_label: str) -> list[str]:
    lines = [
        f"| configuration | FINDING | NO_BUG | refused | {error_label} (95% CI) |",
        "|---|---|---|---|---|",
    ]
    for config in CONFIGS:
        cell = block["configs"][config]
        label = config if config != "naive" else "naive (provenance, not a comparison)"
        lines.append(
            f"| {label} | {cell['finding']} | {cell['no_bug']} | {cell['refused']} | "
            f"{format_rate(cell['error_rate'])} |"
        )
    return lines


def render_markdown(payload: dict) -> str:
    m = payload["measurement"]
    sel = payload["selection"]
    out: list[str] = []
    add = out.append

    add("# CVE study: pre-fix and post-fix, ground truth from the vendor")
    add("")
    add(
        "Reproduce with `python benchmarks/cve_study/run_study.py --check`, which recomputes "
        "every number below and exits non-zero if any of them moved."
    )
    add("")
    add(
        f"**{sel['reached']} of {sel['targets_considered']} candidate CVEs were reached.** "
        f"{len(sel['unreached'])} were admissible on paper but reachability could not be "
        f"demonstrated here ({', '.join(sel['unreached']) or 'none'}); "
        f"{len(sel['rejected'])} were rejected by the selection rule "
        f"({', '.join(sel['rejected']) or 'none'}). Only reached targets enter any number."
    )
    add("")
    add(
        "The selection rule was written and committed **before** any target was chosen; see "
        "`SELECTION_RULE.md`. Memory-safety CVEs are excluded by rule, because a sanitizer is "
        "already a mechanical oracle there."
    )
    add("")

    add("## 1. Pre-fix, rig intact: the false-negative rate")
    add("")
    add(
        "The vendor shipped a fix, so the vulnerability is present. `NO_BUG` is a false "
        "negative. A refusal is neither right nor wrong and is counted as its own class."
    )
    add("")
    out.extend(_config_table(m["prefix_clean"], "false-negative rate"))
    add("")
    fisher = m["prefix_clean"]["fisher_gated_vs_fair"]
    add(
        f"**Two-sided Fisher exact, gated versus fair: p = {fisher['p_two_sided']:.4g}** "
        f"(table {fisher['table']})."
    )
    add("")

    add("## 2. Post-fix, rig intact: the false-positive rate")
    add("")
    add("The fix is in, so `NO_BUG` is correct and `FINDING` is a false positive.")
    add("")
    out.extend(_config_table(m["postfix_clean"], "false-positive rate"))
    add("")
    fisher = m["postfix_clean"]["fisher_gated_vs_fair"]
    add(f"Two-sided Fisher exact, gated versus fair: p = {fisher['p_two_sided']:.4g}.")
    add("")

    add("## 3. Seeded rig breakage on the pre-fix version")
    add("")
    add(
        "The bug is present and the instrument is broken, so **`NO_BUG` is wrong** and a "
        "refusal is the only defensible answer. `FINDING` is unobtainable: the arm that would "
        "have found the bug never reached the target."
    )
    add("")
    for key, heading in (
        ("real_modes_only", "Real breakage (the headline for this arm)"),
        ("injected_modes_only", "Injected breakage (reported separately)"),
        ("controls_intact_only", "Controls intact, only the exploit arm broken"),
        ("all", "All breakage modes together"),
    ):
        block = m["seeded_breakage"][key]
        add(f"### {heading}")
        add("")
        if block.get("note"):
            add(f"{block['note']}")
            add("")
        out.extend(_config_table(block, 'called "no bug" (wrong)'))
        add("")
        add(
            "Two-sided Fisher exact, gated versus fair: "
            f"p = {block['fisher_gated_vs_fair']['p_two_sided']:.4g}."
        )
        add("")

    add("## 3b. Sensitivity: the fair baseline without the reachability record")
    add("")
    sens = m["sensitivity_fair_without_reachability"]
    add(sens["note"])
    add("")
    add(
        "This is the single number that makes the null above interpretable. The fair baseline "
        "refuses a broken rig because it is handed the derived answer to *did the treatment "
        "arm reach the target at all*. Deny it only that record, change nothing else, and:"
    )
    add("")
    add("| set | FINDING | NO_BUG | refused | error rate (95% CI) |")
    add("|---|---|---|---|---|")
    for (
        label,
        key,
    ) in (
        ("pre-fix, rig intact (error = NO_BUG)", "prefix_clean"),
        ("post-fix, rig intact (error = FINDING)", "postfix_clean"),
        ("seeded breakage, all modes (error = NO_BUG)", "seeded_breakage_all"),
        ("seeded breakage, real modes (error = NO_BUG)", "seeded_breakage_real_modes"),
    ):
        cell = sens[key][SENSITIVITY[0]]
        add(
            f"| {label} | {cell['finding']} | {cell['no_bug']} | {cell['refused']} | "
            f"{format_rate(cell['error_rate'])} |"
        )
    add("")
    add(
        "Gated versus this arm on all seeded breakage: Fisher p = "
        f"{sens['fisher_gated_vs_fair_no_reachability_on_breakage']['p_two_sided']:.4g}; "
        "on real modes only: p = "
        f"{sens['fisher_gated_vs_fair_no_reachability_on_real_breakage']['p_two_sided']:.4g}."
    )
    add("")
    add(
        "**Read it as a localisation, not as a win.** It says the lattice's value on this "
        "corpus is carried almost entirely by one record that a competent engineer could keep "
        "without this library, and that an engineer who does not keep it reports a broken rig "
        "as a clean target. It does not say the lattice beat the competent engineer: it did "
        "not, which is section 3."
    )
    add("")
    add("### Where the two configurations actually differ")
    add("")
    add(
        "The error rates above are identical, so it is worth saying plainly where gated and "
        "fair do **not** behave the same. On `stale_positive_control` the exploit arm still "
        "runs and still fires, because that mode corrupts the control's *record* rather than "
        "the exploit path. Gated refuses the run (`VOID`, rule `B-stale-control`) because the "
        "positive control it would be relying on belongs to an earlier run. Fair proceeds and "
        "reports a finding, which on a pre-fix pin is the right answer about the target."
    )
    add("")
    add(
        "That is the lattice being **more conservative than it needed to be**, not the lattice "
        "winning. It is counted as a refusal, it costs gated eleven correct findings, and it "
        "is the one place in this study where the discipline has a measurable price. Reporting "
        "it as a win would be the same move this repository criticises elsewhere."
    )
    add("")
    add("### By breakage mode")
    add("")
    add(
        '| mode | scope | realism | gated "no bug" | fair "no bug" | naive "no bug" | '
        'fair-no-reach "no bug" |'
    )
    add("|---|---|---|---|---|---|---|")
    for name, block in m["seeded_breakage"]["by_mode"].items():
        cells = " | ".join(
            f"{block['configs'][c]['no_bug']}/{block['n_per_config']}"
            for c in (*CONFIGS, *SENSITIVITY)
        )
        add(f"| `{name}` | {block['scope']} | {block['realism']} | {cells} |")
    add("")

    add("## 4. The targets")
    add("")
    add("| CVE | package | pre -> post | class | status |")
    add("|---|---|---|---|---|")
    for t in payload["targets"]:
        add(
            f"| [{t['cve']}]({t['advisory_url']}) | {t['package']} | "
            f"`{t['pre']}` -> `{t['post']}` | {t['class']} | {t['status']} |"
        )
    add("")
    for t in payload["targets"]:
        add(f"### {t['cve']} ({t['package']} {t['pre']} -> {t['post']}) -- {t['status']}")
        add("")
        add(f"- **class** {t['class']}")
        add(f"- **advisory** {t['advisory_url']}")
        add(f"- **fix** {t['fix_release_url']}")
        add(f"- **fix evidence** {t['fix_evidence']}")
        add(f"- **oracle** {t['oracle']}")
        add(f"- **reachability** {t['reachability']}")
        if t["support_requirements"]:
            add(
                f"- **unpinned scaffolding** {', '.join(t['support_requirements'])} "
                "(not the independent variable)"
            )
        if t["notes"]:
            add(f"- **notes** {t['notes']}")
        add("")

    disagreements = m["fair_disagreements_with_reviewer_baseline"]
    add("## 5. Baseline cross-check")
    add("")
    add(
        "The `fair` configuration is the external reviewer's own `competent()` callable. "
        "`gates._fair` is a transcription of it, and every run was adjudicated by both. "
        + (
            f"**They disagreed on {len(disagreements)} runs: {disagreements}.** "
            "A disagreement is a finding about this repository and is published as one."
            if disagreements
            else "They agreed on all "
            f"{m['runs_total']} runs, so the baseline is the reviewer's, not a weakened copy."
        )
    )
    add("")
    add(
        f"Total runs: {m['runs_total']} = {sel['reached']} CVEs x "
        f"(2 clean + {len(MODES)} breakage modes)."
    )
    add("")
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------ cli


def _comparable(payload: dict) -> dict:
    """Everything a reader could quote. Excludes nothing that is a number."""
    return {"measurement": payload["measurement"], "selection": payload["selection"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire", action="store_true", help="fetch the pins (needs network)")
    parser.add_argument("--check", action="store_true", help="diff against the committed results")
    args = parser.parse_args(argv)

    if args.acquire:
        return do_acquire()

    runs = collect()
    payload = build_payload(runs)

    if args.check:
        if not JSON_PATH.exists():
            print(f"{JSON_PATH} does not exist; run without --check first", file=sys.stderr)
            return 1
        committed = json.loads(JSON_PATH.read_text(encoding="utf-8"))
        if _comparable(committed) != _comparable(payload):
            print("CVE study results moved. Committed versus recomputed:", file=sys.stderr)
            old = json.dumps(_comparable(committed), indent=2, sort_keys=True).splitlines()
            new = json.dumps(_comparable(payload), indent=2, sort_keys=True).splitlines()
            import difflib

            for line in difflib.unified_diff(old, new, "committed", "recomputed", lineterm=""):
                print(line, file=sys.stderr)
            return 1
        print(f"CVE study reproduces: {payload['measurement']['runs_total']} runs, numbers match.")
        return 0

    RESULTS.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    MD_PATH.write_text(render_markdown(payload), encoding="utf-8")
    print(f"wrote {JSON_PATH}")
    print(f"wrote {MD_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
