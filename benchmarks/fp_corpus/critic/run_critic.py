"""Score benchmarks/gates.py against the critic's adversarial pairs, and score a
*fair* unguarded baseline against the committed corpus.

Two separate experiments, both read-only with respect to the committed tree:

1. ``--critic``  twelve new cases (six pairs) aimed at the implementation.
2. ``--baseline`` the committed 38 cases re-scored with a "competent engineer
   without this library" baseline instead of ``gates._naive``. The competent
   baseline is allowed to do three things the published baseline is not: look at
   the positive control, look at the reported number, and say "I cannot tell".

Run both:  python benchmarks/fp_corpus/critic/run_critic.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from benchmarks import gates  # noqa: E402
from benchmarks.fp_corpus import load_cases  # noqa: E402
from benchmarks.scoring import CLASSES, classify_result, confusion, score  # noqa: E402

CRITIC_DIR = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# A fair unguarded baseline: a competent engineer with no library, who checks
# the status code, reads the response body, looks at whether their own positive
# control fired, and is willing to say "I cannot tell".
# --------------------------------------------------------------------------


def competent(obs: dict) -> gates.GateResult:
    kind = obs["kind"]

    if kind == "run_lattice":
        # An engineer who wrote a positive control looks at it.
        control = [a for a in obs["arms"] if a["role"] == "honest-control"]
        liveness = [a for a in obs["arms"] if a["role"] == "liveness"]
        tests = [a for a in obs["arms"] if a["role"] == "test"]
        executed = [a["name"] for a in tests if a["outcome"] == "executed"]
        if liveness and all(a["outcome"] != "executed" for a in liveness):
            return gates.GateResult("REFUSED", "VOID", "sense", "liveness never ran")
        if control and all(a["outcome"] != "refused" for a in control):
            return gates.GateResult("REFUSED", "VOID", "sense", "the control did not behave")
        if obs.get("reached_application_layer") is False:
            return gates.GateResult("REFUSED", "VOID", "sense", "never reached the app layer")
        if obs["claim"] == "clean-negative":
            if executed:
                return gates.GateResult("REFUSED", "CANDIDATE", "sense", f"arms ran: {executed}")
            return gates.GateResult("SUPPORTED", "KILL", "sense", "silent, control behaved")
        if executed:
            return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", "an arm executed")
        return gates.GateResult("REFUSED", "no-bug", "sense", "no arm executed")

    if kind == "oracle_expressivity":
        # One comparison: did the planted positive actually show up?
        pc = obs.get("positive_control") or {}
        if not pc or not pc.get("ran", False):
            return gates.GateResult("REFUSED", "VOID", "sense", "no control, or it did not run")
        exp, got = pc.get("expected_observable", ""), pc.get("observed", "")
        if exp and exp not in got:
            return gates.GateResult(
                "REFUSED", "VOID", "sense", "the planted positive did not show up"
            )
        marker = obs.get("treatment_observed", "")
        if obs["claim"] == "clean-negative":
            if marker:
                return gates.GateResult("REFUSED", "CANDIDATE", "sense", "the treatment fired")
            return gates.GateResult("SUPPORTED", "KILL", "sense", "silent, control proved")
        if marker:
            return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", "the marker was seen")
        return gates.GateResult("REFUSED", "no-bug", "sense", "no marker")

    if kind == "numeric_claim":
        # An engineer who reports a number has looked at the number.
        if obs["metric"] == "r2":
            v = float(obs["value"])
            if v < 0.0:
                return gates.GateResult(
                    "REFUSED", "INCONCLUSIVE", "sense", f"r2={v} is worse than the mean"
                )
            return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", f"r2={v}")
        if int(obs.get("constraint_eval_errors", 0)):
            return gates.GateResult(
                "REFUSED", "INCONCLUSIVE", "sense", "the generator reported errors"
            )
        if int(obs["rows"]) < int(obs["independent_minimum"]):
            return gates.GateResult(
                "REFUSED", "INCONCLUSIVE", "sense", "fewer rows than the stated minimum"
            )
        return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", "rows meet the minimum")

    if kind == "http_differential":
        # An engineer who reads the status code before the body.
        arms = obs["arms"]
        if obs["claim"] == "disclosure":
            if all(not 200 <= a["response"]["status"] < 300 for a in arms):
                return gates.GateResult("REFUSED", "KILL", "sense", "no 2xx: it was rejected")
            return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", "a 2xx carries the id")
        bodies = {a["label"]: json.dumps(a["response"].get("body"), sort_keys=True) for a in arms}
        if len(set(bodies.values())) > 1:
            return gates.GateResult("SUPPORTED", "CANDIDATE", "sense", "the bodies differ")
        return gates.GateResult("REFUSED", "no-bug", "sense", "identical")

    # Everything else: fall back to the published naive check unchanged.
    return gates._naive(obs)


# ----------------------------------------------------------------- reporting


def _score_block(cases, fn) -> dict:
    res = {c.id: fn(c.observation) for c in cases}
    s = score([(c.member, res[c.id].decision) for c in cases])
    conf = confusion(
        [(c.truth_class, classify_result(res[c.id].decision, res[c.id].verdict)) for c in cases]
    )
    return {"results": res, "score": s, "confusion": conf}


def report_critic() -> int:
    cases = load_cases(CRITIC_DIR)
    block = _score_block(cases, lambda o: gates.adjudicate(o, gates_enabled=True))
    res, s = block["results"], block["score"]
    print(f"=== critic adversarial corpus: {len(cases)} cases, {len(cases) // 2} pairs ===")
    wrong = []
    for c in cases:
        r = res[c.id]
        ok = r.decision == c.correct_decision
        if not ok:
            wrong.append(c)
        print(
            f"  {'PASS' if ok else 'FAIL'}  {c.id:14s} want {c.correct_decision:9s}/"
            f"{c.correct_verdict:12s}  got {r.decision:9s}/{r.verdict:12s} rule={r.rule}"
        )
    print(
        f"  gates: recall={s.recall} precision={s.precision} "
        f"(tp {s.tp} fn {s.fn} fp {s.fp} tn {s.tn}), accuracy={s.accuracy}"
    )
    print(f"  failed {len(wrong)}/{len(cases)}: {[c.id for c in wrong]}")
    for c in wrong:
        kind = (
            "FALSE NEGATIVE (killed a genuine case)"
            if c.member == "genuine"
            else "FALSE POSITIVE (accepted a false signal)"
        )
        print(f"    - {c.id}: {kind}")
    return len(wrong)


def report_baseline() -> None:
    cases = load_cases()
    print(f"\n=== committed corpus ({len(cases)} cases): three configurations ===")
    rows = []
    for name, fn in (
        ("gated", lambda o: gates.adjudicate(o, gates_enabled=True)),
        ("published naive", lambda o: gates.adjudicate(o, gates_enabled=False)),
        ("competent engineer", competent),
    ):
        b = _score_block(cases, fn)
        s, conf = b["score"], b["confusion"]
        un = [c for c in cases if c.truth_class == "UNINTERPRETABLE"]
        cls = [classify_result(b["results"][c.id].decision, b["results"][c.id].verdict) for c in un]
        neg = [c for c in un if c.claim == "clean-negative"]
        ncls = [
            classify_result(b["results"][c.id].decision, b["results"][c.id].verdict) for c in neg
        ]
        rows.append(
            (
                name,
                conf.correct(),
                conf.total(),
                cls.count("NO_BUG"),
                cls.count("UNINTERPRETABLE"),
                ncls.count("NO_BUG"),
                len(neg),
                s.recall,
                s.precision,
            )
        )
    hdr = (
        f"{'configuration':20s} {'acc':>9s}  {'11 UNINTERP: no-bug':>20s} {'refused':>8s}  "
        f"{'7 true negs: no-bug':>20s}  {'recall':>6s} {'prec':>5s}"
    )
    print(hdr)
    for n, c, t, nb, ref, nnb, nn, rc, pr in rows:
        print(
            f"{n:20s} {c}/{t} ({c / t:.2f})  {nb:>20d} {ref:>8d}  "
            f"{str(nnb) + '/' + str(nn):>20s}  {rc if rc is None else f'{rc:.2f}':>6} "
            f"{pr if pr is None else f'{pr:.2f}':>5}"
        )
    print(
        "\n  Note: the published naive adjudicator can return only the verdicts "
        "'CANDIDATE' and 'no-bug'.\n  scoring._UNINTERPRETABLE = "
        f"{sorted(['VOID', 'CONFOUNDED', 'INCONCLUSIVE', 'NO-TESTS'])}.\n"
        "  Its score on the 11 UNINTERPRETABLE cases is therefore 0/11 before any "
        "fixture is read."
    )
    # Which of the 11 are actually negatives?
    un = [c for c in cases if c.truth_class == "UNINTERPRETABLE"]
    print("\n  The 11 'untrustworthy negatives', by the claim their own fixture makes:")
    for c in un:
        print(f"    {c.id:14s} claim={c.claim}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--critic", action="store_true")
    ap.add_argument("--baseline", action="store_true")
    a = ap.parse_args()
    both = not (a.critic or a.baseline)
    failed = 0
    if a.critic or both:
        failed = report_critic()
    if a.baseline or both:
        report_baseline()
    assert CLASSES
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
