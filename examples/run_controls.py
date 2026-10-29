"""Two experiments against the local target, in four modes, producing four verdicts.

No credentials, no network, no accounts. The target is the deliberately flawed
app in ``examples/local_target``, driven in-process.

    python examples/run_controls.py

Experiment A reads a document belonging to another tenant. Experiment B asks the
target to fetch a URL whose host the allowlist and the fetcher parse differently.
The same three arms are submitted in every mode; only the mode changes.

The instructive cell is **A/flawed = VOID**, not a missed finding. In that mode
the boundary is absent, so the honest control -- the plain request, with no
evasion at all -- already succeeds. The harness refuses to credit the test arm,
because nothing it did can be distinguished from the plain request working. The
finding there is the honest control itself, and a harness that reported
CANDIDATE would be taking credit for an evasion that was never needed.

B/flawed is a real CANDIDATE: the plain request is refused, and the test arm
reaches a host outside the allowlist because two parsers disagree about it.
"""

from __future__ import annotations

import json
import pathlib
import sys

# Running this as a plain script puts examples/ on sys.path, not the repository
# root, so `examples.local_target` would not resolve. The root is added here
# rather than asking the reader to set PYTHONPATH, because the README promises
# that `python examples/run_controls.py` works exactly as written.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from controlarm import Run, Verdict
from examples.local_target.app import ALLOWLIST, Target

#: From the target's fixture data: doc_1001 belongs to t_alpha, doc_2002 to
#: t_beta. The caller is t_alpha throughout, so doc_2002 is the foreign object.
CALLER = {"x-tenant": "t_alpha"}
OWN_DOC = "doc_1001"
FOREIGN_DOC = "doc_2002"

#: A host the allowlist does not contain. The backslash form is the differential:
#: one parser treats it as a path separator and reads `allowed.example`, the
#: other reads the real authority. Neither parser is wrong on its own.
OFF_LIST = "listener.invalid"
ON_LIST = next(iter(sorted(ALLOWLIST)))
PLAIN_URL = f"https://{OFF_LIST}/c"
SPLIT_URL = rf"https://{ON_LIST}\@{OFF_LIST}/c"

MODES = ("flawed", "patched", "refuse-all", "unauthorized-all")


def _read(
    target: Target, doc_id: str, headers: dict[str, str], suffix: str = ""
) -> tuple[bool, str]:
    """Did the read go through, and what did the target say about it."""
    response = target.respond("GET", f"/v1/documents/{doc_id}{suffix}", headers=headers)
    return response.status == 200, f"{response.status} {response.as_bytes().decode()}"


def _fetch(target: Target, url: str) -> tuple[bool, str]:
    """Did the fetch reach a host outside the allowlist.

    The oracle is ``final_host``, which the target reports from the parser that
    actually performs the fetch. It is mechanical: a host outside the allowlist
    appearing there is the whole claim. Note what is *not* used -- the response
    also echoes the submitted URL, so a substring check for ``listener.invalid``
    would fire on the correctly-blocked requests too.
    """
    response = target.respond("POST", "/v1/fetch", body=json.dumps({"url": url}).encode())
    reached = response.body.get("final_host")
    return (
        response.status == 200 and reached not in ALLOWLIST and reached is not None,
        f"{response.status} final_host={reached!r}",
    )


def experiment_a(target: Target) -> Run:
    """Object-level authorization on the document route."""
    run = Run("A: the tenant boundary holds on the document route")
    run.liveness(lambda: _read(target, OWN_DOC, CALLER), name="read own document")
    run.honest_control(
        lambda: _read(target, FOREIGN_DOC, CALLER), name="read foreign document, plainly"
    )
    run.arm(
        "foreign document via the acknowledge route",
        lambda: _read(target, FOREIGN_DOC, CALLER, suffix="/ack"),
    )
    return run


def experiment_b(target: Target) -> Run:
    """A parser differential between the allowlist and the fetcher."""
    run = Run("B: the fetch allowlist cannot be reached past")
    run.liveness(lambda: _on_list_fetch(target), name="fetch an allowed host")
    run.honest_control(lambda: _fetch(target, PLAIN_URL), name="fetch the off-list host, plainly")
    run.arm("off-list host behind a backslash authority", lambda: _fetch(target, SPLIT_URL))
    return run


def _on_list_fetch(target: Target) -> tuple[bool, str]:
    """Liveness for B: an allowed host must fetch, or the route is simply broken."""
    response = target.respond(
        "POST", "/v1/fetch", body=json.dumps({"url": f"https://{ON_LIST}/ok"}).encode()
    )
    return response.status == 200, f"{response.status} {response.as_bytes().decode()[:60]}"


EXPECTED = {
    ("A", "flawed"): Verdict.VOID,
    ("A", "patched"): Verdict.KILL,
    ("A", "refuse-all"): Verdict.VOID,
    ("A", "unauthorized-all"): Verdict.VOID,
    ("B", "flawed"): Verdict.CANDIDATE,
    ("B", "patched"): Verdict.KILL,
    ("B", "refuse-all"): Verdict.VOID,
    ("B", "unauthorized-all"): Verdict.VOID,
}


def main() -> int:
    width = max(len(m) for m in MODES)
    print(f"{'exp':<4}{'mode':<{width + 2}}{'verdict':<12}why")
    print("-" * (width + 92))

    seen: dict[tuple[str, str], Verdict] = {}
    for label, build in (("A", experiment_a), ("B", experiment_b)):
        for mode in MODES:
            verdict, why = build(Target(mode=mode)).decide()
            seen[(label, mode)] = verdict
            print(
                f"{label:<4}{mode:<{width + 2}}{verdict.value:<12}{why.split('.')[0].strip()[:70]}"
            )
        print()

    print("A/flawed is VOID because the plain request already worked, so no evasion")
    print("can be credited. B/flawed is a CANDIDATE because the plain request was")
    print("refused and the test arm still reached an off-list host. The two refuse-all")
    print("and unauthorized-all rows are what an unguarded harness reports as 'no bug'.")

    # The example doubles as an assertion: if these stop differing, the README
    # describes behaviour the code no longer has.
    if seen != EXPECTED:
        wrong = {f"{k[0]}/{k[1]}": v.value for k, v in seen.items() if EXPECTED[k] is not v}
        print(f"\nUNEXPECTED: {wrong}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
