"""Run one probe against one pin, in a subprocess, and report what each arm did.

A separate process per (CVE, version, breakage) is not ceremony. Two versions of
the same distribution cannot coexist in one interpreter, and a probe that
imported the wrong one would produce a clean-looking run whose numbers belong to
code that never executed. One process, one pin at the front of ``sys.path``, and
a version assertion in every liveness arm.

The three rig preconditions below exist because a real harness has them, and
because the seeded-breakage arm needs somewhere honest to break. In an unbroken
run they pass and cost nothing.

Output is a single JSON object on stdout. Anything this process writes to stderr
is captured by the parent and folded into the failing arm's detail, because a
swallowed reason is the defect the whole repository exists to prevent.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _precondition_scratch(config: dict) -> tuple[bool, str]:
    """The rig's scratch area must exist and be readable."""
    marker = Path(config["workdir"]) / "rig-ready"
    with marker.open("r", encoding="utf-8") as handle:
        handle.read()
    return True, "scratch directory readable"


def _precondition_helper(config: dict) -> tuple[bool, str]:
    """The rig's helper process must start."""
    if config.get("action") == "helper_missing":
        executable = str(Path(config["workdir"]) / "controlarm-helper-not-installed")
    else:
        executable = sys.executable
    subprocess.run([executable, "-c", "pass"], capture_output=True, check=True)
    return True, "helper process started"


def _precondition_auth(config: dict) -> tuple[bool, str]:
    """The rig's service token must be accepted."""
    action = config.get("action")
    if action == "auth_401":
        raise RuntimeError("401 unauthorized: token expired for the probe service account")
    if action == "auth_429":
        raise RuntimeError("429 too many requests: rate limit reached, retry after 60s")
    return True, "service token accepted"


_PRECONDITIONS = (
    ("scratch", _precondition_scratch),
    ("helper", _precondition_helper),
    ("auth", _precondition_auth),
)


def _call(fn, *args) -> tuple[bool, str]:
    """Call one arm, turning any exception into a named failure rather than a crash.

    The exception type and message are preserved so the parent's classifier can
    still see a connection refusal, a missing file or a rate limit.
    """
    try:
        result = fn(*args)
    except Exception as exc:
        return False, f"<exception {type(exc).__name__}: {exc}>"
    if isinstance(result, tuple):
        return bool(result[0]), str(result[1])
    return bool(result), ""


def main() -> int:
    config = json.loads(sys.argv[1])
    action = config.get("action")

    sys.path.insert(0, config["repo_root"])
    if config.get("support_dir"):
        sys.path.insert(0, config["support_dir"])
    if action != "omit_pin_from_path":
        sys.path.insert(0, config["pin_dir"])

    report: dict = {"arms": {}, "exploit_reached_target": False}

    import importlib

    module_name = f"benchmarks.cve_study.probes.{config['probe']}"
    ctx = {
        "workdir": config["workdir"],
        "package": config["package"],
        "version": config["version"],
        "pin_dir": config["pin_dir"],
    }

    try:
        probe = importlib.import_module(module_name)
    except Exception as exc:
        detail = f"<exception {type(exc).__name__}: {exc}>"
        for arm in ("liveness", "control", "exploit"):
            report["arms"][arm] = [False, detail]
        print(json.dumps(report))
        return 0

    report["arms"]["liveness"] = list(_call(probe.liveness, ctx))
    report["arms"]["control"] = list(_call(probe.control, ctx))

    if action == "exit_before_reporting":
        # The shape of an out-of-memory kill: the work was under way and the
        # process vanished without writing a result.
        sys.stdout.flush()
        os._exit(3)

    if action == "delete_scratch":
        shutil.rmtree(config["workdir"], ignore_errors=True)

    failed = None
    for name, check in _PRECONDITIONS:
        ok, detail = _call(check, config)
        if not ok:
            failed = (name, detail)
            break

    if failed is not None:
        report["arms"]["exploit"] = [False, f"rig precondition {failed[0]!r} failed: {failed[1]}"]
    else:
        report["arms"]["exploit"] = list(_call(probe.exploit, ctx))
        report["exploit_reached_target"] = True

    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
