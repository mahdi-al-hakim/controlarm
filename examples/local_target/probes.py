"""Probe callables a plan file can name, against the deliberately flawed target.

``controlarm run`` resolves each arm's ``call`` as ``module:attribute`` and
invokes it with the arm's ``args``. A probe therefore has to be an ordinary
keyword-argument function returning ``(fired, detail)``, where ``detail`` is the
text the confound classifier reads. These are the ones the worked example in
``docs/cli.md`` uses, and they exist here rather than in the package for the
same reason the example target does: a probe that shipped inside the thing it
measures is harder for a reviewer to trust.

The oracle in ``reached_off_list`` is the host the fetcher **actually reached**,
read out of the parsed ``final_host`` field. It is deliberately not a substring
search for the off-list host: the response echoes the submitted URL, so a
substring check fires on the requests that were correctly blocked as well, and
that single mistake is five of the six numbered false positives in the
catalogue this repository encodes.
"""

from __future__ import annotations

import json

from examples.local_target.app import ALLOWLIST, Target

__all__ = ["fetch", "reached_off_list", "route_works"]


def fetch(url: str, mode: str = "flawed") -> tuple[int, str | None, str]:
    """POST one URL to ``/v1/fetch`` and return (status, final_host, detail)."""
    target = Target(mode=mode)
    response = target.respond("POST", "/v1/fetch", body=json.dumps({"url": url}).encode())
    host = response.body.get("final_host")
    return response.status, host, f"{response.status} final_host={host!r}"


def route_works(url: str, mode: str = "flawed") -> tuple[bool, str]:
    """Liveness. Asks only whether the route functions at all.

    A different question from the test arm's, on purpose: an arm that asked the
    same question as the thing under test would prove the rig works only when
    the finding exists, which is the confound that voids a run.
    """
    status, _, detail = fetch(url, mode)
    return status == 200, detail


def reached_off_list(url: str, mode: str = "flawed") -> tuple[bool, str]:
    """Fires when the fetcher reached a host the allowlist does not contain."""
    status, host, detail = fetch(url, mode)
    return (status == 200 and host is not None and host not in ALLOWLIST), detail
