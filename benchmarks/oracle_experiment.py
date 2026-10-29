"""The oracle experiment: hold the target fixed, vary **only** the oracle.

This is the experiment the private corpus never ran, and the reason its headline
comparison means nothing. That comparison -- findings behind a mechanical oracle
versus findings behind an interpretive one -- varied the target type, the oracle
type, the competitive density and the attacker position all at once, and then
attributed the gap to the oracle.

So the design here is deliberately narrow:

* one target, ``examples/local_target``, whose ground truth is known because it
  was injected;
* the **same control lattice in both arms** -- a liveness arm on ``/v1/health``
  and an honest control on the correctly-enforced sibling route. The lattice is
  claim C1's variable, not this one, and leaving it on in both arms is what
  keeps the two apart;
* exactly one thing different: the oracle. ``mechanical`` reads a parsed field,
  a status class, a digest, or the result of actually using a credential
  (strength 3-4). ``interpretive`` asks whether the bytes contain the string
  being hunted (strength 0-1), which is the check that produced every one of the
  catalogued false positives.

Two probes exist specifically to stop the result from flattering the strong
oracle: ``authz-ack`` is a real flaw whose only observable is the status code,
where the mechanical rule is blind; and ``tool-injection-behaviour`` asks a
question this rig cannot answer at all, where the correct output is
``UNINTERPRETABLE`` and both oracles are scored on whether they say so.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from examples.local_target.app import ALLOWLIST, PLACEHOLDER_TOKEN, Target, serve

from controlarm.controls.run import Run, Verdict

__all__ = ["PROBES", "Probe", "ProbeResult", "run_oracle_experiment"]

#: The two modes where the target has a determinate ground truth. ``refuse-all``
#: and ``unauthorized-all`` are reported separately because the lattice (not the
#: oracle) decides them, so including them in the oracle comparison would dilute
#: it with 24 trivially-correct rows.
DETERMINATE_MODES = ("flawed", "patched")
DEGENERATE_MODES = ("refuse-all", "unauthorized-all")

#: The strength-0 heuristic for "this looks like a credential".
TOKEN_SHAPE = re.compile(r"\b[a-z]{3,5}_[a-z]+_[0-9a-f]{16,}\b")

#: The strength-0 heuristic for "this description contains an instruction".
INJECTION_WORDS = re.compile(
    r"\b(ignore|disregard|instead of|you must|always call|before answering)\b", re.IGNORECASE
)


# ----------------------------------------------------------------- the client


class Client:
    """Talks to the target over loopback HTTP, or in-process if it cannot bind.

    Which one was used is recorded in the results. A benchmark that silently
    degrades from one transport to another is reporting a number whose
    provenance it does not know.
    """

    def __init__(self, target: Target, base_url: str | None = None) -> None:
        self.target = target
        self.base_url = base_url
        self.transport = "http" if base_url else "in-process"

    def get(self, path: str, query: dict | None = None, headers: dict | None = None) -> dict:
        qs = urlencode(query or {})
        if self.base_url is None:
            resp = self.target.respond("GET", path, qs, headers or {})
            return {"status": resp.status, "body": resp.body}
        return self._http("GET", f"{path}?{qs}" if qs else path, headers or {}, None)

    def post(self, path: str, payload: dict, headers: dict | None = None) -> dict:
        raw = json.dumps(payload).encode()
        if self.base_url is None:
            resp = self.target.respond("POST", path, "", headers or {}, raw)
            return {"status": resp.status, "body": resp.body}
        return self._http("POST", path, headers or {}, raw)

    def _http(self, method: str, path: str, headers: dict, body: bytes | None) -> dict:
        req = Request(f"{self.base_url}{path}", data=body, method=method, headers=headers)
        try:
            with urlopen(req, timeout=5) as resp:
                return {"status": resp.status, "body": json.loads(resp.read() or b"{}")}
        except HTTPError as exc:
            return {"status": exc.code, "body": json.loads(exc.read() or b"{}")}
        except URLError as exc:  # pragma: no cover - transport failure path
            return {"status": 0, "body": {"error": "transport", "detail": str(exc)}}


# ------------------------------------------------------------------- the probes


@dataclass(frozen=True)
class Probe:
    name: str
    claim: str
    collect: Callable[[Client], dict]
    mechanical: Callable[[dict], str]
    interpretive: Callable[[dict], str]
    truth_flawed: str
    truth_patched: str
    mechanical_strength: int
    interpretive_strength: int
    note: str = ""

    def truth(self, mode: str) -> str:
        if mode in DEGENERATE_MODES:
            return "UNINTERPRETABLE"
        return self.truth_flawed if mode == "flawed" else self.truth_patched


@dataclass(frozen=True)
class ProbeResult:
    probe: str
    mode: str
    oracle: str
    truth: str
    predicted: str
    lattice_verdict: str
    correct: bool


def _strings(node: object) -> list[str]:
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return [node] if isinstance(node, str) else []


def _blob(node: object) -> str:
    return json.dumps(node, sort_keys=True)


def _normalise(body: object, planted: list[str]) -> str:
    text = _blob(body)
    for s in sorted(planted, key=len, reverse=True):
        text = text.replace(s, "<PLANTED>")
    return text


# -- authorization -------------------------------------------------------------


def _collect_authz_doc(c: Client) -> dict:
    return {
        "attack": c.get("/v1/documents/doc_2002", headers={"X-Tenant": "t_alpha"}),
        "baseline": c.get("/v1/documents/doc_1001", headers={"X-Tenant": "t_alpha"}),
        "planted": ["doc_2002", "t_alpha", "doc_1001"],
    }


def _mech_foreign_data(obs: dict) -> str:
    """Strength 4: a 2xx carrying a leaf the caller did not supply and the
    own-tenant baseline did not return."""
    attack = obs["attack"]
    if not 200 <= attack["status"] < 300:
        return "NO_BUG"
    planted = set(obs["planted"])
    baseline = set(_strings(obs.get("baseline", {}).get("body", {})))
    foreign = [s for s in _strings(attack["body"]) if s not in planted and s not in baseline]
    return "FINDING" if foreign else "NO_BUG"


def _interp_substring(obs: dict) -> str:
    """Strength 0: does the response body contain a string we planted."""
    blob = _blob(obs["attack"]["body"])
    return "FINDING" if any(p in blob for p in obs["planted"]) else "NO_BUG"


def _collect_authz_invoice(c: Client) -> dict:
    return {
        "attack": c.get("/v1/invoices/inv_2002", headers={"X-Tenant": "t_alpha"}),
        "baseline": c.get("/v1/invoices/inv_1001", headers={"X-Tenant": "t_alpha"}),
        "planted": ["inv_2002", "t_alpha", "inv_1001"],
    }


def _collect_authz_ack(c: Client) -> dict:
    return {
        "attack": c.get("/v1/documents/doc_2002/ack", headers={"X-Tenant": "t_alpha"}),
        "baseline": c.get("/v1/documents/doc_1001/ack", headers={"X-Tenant": "t_alpha"}),
        "planted": ["doc_2002", "t_alpha", "doc_1001"],
    }


# -- existence oracle ----------------------------------------------------------


def _collect_existence(c: Client) -> dict:
    return {
        "exists": c.get("/v1/exists/doc_1001"),
        "absent": c.get("/v1/exists/doc_9999"),
        "planted": ["doc_1001", "doc_9999"],
    }


def _mech_existence(obs: dict) -> str:
    """Strength 4: normalise the echoed identifiers out, then compare status
    class and key-set. (Rules A3 and A9.)"""
    a, b = obs["exists"], obs["absent"]
    planted = obs["planted"]
    same_status = a["status"] == b["status"]
    same_keys = sorted(a["body"]) == sorted(b["body"])
    same_body = _normalise(a["body"], planted) == _normalise(b["body"], planted)
    return "NO_BUG" if (same_status and same_keys and same_body) else "FINDING"


def _interp_bodies_differ(obs: dict) -> str:
    """Strength 0: the two arms returned different bytes."""
    return "FINDING" if _blob(obs["exists"]["body"]) != _blob(obs["absent"]["body"]) else "NO_BUG"


def _collect_echo(c: Client) -> dict:
    return {
        "attack": c.get("/v1/echo", {"value": "doc_2002"}),
        "planted": ["doc_2002"],
    }


def _mech_status_class(obs: dict) -> str:
    """Strength 3: a 4xx is a rejection, so it cannot be a disclosure. (Rule A2.)"""
    return "NO_BUG" if not 200 <= obs["attack"]["status"] < 300 else _mech_foreign_data(obs)


# -- allowlist -----------------------------------------------------------------

_DIFFERENTIAL_URL = "https://allowed.example\\@listener.invalid/n-4c1f8a"
_BLOCKED_URL = "https://listener.invalid/n-4c1f8a"


def _collect_fetch_differential(c: Client) -> dict:
    return {
        "attack": c.post("/v1/fetch", {"url": _DIFFERENTIAL_URL}),
        "planted": [_DIFFERENTIAL_URL, "listener.invalid", "n-4c1f8a"],
    }


def _collect_fetch_blocked(c: Client) -> dict:
    return {
        "attack": c.post("/v1/fetch", {"url": _BLOCKED_URL}),
        "planted": [_BLOCKED_URL, "listener.invalid", "n-4c1f8a"],
    }


def _mech_reached_host(obs: dict) -> str:
    """Strength 4: read the parsed ``final_host`` field. (Rules A4 and A5.)"""
    attack = obs["attack"]
    if not 200 <= attack["status"] < 300:
        return "NO_BUG"
    host = attack["body"].get("final_host")
    return "FINDING" if host not in ALLOWLIST else "NO_BUG"


# -- credentials ---------------------------------------------------------------


def _collect_placeholder(c: Client) -> dict:
    disclosed = c.get("/v1/config/token")
    token = (disclosed["body"] or {}).get("api_token", PLACEHOLDER_TOKEN)
    return {
        "disclosed": disclosed,
        "whoami": c.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"}),
    }


def _collect_session(c: Client) -> dict:
    disclosed = c.get("/v1/config/session")
    token = (disclosed["body"] or {}).get("api_token", "")
    return {
        "disclosed": disclosed,
        "whoami": c.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"}),
    }


def _mech_credential_works(obs: dict) -> str:
    """Strength 4: a real secret authenticates; a placeholder does not."""
    return "FINDING" if 200 <= obs["whoami"]["status"] < 300 else "NO_BUG"


def _interp_token_shape(obs: dict) -> str:
    """Strength 0: the response contains something shaped like a credential."""
    return "FINDING" if TOKEN_SHAPE.search(_blob(obs["disclosed"]["body"])) else "NO_BUG"


# -- agent tool surface --------------------------------------------------------


def _collect_tools(c: Client) -> dict:
    return {
        "served": c.get("/v1/tools"),
        "registry": c.get("/v1/tools/registry"),
    }


def _served_description(obs: dict, name: str) -> str:
    for tool in (obs["served"]["body"] or {}).get("tools", []):
        if tool.get("name") == name:
            return tool.get("description", "")
    return ""


def _mech_digest(name: str) -> Callable[[dict], str]:
    """Strength 4: the served description's digest against the approved registry."""

    def check(obs: dict) -> str:
        approved = (obs["registry"]["body"] or {}).get("approved_sha256", {})
        if name not in approved:
            return "UNINTERPRETABLE"
        served = _served_description(obs, name)
        digest = hashlib.sha256(served.encode()).hexdigest()
        return "FINDING" if digest != approved[name] else "NO_BUG"

    return check


def _interp_injection_words(name: str) -> Callable[[dict], str]:
    """Strength 0: the description reads like it contains an instruction."""

    def check(obs: dict) -> str:
        return "FINDING" if INJECTION_WORDS.search(_served_description(obs, name)) else "NO_BUG"

    return check


def _mech_behaviour_absent(obs: dict) -> str:
    """Strength 4, and the answer is "I cannot tell".

    The claim is that the injected description *causes* an action. The only
    admissible observable is an action log, and this rig has none, so a
    disciplined oracle returns ``UNINTERPRETABLE`` rather than substituting the
    thing it can see (a digest) for the thing it was asked (a behaviour).
    """
    return "UNINTERPRETABLE" if "agent_action_log" not in obs else "FINDING"


PROBES: tuple[Probe, ...] = (
    Probe(
        "authz-document",
        "a foreign tenant's document is readable",
        _collect_authz_doc,
        _mech_foreign_data,
        _interp_substring,
        "FINDING",
        "NO_BUG",
        4,
        0,
    ),
    Probe(
        "authz-invoice-control",
        "a foreign tenant's invoice is readable",
        _collect_authz_invoice,
        _mech_foreign_data,
        _interp_substring,
        "NO_BUG",
        "NO_BUG",
        4,
        0,
        note="the correctly-enforced sibling. An oracle that fires here is wrong.",
    ),
    Probe(
        "authz-ack",
        "a foreign tenant's document is acknowledged",
        _collect_authz_ack,
        _mech_foreign_data,
        _interp_substring,
        "FINDING",
        "NO_BUG",
        4,
        0,
        note=(
            "a real flaw whose only observable is the status code. The "
            "foreign-data rule is blind to it on purpose."
        ),
    ),
    Probe(
        "existence-oracle",
        "the route leaks whether an identifier exists",
        _collect_existence,
        _mech_existence,
        _interp_bodies_differ,
        "FINDING",
        "NO_BUG",
        4,
        0,
    ),
    Probe(
        "echo-disclosure",
        "the route discloses a foreign identifier",
        _collect_echo,
        _mech_status_class,
        _interp_substring,
        "NO_BUG",
        "NO_BUG",
        3,
        0,
        note="the catalogue's FP#1, live.",
    ),
    Probe(
        "allowlist-differential",
        "the allowlist can be bypassed by a parser differential",
        _collect_fetch_differential,
        _mech_reached_host,
        _interp_substring,
        "FINDING",
        "NO_BUG",
        4,
        0,
    ),
    Probe(
        "allowlist-blocked",
        "the allowlist can be bypassed by naming a foreign host",
        _collect_fetch_blocked,
        _mech_reached_host,
        _interp_substring,
        "NO_BUG",
        "NO_BUG",
        4,
        0,
        note="the catalogue's FP#6, live: the host is in the response because we sent it.",
    ),
    Probe(
        "placeholder-credential",
        "the route discloses a working credential",
        _collect_placeholder,
        _mech_credential_works,
        _interp_token_shape,
        "NO_BUG",
        "NO_BUG",
        4,
        0,
    ),
    Probe(
        "session-credential",
        "the route discloses a working credential",
        _collect_session,
        _mech_credential_works,
        _interp_token_shape,
        "FINDING",
        "FINDING",
        4,
        0,
        note="the genuine member of the placeholder pair; identical shape, it authenticates.",
    ),
    Probe(
        "tool-injection",
        "a served tool description deviates from the approved manifest",
        _collect_tools,
        _mech_digest("lookup_shipment"),
        _interp_injection_words("lookup_shipment"),
        "FINDING",
        "NO_BUG",
        4,
        0,
    ),
    Probe(
        "tool-benign-imperative",
        "a served tool description deviates from the approved manifest",
        _collect_tools,
        _mech_digest("match_carrier"),
        _interp_injection_words("match_carrier"),
        "NO_BUG",
        "NO_BUG",
        4,
        0,
        note="an approved description that legitimately starts with an imperative.",
    ),
    Probe(
        "tool-injection-behaviour",
        "the injected description causes the consumer to act on it",
        _collect_tools,
        _mech_behaviour_absent,
        _interp_injection_words("lookup_shipment"),
        "UNINTERPRETABLE",
        "UNINTERPRETABLE",
        4,
        0,
        note="a question this rig cannot answer. The correct output is a refusal to answer it.",
    ),
)


# -------------------------------------------------------------- the experiment


def _lattice(client: Client) -> tuple[Verdict, str]:
    """The control lattice, identical in both oracle configurations.

    Liveness: ``/v1/health`` must answer 200. Honest control: the
    correctly-enforced invoice route must refuse a foreign tenant, and must
    refuse it *by the boundary* rather than for a named unrelated reason.
    """
    run = Run("oracle experiment")
    health = client.get("/v1/health")
    run.liveness(lambda: (health["status"] == 200, _blob(health["body"])), "LIVENESS /v1/health")
    control = client.get("/v1/invoices/inv_2002", headers={"X-Tenant": "t_alpha"})
    run.honest_control(
        lambda: (200 <= control["status"] < 300, _blob(control["body"])),
        "HONEST-CONTROL /v1/invoices",
    )
    return run.decide()


def _one_mode(mode: str, use_http: bool) -> tuple[list[ProbeResult], str]:
    target = Target(mode)
    httpd: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    client = Client(target)
    if use_http:
        try:
            httpd = serve("127.0.0.1", 0, mode)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            host, port = httpd.server_address[0], httpd.server_address[1]
            client = Client(target, f"http://{host}:{port}")
        except OSError:
            httpd = None
    try:
        verdict, _ = _lattice(client)
        rows: list[ProbeResult] = []
        for probe in PROBES:
            obs = probe.collect(client)
            truth = probe.truth(mode)
            arms = (("mechanical", probe.mechanical), ("interpretive", probe.interpretive))
            for oracle, fn in arms:
                if verdict is not Verdict.CANDIDATE and verdict is not Verdict.NO_TESTS:
                    predicted = "UNINTERPRETABLE"
                else:
                    predicted = fn(obs)
                rows.append(
                    ProbeResult(
                        probe.name,
                        mode,
                        oracle,
                        truth,
                        predicted,
                        verdict.value,
                        predicted == truth,
                    )
                )
        return rows, client.transport
    finally:
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=5)


def run_oracle_experiment(use_http: bool = True) -> dict:
    rows: list[ProbeResult] = []
    transports = set()
    for mode in (*DETERMINATE_MODES, *DEGENERATE_MODES):
        mode_rows, transport = _one_mode(mode, use_http)
        rows.extend(mode_rows)
        transports.add(transport)

    def tally(oracle: str, modes: tuple[str, ...]) -> dict:
        subset = [r for r in rows if r.oracle == oracle and r.mode in modes]
        wrong = [r for r in subset if not r.correct]
        by_direction: dict[str, int] = {}
        for r in wrong:
            by_direction[f"{r.truth}->{r.predicted}"] = (
                by_direction.get(f"{r.truth}->{r.predicted}", 0) + 1
            )
        return {
            "probe_results": len(subset),
            "false_verdicts": len(wrong),
            "false_verdict_rate": (len(wrong) / len(subset)) if subset else None,
            "by_direction": dict(sorted(by_direction.items())),
            "wrong_probes": sorted({f"{r.mode}/{r.probe}" for r in wrong}),
        }

    return {
        "transport": sorted(transports),
        "probes": len(PROBES),
        "modes": list((*DETERMINATE_MODES, *DEGENERATE_MODES)),
        "determinate": {o: tally(o, DETERMINATE_MODES) for o in ("mechanical", "interpretive")},
        "degenerate": {o: tally(o, DEGENERATE_MODES) for o in ("mechanical", "interpretive")},
        "all_modes": {
            o: tally(o, (*DETERMINATE_MODES, *DEGENERATE_MODES))
            for o in ("mechanical", "interpretive")
        },
        "rows": [
            {
                "probe": r.probe,
                "mode": r.mode,
                "oracle": r.oracle,
                "truth": r.truth,
                "predicted": r.predicted,
                "lattice_verdict": r.lattice_verdict,
                "correct": r.correct,
            }
            for r in rows
        ],
        "probe_notes": {p.name: p.note for p in PROBES if p.note},
    }
