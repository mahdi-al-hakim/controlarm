"""Record/replay transport for the network prior-art sources.

Every request a source makes goes through here, and every response is written
to disk as a file containing *both* the request and the response. Three
consequences, each of which is the point:

  * CI never touches the network. The default mode is ``REPLAY``.
  * A published duplicate rate is auditable. The recordings are the primary
    evidence; a reader can re-issue the recorded request and compare.
  * A cassette miss is an error, never an empty result. "I have no recording of
    that question" and "the corpus answered zero" are the same row count and
    opposite claims -- the ``UNGATED``-is-not-``CLEAR`` rule, one layer down.

Numbered failure modes, each a line of code below:

  1  a replay miss returned as zero rows   -> the original sketch returned an
     empty body on a miss, so running the benchmark against a half-recorded
     cassette directory scored every unrecorded case CLEAR. A miss raises.
  2  REPLAY mode reaching the network      -> a mode check placed after the
     network call still makes the call. The check is before it, and ``REPLAY``
     has no code path to the socket at all.
  3  a hand-written body scored as evidence -> fault-injection fixtures have to
     exist (a truncated body, a 500) and must never be counted. Every recording
     carries ``provenance``, only ``recorded`` is admissible, and admitting a
     ``synthetic`` one takes an explicit opt-in the measurement never passes.
  4  a credential written to a cassette    -> the recordings are committed.
     Bodies are scrubbed for token-shaped strings and for the authenticated
     account's identity before anything is written, and a subprocess failure
     records its exit code rather than its stderr.
  5  a free public API hammered            -> a benchmark loop with no pause
     between requests is impolite at best and rate-limited at worst, and a
     429 recorded as a response is a recorded falsehood. Network calls are
     spaced per host, and a non-2xx is never parsed into rows.
  6  a plain-HTTP or IP-literal endpoint   -> an unencrypted or
     unauthenticated-by-DNS endpoint can be answered by anything on the path,
     and "the corpus said zero" would then mean "something said zero". Only
     ``https`` with a named host is fetched.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from controlarm.gates.priorart import PriorArtError

__all__ = [
    "RECORDED",
    "SYNTHETIC",
    "USER_AGENT",
    "CassetteMiss",
    "CassetteStore",
    "FetchMode",
    "Fetcher",
    "Recording",
    "Request",
    "TransportError",
    "scrub",
    "scrub_body",
]

#: Sent on every HTTP request. Names the tool so a corpus operator can see
#: who is calling, and carries no identity: no account, no handle, no
#: machine name. The recordings store the request URL, method and body, so
#: nothing about the caller reaches a committed file either.
USER_AGENT = "controlarm-priorart/0.1 (+https://github.com/controlarm)"

#: Provenance values. Only the first is admissible as evidence.
RECORDED = "recorded"
SYNTHETIC = "synthetic"

#: Token-shaped strings, redacted before anything is written to disk. The
#: harness never sends a token of its own -- ``gh`` holds its credential -- but
#: a response that echoed one back would otherwise be committed.
#: ``(pattern, replacement)`` pairs. The replacement matters. An earlier
#: version substituted a bare ``REDACTED`` for the whole ``"token": "..."``
#: pair, which turns ``{"token": "x"}`` into ``{REDACTED}``. That is not JSON.
#: The rule now keeps the key and the punctuation and redacts only the value.
#: The test that covered this asserted the secret was gone and never asked
#: whether what came back was still parseable, so it passed for months.
_SECRET_SHAPES = (
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"), "REDACTED"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "REDACTED"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*"), "REDACTED"),
    (
        re.compile(r'("(?:token|access_token|authorization)"\s*:\s*)"[^"]*"', re.IGNORECASE),
        r'\1"REDACTED"',
    ),
    # A third party's personal mail address. Advisory authors sometimes put
    # their own name and private address in the "Reporter" section, and the
    # recordings are committed to a public repository, so keeping one here
    # would republish another researcher's contact details and hand them to
    # every scraper that reads this tree. Being already public is not a reason
    # to copy it.
    #
    # The line is consumer mail domain against organisational: security@ at a
    # vendor or a CNA is a published channel and useful context, so it stays.
    # This rule matches on domain shape and names no individual, which is the
    # same discipline the rest of this module follows.
    (
        re.compile(
            r"[A-Za-z0-9._%+-]+@(?:gmail|googlemail|outlook|hotmail|live|yahoo|ymail"
            r"|icloud|proton|protonmail|gmx|yandex|aol|zoho)\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?",
            re.IGNORECASE,
        ),
        "REDACTED",
    ),
)

#: ``?api_key=``-style query parameters, redacted from recorded request URLs.
_SECRET_PARAMS = re.compile(r"((?:api[_-]?key|apikey|token)=)[^&\s\"\\]+", re.IGNORECASE)

#: Environment variables whose values must never reach a committed recording.
#:
#: ``USERNAME``, ``USER`` and ``LOGNAME`` were here and have been removed. They
#: are not credentials, and scrubbing them by bare substring destroyed recorded
#: third-party data: on the machine that recorded this corpus ``USERNAME`` was
#: the four-letter word ``user``, so every occurrence of that word in a public
#: advisory became ``REDACTED``. That corrupted 1147 places across 120
#: recordings, including 54 CVSS vectors whose ``userInteraction`` key became
#: ``REDACTEDInteraction``, 64 ``github.com/user-attachments/`` URLs, and one
#: Maven coordinate in the scored manifest, which turned it into a package that
#: does not exist. Operator home directories, which are the real leak here, are
#: caught by ``tools/prepublish_scan.py`` instead.
_IDENTITY_VARS = ("GH_TOKEN", "GITHUB_TOKEN")

#: Below this an environment value is too short to be a credential and too
#: likely to be an ordinary word appearing in someone else's data.
_MIN_IDENTITY_LEN = 12


class TransportError(PriorArtError):
    """A request could not be completed. The source then has not answered."""


class CassetteMiss(TransportError):
    """No recording for this request, and the mode forbids making one.

    Failure mode 1. This is deliberately an exception and not an empty body:
    ``gate()`` turns a raising source into a non-answer, which becomes
    ``UNGATED``, which never clears a promotion.
    """


class FetchMode(str, Enum):
    """How a fetcher is allowed to obtain a response."""

    REPLAY = "replay"
    """Recordings only. No socket, no subprocess. The default everywhere."""

    RECORD = "record"
    """Replay a hit; make and store the request on a miss."""

    LIVE = "live"
    """Always re-request, and overwrite the recording. For refreshing a corpus."""


@dataclass(frozen=True)
class Request:
    """One request, in the form that is both issued and recorded.

    ``kind`` is ``"http"`` or ``"gh-graphql"``. The GitHub kind records the real
    GraphQL endpoint as its ``url`` so a reader can re-issue it with their own
    credential, while execution goes through the ``gh`` CLI so that no token
    passes through this process.
    """

    kind: str
    url: str
    method: str = "GET"
    body: dict | None = None

    def canonical(self) -> str:
        return json.dumps(
            {"kind": self.kind, "url": self.url, "method": self.method, "body": self.body},
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def key(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()[:32]

    def rerun(self) -> str:
        """A re-runnable form of this request, for the record."""
        if self.kind == "gh-graphql":
            return "gh api graphql -f query=" + json.dumps((self.body or {}).get("query", ""))
        if self.method == "POST":
            payload = json.dumps(json.dumps(self.body))
            return f"curl -s -X POST -H 'Content-Type: application/json' -d {payload} {self.url}"
        return f"curl -s {self.url}"


@dataclass(frozen=True)
class Recording:
    """A stored request/response pair.

    ``recorded_at`` is the retrieval timestamp a ``PriorArtQuery`` carries. On
    replay it is the time the *recording* was made, never the replay time: a
    replayed answer is old evidence, and the freshness window is entitled to
    say so. See ``docs/prior-art.md``.
    """

    request: Request
    status: int
    body: str
    recorded_at: dt.datetime
    provenance: str = RECORDED

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> dict:
        """Parse the body, or refuse. Failure mode 5: a non-2xx is not rows."""
        if not self.ok:
            raise TransportError(
                f"{self.request.url} answered HTTP {self.status}; a non-2xx response is not a "
                "row count. Recorded body starts: " + self.body[:200]
            )
        try:
            parsed = json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise TransportError(f"{self.request.url} returned unparseable JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise TransportError(
                f"{self.request.url} returned a {type(parsed).__name__}, not a JSON object"
            )
        return parsed

    def as_dict(self) -> dict:
        return {
            "provenance": self.provenance,
            "recorded_at": self.recorded_at.isoformat(),
            "request": {
                "kind": self.request.kind,
                "url": self.request.url,
                "method": self.request.method,
                "body": self.request.body,
            },
            "rerun": self.request.rerun(),
            "response": {"status": self.status, "body": self.body},
        }

    @classmethod
    def from_dict(cls, raw: dict) -> Recording:
        req = raw["request"]
        return cls(
            request=Request(
                kind=req["kind"],
                url=req["url"],
                method=req.get("method", "GET"),
                body=req.get("body"),
            ),
            status=int(raw["response"]["status"]),
            body=raw["response"]["body"],
            recorded_at=dt.datetime.fromisoformat(raw["recorded_at"]),
            provenance=raw.get("provenance", RECORDED),
        )


def scrub(text: str) -> str:
    """Redact token-shaped strings and the authenticated account's identity.

    Failure mode 4. The cassettes are committed to a public repository, so this
    runs on every body and every URL before a write. It is a guard, not a
    substitute for not sending credentials: nothing here ever sets an
    ``Authorization`` header.
    """
    out = _SECRET_PARAMS.sub(r"\1REDACTED", text)
    for shape, replacement in _SECRET_SHAPES:
        out = shape.sub(replacement, out)
    for var in _IDENTITY_VARS:
        value = os.environ.get(var)
        if value and len(value) >= _MIN_IDENTITY_LEN:
            out = out.replace(value, "REDACTED")
    return out


def scrub_body(body: str) -> str:
    """Scrub a response body, and refuse to return one the scrub has broken.

    Redaction runs over the serialised text, so a pattern whose value class is
    one character too greedy can consume the backslash of an escaped quote and
    truncate the JSON string it sits in. That happened: two recordings in this
    repository's own prior-art corpus were committed as invalid JSON and stayed
    that way, because the integrity check hashes bytes and nothing parsed them.
    The replay did the right thing when it finally read them, raising
    ``TransportError`` and dropping that item's coverage confidence instead of
    reporting no prior art. But nothing surfaced it for weeks.

    So: if the body parsed before scrubbing, it must still parse after. A guard
    that changes data without checking its own output is the failure this
    repository is named after.
    """
    scrubbed = scrub(body)
    try:
        json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return scrubbed  # not JSON to begin with; nothing to promise
    try:
        json.loads(scrubbed)
    except json.JSONDecodeError as exc:
        raise PriorArtError(
            "the scrub turned a parseable body into invalid JSON and the recording was not "
            f"written: {exc}. A redaction pattern has eaten a structural character."
        ) from exc
    return scrubbed


class CassetteStore:
    """A directory of recordings, one JSON file per distinct request."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def path_for(self, request: Request) -> Path:
        host = urllib.parse.urlsplit(request.url).hostname or "unknown"
        return self.root / f"{host}-{request.key}.json"

    def load(self, request: Request) -> Recording | None:
        path = self.path_for(request)
        if not path.exists():
            return None
        return Recording.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save(self, recording: Recording) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(recording.request)
        scrubbed = Recording(
            request=Request(
                kind=recording.request.kind,
                url=scrub(recording.request.url),
                method=recording.request.method,
                body=recording.request.body,
            ),
            status=recording.status,
            body=scrub_body(recording.body),
            recorded_at=recording.recorded_at,
            provenance=recording.provenance,
        )
        # newline="\n" is load-bearing, not style. A recording's bytes are
        # hashed into cassettes.index.json and `--check` compares that hash,
        # so the file has to be byte-identical no matter who recorded it.
        # Without this, Python's default newline translation writes CRLF on
        # Windows, git normalises it back to LF on commit, and every hash in
        # the index mismatches on a machine that is not the one that recorded
        # them. That is a measurement whose result depends on the operating
        # system of whoever ran it, which is the thing this repository exists
        # to refuse.
        path.write_text(
            json.dumps(scrubbed.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def count(self) -> int:
        if not self.root.exists():
            return 0
        return sum(1 for _ in self.root.glob("*.json"))


@dataclass
class Fetcher:
    """Issues requests under a mode, a rate limit and a provenance rule."""

    store: CassetteStore
    mode: FetchMode = FetchMode.REPLAY
    #: Seconds to leave between network calls to the same host. NVD without an
    #: API key allows roughly five requests per rolling thirty seconds, so its
    #: source raises this; the default is simply polite.
    min_interval: float = 1.0
    timeout: float = 30.0
    #: Admit ``synthetic`` recordings. Failure mode 3: the measurement never
    #: sets this, so a hand-written body cannot become a published number.
    allow_synthetic: bool = False
    #: Injection points for the two clocks this class reads, so a test can hold
    #: time still instead of racing it. ``stamped`` is the retrieval timestamp
    #: written into a new recording; ``ticked`` is the monotonic reading the
    #: rate limiter spaces calls by. Both are ``None`` in every non-test use,
    #: and the clock is only read when they are.
    stamped: dt.datetime | None = None
    ticked: float | None = None
    _last_call: dict[str, float] = field(default_factory=dict, repr=False)
    network_calls: int = field(default=0, repr=False)

    # ----------------------------------------------------------------- clocks

    def _stamp(self) -> dt.datetime:
        """The retrieval timestamp for a new recording."""
        return self.stamped or dt.datetime.now(dt.timezone.utc)

    def _tick(self) -> float:
        """Monotonic seconds, for the per-host spacing."""
        return self.ticked or time.monotonic()

    def fetch(self, request: Request) -> Recording:
        if self.mode is not FetchMode.LIVE:
            hit = self.store.load(request)
            if hit is not None:
                if hit.provenance != RECORDED and not self.allow_synthetic:
                    raise TransportError(
                        f"the recording for {request.url} is marked provenance="
                        f"{hit.provenance!r}, not {RECORDED!r}. A hand-written body is a "
                        "fault-injection fixture and is not evidence of anything a corpus "
                        "said; pass allow_synthetic=True only in a test."
                    )
                return hit

        if self.mode is FetchMode.REPLAY:
            raise CassetteMiss(
                f"no recording for {request.url} (key {request.key}) in {self.store.root}, and "
                f"mode is {self.mode.value}, so no request was made. This is a missing "
                "recording, not a corpus that answered zero. Re-record with "
                "`python benchmarks/dedup/run_dedup.py --record`.\n  rerun: " + request.rerun()
            )

        recording = self._issue(request)
        self.store.save(recording)
        return recording

    # ------------------------------------------------------------- the network

    def _issue(self, request: Request) -> Recording:
        self._wait(request.url)
        self.network_calls += 1
        if request.kind == "gh-graphql":
            return self._issue_gh(request)
        if request.kind == "http":
            return self._issue_http(request)
        raise TransportError(f"unknown request kind {request.kind!r}")

    def _wait(self, url: str) -> None:
        """Failure mode 5. Space calls to one host; never sleep on a replay."""
        host = urllib.parse.urlsplit(url).hostname or "unknown"
        previous = self._last_call.get(host)
        if previous is not None:
            remaining = self.min_interval - (self._tick() - previous)
            if remaining > 0:
                time.sleep(remaining)
        self._last_call[host] = self._tick()

    def _issue_http(self, request: Request) -> Recording:
        _require_https(request.url)
        data = None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if request.body is not None:
            data = json.dumps(request.body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        # The scheme, host and absence of embedded credentials are checked above.
        issue = urllib.request.Request(
            request.url, data=data, headers=headers, method=request.method
        )
        try:
            with urllib.request.urlopen(issue, timeout=self.timeout) as response:
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", errors="replace")
        except OSError as exc:
            raise TransportError(f"{request.url} unreachable: {type(exc).__name__}: {exc}") from exc
        return Recording(request, status, body, self._stamp(), RECORDED)

    def _issue_gh(self, request: Request) -> Recording:
        """Run a GraphQL query through the ``gh`` CLI.

        ``gh`` holds the credential; this process never reads it, never passes
        it on a command line and never writes it anywhere. On failure the exit
        code is recorded and the stderr is not: failure mode 4, because an
        authentication error names the account.
        """
        query = (request.body or {}).get("query")
        if not query:
            raise TransportError("a gh-graphql request needs a 'query' in its body")
        try:
            # A fixed argv, no shell, and the query passed as one argument.
            completed = subprocess.run(
                ["gh", "api", "graphql", "-f", f"query={query}"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TransportError(f"gh could not be run: {type(exc).__name__}: {exc}") from exc
        if completed.returncode != 0:
            raise TransportError(
                f"gh api graphql exited {completed.returncode}; stderr is withheld from the "
                "record because an authentication failure names the account."
            )
        return Recording(request, 200, completed.stdout, self._stamp(), RECORDED)


def _require_https(url: str) -> None:
    """Failure mode 6. https, a named host, and no embedded credential."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise TransportError(
            f"refusing to fetch {url!r}: only https is allowed. Over plain http anything on "
            "the path can answer, and 'the corpus said zero' would mean 'something said zero'."
        )
    host = parts.hostname or ""
    if not host or parts.username or parts.password:
        raise TransportError(f"refusing to fetch {url!r}: no host, or a credential in the URL")
    # ``urlsplit`` strips the brackets from an IPv6 literal, so the colon is
    # what identifies one here: a DNS hostname never contains a colon once the
    # port has been split off.
    if re.fullmatch(r"[0-9.]+", host) or ":" in host:
        raise TransportError(
            f"refusing to fetch {url!r}: the host is an IP literal, so the certificate cannot "
            "bind the answer to a named corpus."
        )
