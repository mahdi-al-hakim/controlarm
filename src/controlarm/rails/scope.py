"""Deny-by-default on the target.

A scope file is a claim about the world: *these hosts, and no others, may be
touched, and this claim was checked on this date.* Treating it as configuration
rather than as a claim is how a rail fails open.

Each guard here exists because a specific wrong verdict was once produced. The
numbered defects are kept in the source so a guard cannot be removed without
removing its justification. Defects 1, 2, 3, 5 and 6 are faults found in the
source this module was ported from; defect 4 is a vocabulary error found in the
surrounding method rather than in the code:

  1  ``entry.lstrip("*.")`` used as a prefix strip   -> ``str.lstrip`` takes a
     character *set*, so an entry of ``*.*.example`` collapses to the bare
     suffix ``example`` and the allowlist silently widens. Closed twice: the
     matcher uses ``removeprefix``, and the schema refuses the shape outright.
  2  the freshness check ran only in ``__main__``    -> every programmatic
     caller skipped it, so the file's one claim about the world went unchecked
     on the only code path anybody used.
  3  loopback allowed unconditionally                -> correct for a local
     fixture rig, wrong everywhere else, and an undeclared policy either way.
     It is now a field in the scope file.
  4  a denial folded into the negative band          -> "we were not allowed to
     test it" became "we tested it and found nothing". ``BLOCKED`` is a distinct
     verdict and carries ``is_result = False``.
  5  a YAML loader with no schema                    -> a mistyped
     ``out_of_scope`` key read as "no exclusions at all", which is the fail-open
     direction, and failed late and confusingly rather than at load time.
  6  a hardcoded scope path                          -> no override, so a test
     rig and a live rig could not be kept apart.

The file format is strict JSON, documented in ``ScopeFile``. It is deliberately
not YAML: the core is stdlib-only, and a rail that refuses unsupported claims
should not need a dependency tree to read its own configuration.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

__all__ = [
    "DEFAULT_MAX_AGE_DAYS",
    "LOOPBACK_NAMES",
    "ScopeConfigError",
    "ScopeDecision",
    "ScopeEntry",
    "ScopeError",
    "ScopeFile",
    "ScopeGuard",
    "ScopeTrust",
    "ScopeVerdict",
    "host_matches",
    "host_of",
]

#: Seven days. A bug-bounty scope page changes without notice; a week-old copy of
#: one is an assertion about last week.
DEFAULT_MAX_AGE_DAYS = 7

#: Names that denote the local machine without being IP literals.
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

#: One DNS label: letters, digits and interior hyphens. Deliberately strict --
#: an underscore, a space or a stray ``*`` in a scope entry is a typo, and a typo
#: in an allowlist is the failure this module exists to prevent.
_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")

_WILDCARD = "*."


class ScopeError(Exception):
    """Raised when a target is not provably in scope, or the scope is untrusted."""


class ScopeConfigError(Exception):
    """Raised when the scope file is malformed. Always raised at load time."""


class ScopeVerdict(str, Enum):
    """Two verdicts, and the second one is not a negative result."""

    IN_SCOPE = "IN-SCOPE"
    """The target is explicitly listed and not explicitly excluded."""

    BLOCKED = "BLOCKED"
    """The target may not be touched. This is the absence of a test, not the
    absence of a finding, and nothing downstream may read it as a negative."""


class ScopeTrust(str, Enum):
    """Whether the scope file's own claim about the world still holds."""

    VERIFIED = "verified"
    """Reconciled against a cited source within ``max_age_days``."""

    STALE = "stale"
    """Reconciled, but longer ago than the file's own freshness window."""

    UNVERIFIED = "unverified"
    """Never reconciled, or stamped with a date that is not usable."""


@dataclass(frozen=True)
class ScopeEntry:
    host: str
    allow_subdomains: bool = False
    notes: str = ""


@dataclass(frozen=True)
class ScopeDecision:
    verdict: ScopeVerdict
    reason: str
    trust: ScopeTrust
    host: str

    @property
    def trusted(self) -> bool:
        return self.trust is ScopeTrust.VERIFIED

    @property
    def is_result(self) -> bool:
        """False for ``BLOCKED``. Defect 4: a block is not a measurement."""
        return self.verdict is not ScopeVerdict.BLOCKED


@dataclass(frozen=True)
class ScopeFile:
    """The scope file, validated.

    The format is a strict JSON object. Unknown keys are refused rather than
    ignored, because the characteristic failure of a lenient loader is that a
    mistyped exclusion list reads as an empty one::

        {
          "last_verified": "2026-10-25",   required; an ISO date or null
          "max_age_days": 7,               optional, positive int
          "allow_loopback": false,         optional; defect 3
          "in_scope":     [{"host": "api.example",
                            "allow_subdomains": true,
                            "notes": "free text"}],
          "out_of_scope": [{"host": "internal.example"}]
        }

    ``in_scope`` is required *and may be empty*, and an empty list denies
    everything. Requiring the key keeps "I have not filled this in yet" and "I
    have decided nothing is in scope" apart.
    """

    last_verified: dt.date | None
    in_scope: tuple[ScopeEntry, ...]
    out_of_scope: tuple[ScopeEntry, ...] = ()
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    allow_loopback: bool = False
    source: str = "<text>"

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_path(cls, path: str | Path) -> ScopeFile:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise ScopeConfigError(f"scope file unreadable: {p} ({exc})") from exc
        return cls.from_text(text, source=str(p))

    @classmethod
    def from_text(cls, text: str, source: str = "<text>") -> ScopeFile:
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise ScopeConfigError(f"{source}: not valid JSON ({exc})") from exc
        if not isinstance(raw, dict):
            raise ScopeConfigError(f"{source}: top level must be a JSON object, got {_kind(raw)}")

        known = {"last_verified", "max_age_days", "allow_loopback", "in_scope", "out_of_scope"}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise ScopeConfigError(
                f"{source}: unknown key(s) {unknown}. A mistyped key would be read as a "
                f"default, and the default for an exclusion list is 'no exclusions'. "
                f"Known keys: {sorted(known)}"
            )
        for required in ("last_verified", "in_scope"):
            if required not in raw:
                raise ScopeConfigError(
                    f"{source}: missing required key {required!r}. A scope file is an "
                    "assertion; an omitted assertion is an unfinished file, not a cautious one."
                )

        return cls(
            last_verified=_date_or_none(raw["last_verified"], source),
            in_scope=_entries(raw["in_scope"], "in_scope", source),
            out_of_scope=_entries(raw.get("out_of_scope", []), "out_of_scope", source),
            max_age_days=_positive_int(raw.get("max_age_days", DEFAULT_MAX_AGE_DAYS), source),
            allow_loopback=_bool(raw.get("allow_loopback", False), "allow_loopback", source),
            source=source,
        )

    # ------------------------------------------------------------------ freshness

    def trust_on(self, today: dt.date) -> tuple[ScopeTrust, str]:
        """Classify the file's own freshness. Defect 2: this runs on every check."""
        if self.last_verified is None:
            return (
                ScopeTrust.UNVERIFIED,
                f"{self.source}: last_verified is null, so the allowlist has never been "
                "reconciled against a cited source. Treat every result from this run as "
                "untrusted.",
            )
        age = (today - self.last_verified).days
        if age < 0:
            return (
                ScopeTrust.UNVERIFIED,
                f"{self.source}: last_verified is {-age} day(s) in the future. A clock that "
                "reads forward is a broken instrument, not a fresh scope file. Treat every "
                "result from this run as untrusted.",
            )
        if age > self.max_age_days:
            return (
                ScopeTrust.STALE,
                f"{self.source}: scope last verified {age} day(s) ago, window is "
                f"{self.max_age_days}. Re-reconcile against the published scope before "
                "testing. Treat every result from this run as untrusted.",
            )
        return (ScopeTrust.VERIFIED, f"{self.source}: scope verified {age} day(s) ago")


@dataclass(frozen=True)
class ScopeGuard:
    """Deny-by-default target rail.

    ``check`` reports; ``assert_in_scope`` refuses. The split exists so a CLI can
    print a reason for a denial without the denial having to be an exception, and
    so the refusal path has no override parameter to reach for.
    """

    scope: ScopeFile
    today: dt.date | None = None

    def _today(self) -> dt.date:
        return self.today or dt.date.today()

    def check(self, target: str) -> ScopeDecision:
        host = host_of(target)
        trust, trust_reason = self.scope.trust_on(self._today())
        suffix = "" if trust is ScopeTrust.VERIFIED else f" [{trust_reason}]"

        # Out-of-scope wins over everything, including the loopback declaration.
        # A carve-out is the one statement in the file that is never overridden.
        for entry in self.scope.out_of_scope:
            if host_matches(host, entry.host, entry.allow_subdomains):
                note = f" ({entry.notes})" if entry.notes else ""
                return ScopeDecision(
                    ScopeVerdict.BLOCKED,
                    f"explicitly OUT of scope via {entry.host}{note}",
                    trust,
                    host,
                )

        # An empty allowlist denies everything, and "everything" includes the
        # operator's own fixtures. The alternative reading -- vacuous truth, so
        # allow all -- is the single most common way this rail is written wrong.
        if not self.scope.in_scope:
            return ScopeDecision(
                ScopeVerdict.BLOCKED,
                f"{self.scope.source}: in_scope is EMPTY, so every target is denied, "
                "including loopback. Populate it from the published scope and stamp "
                "last_verified before touching any asset.",
                trust,
                host,
            )

        if self.scope.allow_loopback and _is_loopback(host):
            return ScopeDecision(
                ScopeVerdict.IN_SCOPE,
                f"loopback, allowed by the scope file's allow_loopback declaration{suffix}",
                trust,
                host,
            )

        for entry in self.scope.in_scope:
            if host_matches(host, entry.host, entry.allow_subdomains):
                note = f" (NOTE: {entry.notes})" if entry.notes else ""
                return ScopeDecision(
                    ScopeVerdict.IN_SCOPE,
                    f"in scope via {entry.host}{note}{suffix}",
                    trust,
                    host,
                )

        return ScopeDecision(
            ScopeVerdict.BLOCKED,
            f"{host} is not listed in {self.scope.source} in_scope -- denied by default",
            trust,
            host,
        )

    def assert_in_scope(self, target: str) -> ScopeDecision:
        """Raise ``ScopeError`` unless the target is in scope under a trusted file.

        There is no override parameter. An untrusted scope file is refused for the
        same reason a dead rig voids a run: the instrument's own calibration is
        the precondition for believing anything it says.
        """
        decision = self.check(target)
        if decision.verdict is ScopeVerdict.BLOCKED:
            raise ScopeError(f"BLOCKED: {target} -> {decision.reason}")
        if not decision.trusted:
            _, reason = self.scope.trust_on(self._today())
            raise ScopeError(f"BLOCKED: {target} is in scope, but the scope file is {reason}")
        return decision


# ------------------------------------------------------------------- primitives


def host_of(target: str) -> str:
    """Extract a lowercase host from a URL or a bare host.

    Raises rather than returning an empty string: an unparseable target is a
    broken call, and reporting it as "not in scope" would hide a bug behind a
    correct-looking denial.
    """
    raw = (target or "").strip()
    if not raw:
        raise ScopeError("empty target")
    if "://" in raw:
        candidate = raw
    elif _is_bare_ipv6(raw):
        # A bare ``::1`` has to be bracketed before a URL parser will read it as
        # a host rather than as a scheme-and-port. Without this a loopback v6
        # literal is rejected as unparseable, which looks exactly like a denial.
        candidate = f"https://[{raw}]"
    else:
        candidate = f"https://{raw}"
    try:
        host = urlparse(candidate).hostname or ""
    except ValueError as exc:
        raise ScopeError(f"could not parse host from {target!r}: {exc}") from exc
    host = host.lower().strip(".")
    if not host:
        raise ScopeError(f"could not parse host from {target!r}")
    return host


def host_matches(host: str, entry_host: str, allow_subdomains: bool) -> bool:
    """Does ``host`` match a scope entry?

    Defect 1 lives here. ``removeprefix`` strips the literal two-character
    wildcard prefix; ``lstrip("*.")`` strips any leading run of ``*`` and ``.``
    characters, which turns a malformed entry into a working and much broader one.
    """
    entry = entry_host.lower().removeprefix(_WILDCARD).strip(".")
    if not entry:
        return False
    if host == entry:
        return True
    return bool(allow_subdomains and host.endswith("." + entry))


def _is_bare_ipv6(raw: str) -> bool:
    try:
        ipaddress.IPv6Address(raw)
    except ValueError:
        return False
    return True


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- schema helpers


def _kind(value: Any) -> str:
    return type(value).__name__


def _bool(value: Any, key: str, source: str) -> bool:
    if not isinstance(value, bool):
        raise ScopeConfigError(f"{source}: {key} must be true or false, got {_kind(value)}")
    return value


def _positive_int(value: Any, source: str) -> int:
    # bool is a subclass of int, and ``"max_age_days": true`` is a typo, not a 1.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ScopeConfigError(f"{source}: max_age_days must be a positive integer, got {value!r}")
    return value


def _date_or_none(value: Any, source: str) -> dt.date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScopeConfigError(
            f"{source}: last_verified must be an ISO date string or null, got {_kind(value)}"
        )
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise ScopeConfigError(
            f"{source}: last_verified is not an ISO-8601 date: {value!r} ({exc})"
        ) from exc


def _entries(value: Any, key: str, source: str) -> tuple[ScopeEntry, ...]:
    if not isinstance(value, list):
        raise ScopeConfigError(f"{source}: {key} must be a list, got {_kind(value)}")
    out = []
    for i, item in enumerate(value):
        where = f"{source}: {key}[{i}]"
        if not isinstance(item, dict):
            raise ScopeConfigError(f"{where} must be an object with a host key, got {_kind(item)}")
        unknown = sorted(set(item) - {"host", "allow_subdomains", "notes"})
        if unknown:
            raise ScopeConfigError(f"{where}: unknown key(s) {unknown}")
        if "host" not in item:
            raise ScopeConfigError(f"{where}: missing required key 'host'")
        host = item["host"]
        if not isinstance(host, str):
            raise ScopeConfigError(f"{where}: host must be a string, got {_kind(host)}")
        notes = item.get("notes", "")
        if not isinstance(notes, str):
            raise ScopeConfigError(f"{where}: notes must be a string, got {_kind(notes)}")
        out.append(
            ScopeEntry(
                host=_validate_host(host, where),
                allow_subdomains=_bool(
                    item.get("allow_subdomains", False), "allow_subdomains", where
                ),
                notes=notes,
            )
        )
    return tuple(out)


def _validate_host(host: str, where: str) -> str:
    """Accept one hostname, one IP literal, or a single ``*.`` wildcard prefix.

    Defect 1, closed a second time. ``*.*.example`` and ``*api.example`` are
    refused here, so the matcher is never asked to interpret a shape whose
    interpretation is the bug.
    """
    value = host.strip().lower().rstrip(".")
    if not value:
        raise ScopeConfigError(f"{where}: host is empty")
    body = value.removeprefix(_WILDCARD)
    if "*" in body:
        raise ScopeConfigError(
            f"{where}: host {host!r} may carry at most one leading '*.' wildcard. "
            "A '*' anywhere else is a typo, and a typo in an allowlist widens it."
        )
    try:
        ipaddress.ip_address(body)
    except ValueError:
        if not _HOSTNAME.match(body):
            raise ScopeConfigError(
                f"{where}: host {host!r} is not a hostname, an IP literal, or '*.' plus one"
            ) from None
    return value
