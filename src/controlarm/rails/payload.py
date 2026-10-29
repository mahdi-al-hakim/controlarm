"""Deny-by-default on the payload.

``scope`` gates the target you are allowed to send requests *to*. This gates the
URL you hand the target to fetch *for* you, and it is the inverse problem: the
address that matters is the one the remote fetcher resolves, not the one you
typed. A server-side fetcher pointed at a numerically-encoded internal address
is an attack on somebody's private network, and it is still an attack when the
intent was a demonstration.

So the rule is absolute and has no override: a payload URL must resolve, **in
any encoding**, to infrastructure the operator has declared as their own, and
the forbidden ranges are refused even when they are declared.

Numbered defects, all of them faults in the source this was ported from except
4, which is a design gap found while porting:

  1  no IPv6 handling at all                       -> ``[::1]`` and
     ``::ffff:169.254.169.254`` fell through to a generic refusal. That happens
     to be the safe direction, which is luck, not design -- and the same
     fall-through also refused the operator's own IPv6 collector, so the rail
     was unusable on a v6 network and would have been switched off.
  2  no 6to4, NAT64 or IPv4-compatible unwrapping   -> three further ways to
     write an internal IPv4 address in a v6 host.
  3  only four-part dotted forms decoded            -> ``127.1`` and ``192.0.519``
     are accepted by every C resolver and decoded to nothing here.
  4  a zero-padded octet decoded one way            -> ``010`` is 8 to a
     resolver and 10 to a reader. Deciding which one it "really" is means
     proving something about an address the fetcher may not use. Every reading
     is now kept and every reading must be declared.
  5  the loopback and private check ran only after  -> an undeclared-but-private
     an "is this my box" early return                 host was refused for the
     wrong reason, and a *declared* private host was permitted. There is now no
     declaration that can permit a forbidden range.
  6  the refusal echoed the whole URL               -> a payload URL carries a
     nonce, and a nonce in a log is a credential in a log. Only the host and
     the verdict are reported.

Documentation space (RFC 5737, RFC 3849) is deliberately *not* a forbidden
range: it is neither routable nor internal, so it is the natural stand-in for a
collector in tests and examples. It is still refused unless declared, so
nothing is loosened by that choice.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

__all__ = [
    "DOCUMENTATION_NETWORKS",
    "ENV_ADDRESSES",
    "ENV_HOSTNAMES",
    "OwnedInfra",
    "PayloadDecision",
    "PayloadError",
    "PayloadVerdict",
    "assert_own_payload_host",
    "check_payload_host",
    "decode_candidates",
]

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Ranges reserved for documentation. Not global, not internal, not forbidden.
DOCUMENTATION_NETWORKS: tuple[str, ...] = (
    "192.0.2.0/24",  # RFC 5737 TEST-NET-1
    "198.51.100.0/24",  # RFC 5737 TEST-NET-2
    "203.0.113.0/24",  # RFC 5737 TEST-NET-3
    "2001:db8::/32",  # RFC 3849
)
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in DOCUMENTATION_NETWORKS)

ENV_HOSTNAMES = "CONTROLARM_OWNED_HOSTS"
ENV_ADDRESSES = "CONTROLARM_OWNED_ADDRS"

_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")

#: The characters a host field can legally hold, colons included for IPv6.
_HOST_CHARS = re.compile(r"^[a-z0-9.:_-]+$")

#: Names that denote the local machine without being IP literals. A fetcher sent
#: to one of these reaches the *target's* local machine.
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

#: What to do instead. The error text is the documentation: a rail that only
#: says "no" gets switched off by the next person who needs the result.
_GUIDANCE = (
    "Point server-side fetchers only at infrastructure you have declared as your own. "
    "To evidence an internal hop without sending one: demonstrate the decoding step and "
    "external reach against your own declared collector, record both, and argue the "
    "internal reachability from that evidence plus the target's own documentation. "
    "An argued hop is a reportable finding; a sent one is an intrusion."
)


class PayloadError(Exception):
    """Raised when a payload URL is not provably the operator's own, and at
    declaration time when the declaration itself is unusable."""


class PayloadVerdict(str, Enum):
    """Six outcomes. Only the first two permit the fetch."""

    OWNED = "OWNED"
    """Every encoding of the host decodes to a declared address."""

    OWNED_HOSTNAME = "OWNED-HOSTNAME"
    """The host is a declared hostname. Where it resolves is not checked here:
    the core makes no network calls, so this is a declaration, not a proof."""

    NOT_OWNED = "NOT-OWNED"
    """The host decodes to an address, and at least one reading is undeclared."""

    FORBIDDEN_RANGE = "FORBIDDEN-RANGE"
    """The host decodes into loopback, private, link-local, reserved, multicast
    or unspecified space. Refused regardless of any declaration."""

    UNDECODABLE = "UNDECODABLE"
    """Not a declared hostname and not decodable to an address offline. Refused:
    "I could not check" is not "it is fine"."""

    UNPARSEABLE = "UNPARSEABLE"
    """No host could be read out of the URL at all."""


_PERMITTED = frozenset({PayloadVerdict.OWNED, PayloadVerdict.OWNED_HOSTNAME})


@dataclass(frozen=True)
class PayloadDecision:
    verdict: PayloadVerdict
    reason: str
    host: str
    candidates: frozenset[IPAddress] = frozenset()

    @property
    def permitted(self) -> bool:
        return self.verdict in _PERMITTED


@dataclass(frozen=True)
class OwnedInfra:
    """The operator's declaration of what they own.

    Both fields default to empty, so an operator who has declared nothing has no
    valid payload target. A declaration is validated at construction: an address
    in a forbidden range raises here rather than being refused later, because a
    declaration that can never be honoured is a configuration bug and should
    fail at the point it is written.
    """

    hostnames: tuple[str, ...] = ()
    addresses: tuple[IPAddress, ...] = ()
    _lookup: frozenset[IPAddress] = field(default=frozenset(), repr=False, compare=False)

    def __init__(
        self,
        hostnames: Iterable[str] = (),
        addresses: Iterable[IPAddress | str] = (),
    ) -> None:
        names = tuple(_validate_hostname(h) for h in hostnames)
        addrs = tuple(_validate_address(a) for a in addresses)
        object.__setattr__(self, "hostnames", names)
        object.__setattr__(self, "addresses", addrs)
        object.__setattr__(self, "_lookup", frozenset(addrs))

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> OwnedInfra:
        """Read the declaration from the environment.

        Real infrastructure belongs in the environment and never in the source,
        for the same reason a credential does: a repository is a publication.
        """
        source = os.environ if env is None else env
        return cls(
            hostnames=_split(source.get(ENV_HOSTNAMES, "")),
            addresses=_split(source.get(ENV_ADDRESSES, "")),
        )

    def owns_address(self, ip: IPAddress) -> bool:
        return ip in self._lookup

    def owns_hostname(self, host: str) -> bool:
        return host.lower().rstrip(".") in self.hostnames


# ------------------------------------------------------------------- the guard


def check_payload_host(url: str, owned: OwnedInfra) -> PayloadDecision:
    """Classify a payload URL. Reports; does not raise on a refusal."""
    try:
        host = _host_of(url)
    except ValueError as exc:
        return PayloadDecision(PayloadVerdict.UNPARSEABLE, str(exc), "")

    # A declared *name* does not launder the address it denotes, so the range
    # check runs first. Defect 5.
    candidates = decode_candidates(host)
    if host in _LOOPBACK_NAMES:
        return PayloadDecision(
            PayloadVerdict.FORBIDDEN_RANGE,
            f"{host!r} names the loopback interface of whatever machine resolves it, "
            f"which for a server-side fetcher is the target's own. {_GUIDANCE}",
            host,
            candidates,
        )
    for ip in sorted(candidates, key=str):
        forbidden = _forbidden_reason(ip)
        if forbidden:
            return PayloadDecision(
                PayloadVerdict.FORBIDDEN_RANGE,
                f"{host!r} decodes to {ip}, which is {forbidden}. {_GUIDANCE}",
                host,
                candidates,
            )

    if owned.owns_hostname(host):
        return PayloadDecision(
            PayloadVerdict.OWNED_HOSTNAME,
            f"{host!r} is a declared hostname. Note that this rail does not resolve it: "
            "the declaration is the evidence, so keep the declaration true.",
            host,
            candidates,
        )

    if not candidates:
        return PayloadDecision(
            PayloadVerdict.UNDECODABLE,
            f"{host!r} is not a declared hostname and does not decode to an address "
            f"offline, so nothing here proves where a fetcher would go. {_GUIDANCE}",
            host,
            candidates,
        )

    # Every reading must be owned. One undeclared reading is enough to refuse:
    # the fetcher picks the reading, not the operator. Defect 4.
    undeclared = sorted((ip for ip in candidates if not owned.owns_address(ip)), key=str)
    if undeclared:
        return PayloadDecision(
            PayloadVerdict.NOT_OWNED,
            f"{host!r} can be read as {[str(ip) for ip in undeclared]}, which is not "
            f"declared as yours. {_GUIDANCE}",
            host,
            candidates,
        )

    return PayloadDecision(
        PayloadVerdict.OWNED,
        f"{host!r} decodes only to declared addresses {sorted(str(ip) for ip in candidates)}",
        host,
        candidates,
    )


def assert_own_payload_host(url: str, owned: OwnedInfra) -> PayloadDecision:
    """Raise ``PayloadError`` unless the payload URL is provably the operator's.

    There is no override parameter, and the forbidden ranges are not declarable.
    """
    decision = check_payload_host(url, owned)
    if not decision.permitted:
        raise PayloadError(f"COMPLIANCE BLOCK [{decision.verdict.value}]: {decision.reason}")
    return decision


# ----------------------------------------------------------------- the decoder


def decode_candidates(host: str) -> frozenset[IPAddress]:
    """Every address ``host`` could denote, across every encoding.

    An empty set means "not an address literal under any reading", which is a
    refusal and never a pass. A set with more than one member means the host is
    ambiguous, and the guard then requires every member to be declared.
    """
    raw = (host or "").strip().strip("[]")
    if not raw:
        return frozenset()

    out: set[IPAddress] = set()

    # IPv6, including the four ways an IPv4 address hides inside one.
    try:
        v6 = ipaddress.IPv6Address(raw)
    except ValueError:
        pass
    else:
        return frozenset({_unwrap_v6(v6)})

    # Dotted forms. inet_aton semantics: the final part absorbs the remaining
    # octets, so one, two, three and four-part forms are all addresses, and
    # ``127.1`` is loopback. Defect 3.
    parts = raw.split(".")
    if len(parts) > 4:
        return frozenset()
    readings: list[list[int]] = [[]]
    for index, part in enumerate(parts):
        is_last = index == len(parts) - 1
        width = 8 * (4 - len(parts) + 1) if is_last else 8
        values = _part_values(part, width)
        if not values:
            return frozenset()
        readings = [[*reading, value] for reading in readings for value in sorted(values)]

    for reading in readings:
        out.add(ipaddress.IPv4Address(_assemble(reading)))
    return frozenset(out)


def _assemble(reading: list[int]) -> int:
    """Combine octet values under inet_aton's "last part absorbs the rest" rule."""
    leading, last = reading[:-1], reading[-1]
    total = 0
    for value in leading:
        total = (total << 8) | value
    return (total << (8 * (4 - len(reading) + 1))) | last


def _part_values(part: str, width: int) -> set[int]:
    """Decode one dotted part into every value it could hold.

    A leading zero is the ambiguity: C reads it as octal, a human reads it as
    decimal, and both readings are returned. Defect 4.
    """
    text = part.strip()
    if not text:
        return set()
    limit = (1 << width) - 1
    values: set[int] = set()
    lowered = text.lower()
    if lowered.startswith("0x"):
        digits = text[2:]
        if digits and all(c in "0123456789abcdefABCDEF" for c in digits):
            values.add(int(digits, 16))
    elif text.isdigit():
        values.add(int(text, 10))
        if text.startswith("0") and len(text) > 1 and all(c in "01234567" for c in text):
            values.add(int(text, 8))
    return {v for v in values if 0 <= v <= limit}


def _unwrap_v6(v6: ipaddress.IPv6Address) -> IPAddress:
    """Return the IPv4 address embedded in ``v6``, or ``v6`` itself.

    Four embeddings are unwrapped: IPv4-mapped (``::ffff:a.b.c.d``),
    IPv4-compatible (``::a.b.c.d``), 6to4 (``2002:``) and NAT64
    (``64:ff9b::``). Each is a way to write an internal IPv4 address in a host
    field that an IPv4-only check would miss. Defects 1 and 2.
    """
    if v6.ipv4_mapped is not None:
        return v6.ipv4_mapped
    if v6.sixtofour is not None:
        return v6.sixtofour
    packed = v6.packed
    low32 = int.from_bytes(packed[12:], "big")
    # ``::a.b.c.d`` and ``64:ff9b::a.b.c.d``, excluding 0.0.0.0/8 so that ``::``
    # and ``::1`` stay what they are rather than becoming 0.0.0.0 and 0.0.0.1.
    prefix_is_compat = packed[:12] == bytes(12)
    prefix_is_nat64 = packed[:12] == bytes.fromhex("0064ff9b" + "00" * 8)
    if (prefix_is_compat or prefix_is_nat64) and low32 >> 24:
        return ipaddress.IPv4Address(low32)
    return v6


def _forbidden_reason(ip: IPAddress) -> str | None:
    """Name why ``ip`` may never be a payload target, or ``None``.

    Order matters: multicast and some reserved ranges report ``is_global`` as
    true, and ``::1`` is both loopback and reserved, so the most specific and
    most explanatory label has to win.
    """
    if ip.is_multicast:
        return "multicast space"
    if ip.is_loopback:
        return "loopback space -- for a remote fetcher that is the target's own machine"
    if ip.is_link_local:
        return "link-local space, where cloud instance metadata services live"
    if ip.is_unspecified:
        return "the unspecified address"
    if ip.is_reserved:
        return "reserved space"
    if any(ip in net for net in _DOC_NETS):
        return None
    if not ip.is_global:
        return "private or otherwise non-global space"
    return None


# ------------------------------------------------------------------- internals


def _host_of(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        raise ValueError("empty payload URL")
    if "://" in raw:
        candidate = raw
    else:
        try:
            ipaddress.IPv6Address(raw.strip("[]"))
        except ValueError:
            candidate = f"https://{raw}"
        else:
            candidate = f"https://[{raw.strip('[]')}]"
    try:
        host = urlparse(candidate).hostname or ""
    except ValueError as exc:
        raise ValueError(f"could not parse a host out of the payload URL ({exc})") from exc
    host = host.lower().rstrip(".")
    if not host:
        raise ValueError("could not parse a host out of the payload URL")
    if not _HOST_CHARS.match(host):
        # A host carrying a space or a slash is a malformed URL, not an
        # undeclared host. Reporting it as merely undeclared would hide a bug
        # behind a correct-looking refusal.
        raise ValueError("the payload URL's host contains characters a host cannot contain")
    return host


def _split(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _validate_hostname(host: str) -> str:
    if not isinstance(host, str):
        raise PayloadError(f"declared hostname must be a string, got {type(host).__name__}")
    value = host.strip().lower().rstrip(".")
    if not value or not _HOSTNAME.match(value):
        raise PayloadError(
            f"declared hostname {host!r} is not a bare hostname. Declare a host, not a URL: "
            "a scheme, a port or a path in a declaration is a configuration error."
        )
    return value


def _validate_address(value: IPAddress | str) -> IPAddress:
    try:
        ip = ipaddress.ip_address(value if isinstance(value, int) else str(value).strip())
    except ValueError as exc:
        raise PayloadError(f"declared address {value!r} is not an IP address ({exc})") from exc
    forbidden = _forbidden_reason(ip)
    if forbidden:
        raise PayloadError(
            f"declared address {ip} is in {forbidden}, which can never be a valid payload "
            f"target. There is no flag for this. {_GUIDANCE}"
        )
    return ip
