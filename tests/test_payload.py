"""Tests for the payload rail.

The rail's claim is narrow and absolute: *a URL handed to a remote fetcher must
resolve, in any encoding, to infrastructure the operator has declared as their
own.* The tests are therefore mostly an encoding table, because the only way
this rail fails is a form it did not decode.

Every IPv4 and IPv6 literal below is RFC 5737 / RFC 3849 documentation space or
an RFC 3330 special-use range. ``192.0.2.7`` stands in for "the operator's own
declared collector" and ``198.51.100.9`` for "somebody else's host"; neither is
reachable and neither names real infrastructure.
"""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest

from controlarm.rails.payload import (
    DOCUMENTATION_NETWORKS,
    OwnedInfra,
    PayloadDecision,
    PayloadError,
    PayloadVerdict,
    assert_own_payload_host,
    check_payload_host,
    decode_candidates,
)

OWN = ipaddress.IPv4Address("192.0.2.7")
OTHER = ipaddress.IPv4Address("198.51.100.9")

OWN_DECIMAL = str(int(OWN))  # 3221225991
OWN_HEX = f"0x{int(OWN):08x}"  # 0xc0000207
OWN_OCTAL = f"0{int(OWN):o}"


def owned(**kwargs) -> OwnedInfra:
    base = {"hostnames": ("collector.example",), "addresses": (OWN,)}
    base.update(kwargs)
    return OwnedInfra(**base)


def verdict_for(url: str, infra: OwnedInfra | None = None) -> PayloadVerdict:
    return check_payload_host(url, infra or owned()).verdict


# ---------------------------------------------------------------- the decoder


@pytest.mark.parametrize(
    "host",
    [
        "192.0.2.7",  # dotted decimal
        "192.000.002.007",  # zero-padded, both readings agree
        OWN_DECIMAL,  # a single 32-bit decimal
        OWN_HEX,  # a single 0x integer
        OWN_HEX.upper().replace("0X", "0x"),  # case does not matter
        "0xc0.0x0.0x2.0x7",  # per-octet hex
        "0300.0.2.7",  # per-octet octal
        "0300.0x0.02.07",  # mixed radix, one octet each
        "192.0.519",  # three parts: the last is 16 bits
        "192.519",  # two parts: the last is 24 bits
        "0300.519",  # mixed, two parts
        "::ffff:192.0.2.7",  # IPv4-mapped IPv6
        "::ffff:c000:207",  # the same, written in hextets
        "0:0:0:0:0:ffff:c000:0207",  # the same, fully expanded
        "::192.0.2.7",  # IPv4-compatible IPv6 (deprecated, still decoded)
        "[::ffff:192.0.2.7]",  # bracketed
        "2002:c000:207::",  # 6to4
        "64:ff9b::192.0.2.7",  # NAT64
    ],
)
def test_every_encoding_of_one_address_decodes_to_that_address(host):
    """ADDED over the source, which handled only the first eight of these.

    The source's IPv6 gap was described in the inventory as "the safe direction,
    but luck rather than design": an unrecognised host fell through to a generic
    refusal. Luck is not a property a rail can claim, and the same fall-through
    also refused the operator's own IPv6 collector.
    """
    assert decode_candidates(host) == frozenset({OWN}), f"{host} did not decode to {OWN}"


def test_a_zero_padded_octet_is_ambiguous_and_both_readings_are_kept():
    """``010`` is 8 to a C resolver and 10 to a human. The rail keeps both.

    Picking one reading would mean the guard proves something about an address
    the fetcher may not use. Keeping both, and requiring every candidate to be
    declared, is the only fail-closed answer available.
    """
    assert decode_candidates("192.0.2.010") == frozenset(
        {ipaddress.IPv4Address("192.0.2.8"), ipaddress.IPv4Address("192.0.2.10")}
    )


def test_an_ambiguous_host_is_refused_when_only_one_reading_is_declared():
    assert verdict_for("https://192.0.2.010/cb") is PayloadVerdict.NOT_OWNED


def test_an_ambiguous_host_is_accepted_only_when_every_reading_is_declared():
    both = owned(
        addresses=(ipaddress.IPv4Address("192.0.2.8"), ipaddress.IPv4Address("192.0.2.10"))
    )
    assert verdict_for("https://192.0.2.010/cb", both) is PayloadVerdict.OWNED


@pytest.mark.parametrize(
    "host",
    [
        "collector.example",
        "not-an-address",
        "999.0.2.7",
        "192.0.2.256",
        "192.0.2.7.8",
        "0x1c0000207",
        "4294967296",
        "-1",
        "192.0.2.",
        "0x",
        "",
        "::1::2",
    ],
)
def test_a_non_numeric_or_out_of_range_host_decodes_to_nothing(host):
    assert decode_candidates(host) == frozenset()


@pytest.mark.parametrize("host", ["::1", "::"])
def test_the_ipv4_compatible_unwrap_does_not_swallow_loopback_or_unspecified(host):
    """``::1`` is loopback, not ``0.0.0.1``. A careless ::/96 unwrap loses that."""
    decoded = decode_candidates(host)
    assert decoded == frozenset({ipaddress.IPv6Address(host)})


def test_decoding_is_a_set_so_a_caller_cannot_mutate_it():
    assert isinstance(decode_candidates("192.0.2.7"), frozenset)


# --------------------------------------------------------- the forbidden ranges


@pytest.mark.parametrize(
    "host,expected_phrase",
    [
        ("127.0.0.1", "loopback"),
        ("localhost", "loopback"),
        ("10.0.0.1", "non-global"),
        ("172.16.0.1", "non-global"),
        ("192.168.1.1", "non-global"),
        ("169.254.169.254", "link-local"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("[::1]", "loopback"),
        ("[fe80::1]", "link-local"),
        ("[fc00::1]", "non-global"),
        ("[ff02::1]", "multicast"),
        ("2130706433", "loopback"),  # 127.0.0.1 as a decimal
        ("0x7f000001", "loopback"),  # and as hex
        ("0177.0.0.1", "loopback"),  # and with an octal first octet
        ("[::ffff:169.254.169.254]", "link-local"),  # metadata, IPv4-mapped
        ("[64:ff9b::10.0.0.1]", "non-global"),  # metadata-adjacent, via NAT64
    ],
)
def test_a_forbidden_range_is_refused_in_every_encoding(host, expected_phrase):
    decision = check_payload_host(f"https://{host}/cb", owned())
    assert decision.verdict is PayloadVerdict.FORBIDDEN_RANGE
    assert expected_phrase in decision.reason


def test_a_forbidden_range_cannot_be_declared_as_owned_infrastructure():
    """There is no flag for this. A fetcher pointed at loopback reaches the
    *target's* loopback, which is the internal hop the rail exists to refuse."""
    with pytest.raises(PayloadError) as exc:
        owned(addresses=(ipaddress.IPv4Address("127.0.0.1"),))
    assert "loopback" in str(exc.value)


def test_a_forbidden_range_beats_a_declared_hostname():
    """Declaring the *name* does not launder the address it decodes to."""
    decision = check_payload_host("https://127.0.0.1/cb", owned(hostnames=("127.0.0.1",)))
    assert decision.verdict is PayloadVerdict.FORBIDDEN_RANGE


def test_documentation_space_is_not_a_forbidden_range_but_still_needs_declaring():
    """Documentation space is neither routable nor internal, so it is not
    refused outright -- but it is refused unless declared, like anything else."""
    assert verdict_for("https://203.0.113.5/cb") is PayloadVerdict.NOT_OWNED
    assert all(ipaddress.ip_network(n) for n in DOCUMENTATION_NETWORKS)


# ------------------------------------------------------------------ the ladder


def test_a_declared_hostname_is_owned():
    decision = check_payload_host("https://collector.example/cb?n=1", owned())
    assert decision.verdict is PayloadVerdict.OWNED_HOSTNAME
    assert "declared" in decision.reason


def test_a_declared_hostname_match_is_exact_and_case_insensitive():
    assert verdict_for("https://COLLECTOR.Example/cb") is PayloadVerdict.OWNED_HOSTNAME
    assert verdict_for("https://evil-collector.example/cb") is PayloadVerdict.UNDECODABLE
    assert verdict_for("https://collector.example.other/cb") is PayloadVerdict.UNDECODABLE


def test_a_declared_address_is_owned_in_any_encoding():
    for host in ["192.0.2.7", OWN_DECIMAL, OWN_HEX, OWN_OCTAL, "0300.0.2.7", "[::ffff:192.0.2.7]"]:
        assert verdict_for(f"https://{host}/cb") is PayloadVerdict.OWNED, host


def test_an_unbracketed_ipv6_host_in_a_url_is_malformed_not_undeclared():
    """``https://::1/`` is not a URL. Saying so beats reporting it as unowned."""
    assert verdict_for("https://::ffff:192.0.2.7/cb") is PayloadVerdict.UNPARSEABLE


def test_an_undeclared_global_address_is_not_owned():
    assert verdict_for(f"https://{OTHER}/cb") is PayloadVerdict.NOT_OWNED


def test_an_undecodable_undeclared_host_fails_closed():
    """A name the rail cannot resolve offline is refused, not resolved.

    The core does no network calls, so a bare hostname carries no proof about
    where it points. "I could not check" is not "it is fine"."""
    assert verdict_for("https://some-host.example/cb") is PayloadVerdict.UNDECODABLE


@pytest.mark.parametrize("url", ["", "   ", "https://", "https:///cb", "not a url at all/x"])
def test_an_unparseable_url_is_refused_rather_than_skipped(url):
    assert verdict_for(url) is PayloadVerdict.UNPARSEABLE


def test_an_empty_declaration_owns_nothing():
    """Deny-by-default: an operator who has declared no infrastructure has no
    valid payload target at all, including documentation space."""
    nothing = OwnedInfra()
    assert verdict_for("https://192.0.2.7/cb", nothing) is PayloadVerdict.NOT_OWNED
    assert verdict_for("https://collector.example/cb", nothing) is PayloadVerdict.UNDECODABLE


# --------------------------------------------------------------- the assertion


def test_assert_passes_for_declared_infrastructure():
    assert_own_payload_host("https://collector.example/cb", owned())
    assert_own_payload_host("https://192.0.2.7/cb", owned())


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/",
        "https://198.51.100.9/cb",
        "https://some-host.example/cb",
        "",
    ],
)
def test_assert_raises_on_everything_else(url):
    with pytest.raises(PayloadError):
        assert_own_payload_host(url, owned())


def test_the_refusal_says_what_evidence_to_gather_instead():
    """The error text is the documentation. A rail that only says "no" gets
    disabled by the next person who needs the result."""
    with pytest.raises(PayloadError) as exc:
        assert_own_payload_host("https://169.254.169.254/latest/meta-data/", owned())
    message = str(exc.value)
    assert "COMPLIANCE BLOCK" in message
    assert "declared" in message
    assert "decode" in message and "reach" in message


def test_the_refusal_never_quotes_a_credential_or_a_query_string():
    """A payload URL routinely carries a nonce or a token. The refusal reports
    the host and the verdict, and nothing from the rest of the URL."""
    with pytest.raises(PayloadError) as exc:
        assert_own_payload_host("https://198.51.100.9/cb?nonce=SHOULD-NOT-APPEAR", owned())
    assert "SHOULD-NOT-APPEAR" not in str(exc.value)


# -------------------------------------------------------------- the declaration


def test_owned_infra_is_immutable():
    infra = owned()
    with pytest.raises(dataclasses.FrozenInstanceError):
        infra.hostnames = ()  # type: ignore[misc]


def test_a_decision_is_immutable():
    decision = check_payload_host("https://192.0.2.7/cb", owned())
    assert isinstance(decision, PayloadDecision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.verdict = PayloadVerdict.OWNED  # type: ignore[misc]


def test_a_declaration_can_be_read_from_the_environment(monkeypatch):
    """Real infrastructure belongs in the environment, never in the source."""
    monkeypatch.setenv("CONTROLARM_OWNED_HOSTS", "collector.example, other.example")
    monkeypatch.setenv("CONTROLARM_OWNED_ADDRS", "192.0.2.7")
    infra = OwnedInfra.from_env()
    assert infra.hostnames == ("collector.example", "other.example")
    assert infra.addresses == (OWN,)


def test_an_absent_environment_declaration_owns_nothing(monkeypatch):
    monkeypatch.delenv("CONTROLARM_OWNED_HOSTS", raising=False)
    monkeypatch.delenv("CONTROLARM_OWNED_ADDRS", raising=False)
    infra = OwnedInfra.from_env()
    assert infra.hostnames == () and infra.addresses == ()
    assert verdict_for("https://192.0.2.7/cb", infra) is PayloadVerdict.NOT_OWNED


def test_a_malformed_environment_declaration_fails_loudly(monkeypatch):
    monkeypatch.setenv("CONTROLARM_OWNED_ADDRS", "not-an-address")
    with pytest.raises(PayloadError):
        OwnedInfra.from_env()


def test_a_declared_hostname_is_validated(monkeypatch):
    monkeypatch.setenv("CONTROLARM_OWNED_HOSTS", "https://collector.example/cb")
    with pytest.raises(PayloadError):
        OwnedInfra.from_env()


def test_every_verdict_is_exercised_by_this_file():
    """A verdict nothing produces is a verdict nothing tests."""
    produced = {
        verdict_for("https://collector.example/cb"),
        verdict_for("https://192.0.2.7/cb"),
        verdict_for("https://198.51.100.9/cb"),
        verdict_for("https://127.0.0.1/cb"),
        verdict_for("https://some-host.example/cb"),
        verdict_for(""),
    }
    assert produced == set(PayloadVerdict)
