"""Tests for the target rail.

Every test here corresponds to a way a scope guard has been seen to fail open:
a wildcard entry that silently widened, a freshness check that only the CLI ran,
a loopback exemption nobody declared, and a denial folded into the negative band
so that "we were not allowed to test it" became "we tested it and found nothing".

Every IPv4 literal in this file is RFC 5737 documentation space, RFC 3330
special-use space, or loopback. Nothing here names or addresses a real host.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json

import pytest

from controlarm.rails.scope import (
    DEFAULT_MAX_AGE_DAYS,
    ScopeConfigError,
    ScopeDecision,
    ScopeEntry,
    ScopeError,
    ScopeFile,
    ScopeGuard,
    ScopeTrust,
    ScopeVerdict,
    host_matches,
    host_of,
)

TODAY = dt.date(2026, 10, 25)
FRESH = (TODAY - dt.timedelta(days=1)).isoformat()
STALE = (TODAY - dt.timedelta(days=DEFAULT_MAX_AGE_DAYS + 1)).isoformat()


def scope_text(**overrides) -> str:
    body = {
        "last_verified": FRESH,
        "in_scope": [{"host": "api.example", "allow_subdomains": True}],
    }
    body.update(overrides)
    return json.dumps(body)


def guard(**overrides) -> ScopeGuard:
    return ScopeGuard(ScopeFile.from_text(scope_text(**overrides)), today=TODAY)


# ------------------------------------------------------------------ host parsing


@pytest.mark.parametrize(
    "target,expected",
    [
        ("https://api.example/v1/x", "api.example"),
        ("api.example", "api.example"),
        ("API.Example", "api.example"),
        ("api.example.", "api.example"),
        ("https://api.example:8443/x?q=1", "api.example"),
        ("http://127.0.0.1:9000/hits", "127.0.0.1"),
        ("https://[::1]:9000/hits", "::1"),
    ],
)
def test_host_of(target, expected):
    assert host_of(target) == expected


@pytest.mark.parametrize("target", ["", "   ", "https://", "https:///path", "::::"])
def test_host_of_refuses_what_it_cannot_parse(target):
    """An unparseable target is not an out-of-scope target; it is a broken call."""
    with pytest.raises(ScopeError):
        host_of(target)


# ------------------------------------------------------- the wildcard prefix bug


def test_wildcard_prefix_is_a_prefix_not_a_character_set():
    """Defect 1. ``lstrip("*.")`` deletes a *run* of ``*`` and ``.`` characters.

    An entry of ``*.*.example`` -- a realistic copy-paste from a scope page --
    collapses under ``lstrip`` to the bare suffix ``example``, which then matches
    every host under it. The allowlist silently widens, which is the one direction
    a deny-by-default rail must never fail in.
    """
    assert not host_matches("xx.example", "*.*.example", allow_subdomains=True)
    assert not host_matches("anything.example", "*.*.example", allow_subdomains=True)


def test_wildcard_prefix_still_works_for_the_well_formed_shape():
    assert host_matches("a.api.example", "*.api.example", allow_subdomains=True)
    assert host_matches("api.example", "*.api.example", allow_subdomains=True)


def test_a_malformed_host_entry_is_rejected_by_the_schema():
    """The same defect, closed a second time: the shape never reaches the matcher."""
    for bad in ["*.*.example", "*api.example", "api.*.example", "ap i.example", ""]:
        with pytest.raises(ScopeConfigError):
            ScopeFile.from_text(scope_text(in_scope=[{"host": bad}]))


def test_subdomains_are_not_matched_without_the_flag():
    assert host_matches("api.example", "api.example", allow_subdomains=False)
    assert not host_matches("a.api.example", "api.example", allow_subdomains=False)


def test_a_suffix_that_is_not_a_label_boundary_does_not_match():
    """``notapi.example`` must not match ``api.example``: it is a different host."""
    assert not host_matches("notapi.example", "api.example", allow_subdomains=True)


# --------------------------------------------------------------- the deny ladder


def test_an_unlisted_target_is_blocked():
    decision = guard().check("https://other.example/x")
    assert decision.verdict is ScopeVerdict.BLOCKED
    assert "denied by default" in decision.reason


def test_out_of_scope_beats_in_scope():
    """Both lists match; the denial must win regardless of ordering or specificity."""
    decision = guard(
        in_scope=[{"host": "api.example", "allow_subdomains": True}],
        out_of_scope=[{"host": "api.example", "allow_subdomains": True, "notes": "carve-out"}],
    ).check("https://a.api.example/x")
    assert decision.verdict is ScopeVerdict.BLOCKED
    assert "explicitly OUT of scope" in decision.reason


def test_an_empty_allowlist_denies_everything():
    decision = guard(in_scope=[]).check("https://api.example/x")
    assert decision.verdict is ScopeVerdict.BLOCKED
    assert "EMPTY" in decision.reason


def test_an_empty_allowlist_denies_loopback_too():
    """Defect 3, hardest case. ``everything`` includes the operator's own fixtures."""
    decision = guard(in_scope=[], allow_loopback=True).check("http://127.0.0.1:9000/")
    assert decision.verdict is ScopeVerdict.BLOCKED


def test_an_in_scope_target_is_allowed():
    decision = guard().check("https://a.api.example/v1")
    assert decision.verdict is ScopeVerdict.IN_SCOPE
    assert decision.trusted


# -------------------------------------------------------- the loopback exemption


def test_loopback_is_denied_unless_declared():
    """Defect 3. The original allowed loopback unconditionally.

    That is the right policy for a local fixture rig and the wrong policy for
    anything else, so it has to be a declaration in the scope file rather than a
    property of the code.
    """
    decision = guard().check("http://127.0.0.1:9000/hits")
    assert decision.verdict is ScopeVerdict.BLOCKED


@pytest.mark.parametrize("target", ["http://127.0.0.1:9000/", "http://localhost:9000/", "::1"])
def test_loopback_is_allowed_once_declared(target):
    decision = guard(allow_loopback=True).check(target)
    assert decision.verdict is ScopeVerdict.IN_SCOPE
    assert "loopback" in decision.reason


def test_a_declared_loopback_exemption_still_loses_to_out_of_scope():
    decision = guard(
        allow_loopback=True,
        out_of_scope=[{"host": "127.0.0.1"}],
    ).check("http://127.0.0.1:9000/")
    assert decision.verdict is ScopeVerdict.BLOCKED


# ------------------------------------------------------------------- freshness


def test_a_fresh_scope_file_is_verified():
    assert guard().check("https://api.example").trust is ScopeTrust.VERIFIED


def test_a_stale_scope_file_marks_the_result_untrusted():
    """Defect 2. ``_warn_staleness`` was reachable only from ``_main``.

    Every programmatic caller -- which is all of them -- skipped the freshness
    check entirely, so the one thing the scope file claims about the world was
    never checked on the path that mattered.
    """
    decision = guard(last_verified=STALE).check("https://api.example")
    assert decision.verdict is ScopeVerdict.IN_SCOPE
    assert decision.trust is ScopeTrust.STALE
    assert not decision.trusted
    assert "untrusted" in decision.reason


def test_a_null_last_verified_marks_the_result_untrusted():
    decision = guard(last_verified=None).check("https://api.example")
    assert decision.trust is ScopeTrust.UNVERIFIED
    assert not decision.trusted


def test_max_age_days_is_configurable_from_the_file():
    fresh_under_a_longer_window = ScopeGuard(
        ScopeFile.from_text(scope_text(last_verified=STALE, max_age_days=365)), today=TODAY
    )
    assert fresh_under_a_longer_window.check("https://api.example").trust is ScopeTrust.VERIFIED


def test_staleness_is_evaluated_at_the_boundary():
    on_the_day = (TODAY - dt.timedelta(days=DEFAULT_MAX_AGE_DAYS)).isoformat()
    one_day_past = (TODAY - dt.timedelta(days=DEFAULT_MAX_AGE_DAYS + 1)).isoformat()
    assert guard(last_verified=on_the_day).check("https://api.example").trusted
    assert not guard(last_verified=one_day_past).check("https://api.example").trusted


def test_a_future_last_verified_is_rejected_rather_than_trusted():
    """A clock that reads forward is a broken instrument, not a fresh scope file."""
    ahead = (TODAY + dt.timedelta(days=1)).isoformat()
    decision = guard(last_verified=ahead).check("https://api.example")
    assert decision.trust is ScopeTrust.UNVERIFIED


# ------------------------------------------------------------------ the assertion


def test_assert_in_scope_passes_on_a_fresh_in_scope_target():
    guard().assert_in_scope("https://api.example/v1")


def test_assert_in_scope_raises_on_a_blocked_target():
    with pytest.raises(ScopeError) as exc:
        guard().assert_in_scope("https://other.example")
    assert "BLOCKED" in str(exc.value)


def test_assert_in_scope_raises_on_an_untrusted_scope_file():
    """Fail closed: an unverified scope file is not a licence to test."""
    with pytest.raises(ScopeError) as exc:
        guard(last_verified=None).assert_in_scope("https://api.example")
    assert "untrusted" in str(exc.value)


def test_blocked_is_not_a_negative_result():
    """The verdict vocabulary keeps these apart on purpose.

    "We were not allowed to test it" and "we tested it and found nothing" are
    different claims, and only one of them is a result. ``BLOCKED`` is therefore
    its own verdict and carries the flag that says so.
    """
    decision = guard().check("https://other.example")
    assert decision.verdict is ScopeVerdict.BLOCKED
    assert decision.is_result is False
    assert guard().check("https://api.example").is_result is True


# ----------------------------------------------------------------- the schema


def test_the_scope_file_round_trips_through_json():
    scope = ScopeFile.from_text(scope_text())
    assert scope.in_scope == (ScopeEntry("api.example", allow_subdomains=True),)
    assert scope.max_age_days == DEFAULT_MAX_AGE_DAYS
    assert scope.allow_loopback is False


def test_scope_entries_are_immutable():
    entry = ScopeFile.from_text(scope_text()).in_scope[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.host = "other.example"  # type: ignore[misc]


def test_a_decision_is_immutable():
    decision = guard().check("https://api.example")
    assert isinstance(decision, ScopeDecision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.verdict = ScopeVerdict.IN_SCOPE  # type: ignore[misc]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "not json at all",
        "[]",
        '"a string"',
        "null",
    ],
)
def test_a_file_that_is_not_a_json_object_fails_loudly(text):
    with pytest.raises(ScopeConfigError):
        ScopeFile.from_text(text)


def test_an_unknown_top_level_key_fails_loudly():
    """Defect 5. A typo'd key must not be read as a default.

    ``out_of_scpoe`` silently becomes "no exclusions at all", which is the
    fail-open direction. A strict schema is the only cheap defence.
    """
    body = json.loads(scope_text())
    body["out_of_scpoe"] = [{"host": "internal.example"}]
    with pytest.raises(ScopeConfigError) as exc:
        ScopeFile.from_text(json.dumps(body))
    assert "out_of_scpoe" in str(exc.value)


def test_an_unknown_entry_key_fails_loudly():
    with pytest.raises(ScopeConfigError) as exc:
        ScopeFile.from_text(scope_text(in_scope=[{"host": "api.example", "subdomains": True}]))
    assert "subdomains" in str(exc.value)


@pytest.mark.parametrize("missing", ["last_verified", "in_scope"])
def test_a_required_key_cannot_be_omitted(missing):
    """Omitting ``in_scope`` would read as "deny everything", which is safe, and
    omitting ``last_verified`` would read as "unverified", which is also safe.
    Both are still refused: a scope file is an assertion, and a missing assertion
    is an unfinished file rather than a conservative one."""
    body = json.loads(scope_text())
    del body[missing]
    with pytest.raises(ScopeConfigError) as exc:
        ScopeFile.from_text(json.dumps(body))
    assert missing in str(exc.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"in_scope": {"host": "api.example"}},
        {"in_scope": ["api.example"]},
        {"in_scope": [{"host": 7}]},
        {"in_scope": [{}]},
        {"max_age_days": "7"},
        {"max_age_days": 0},
        {"max_age_days": -1},
        {"max_age_days": True},
        {"allow_loopback": "yes"},
        {"last_verified": 20261025},
        {"last_verified": "25-10-2026"},
        {"out_of_scope": {"host": "x.example"}},
    ],
)
def test_a_wrong_type_fails_loudly(overrides):
    with pytest.raises(ScopeConfigError):
        ScopeFile.from_text(scope_text(**overrides))


def test_the_schema_error_names_the_file_when_one_was_read(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ScopeConfigError) as exc:
        ScopeFile.from_path(path)
    assert "scope.json" in str(exc.value)


def test_a_missing_scope_file_fails_loudly(tmp_path):
    with pytest.raises(ScopeConfigError):
        ScopeFile.from_path(tmp_path / "absent.json")


def test_a_scope_path_is_an_argument_not_a_constant(tmp_path):
    """Defect 6. The original hardcoded ``../config/scope.yaml`` with no override."""
    path = tmp_path / "custom-name.json"
    path.write_text(scope_text(), encoding="utf-8")
    assert ScopeGuard(ScopeFile.from_path(path), today=TODAY).check("https://api.example").trusted


def test_no_yaml_dependency_is_imported():
    """The core is stdlib-only, and the scope loader was the one YAML user."""
    import controlarm.rails.scope as module

    assert "yaml" not in module.__dict__
