"""Tests for the network prior-art sources.

Nothing here opens a socket or runs a subprocess. Two of these tests prove it:
they replace ``urlopen`` and ``subprocess.run`` with functions that fail the
test if called, and then assert the expected refusal arrives instead.

The tests that parse a real API response replay a **committed recording** from
``benchmarks/dedup/cassettes/``, so what is parsed is what the corpus actually
said. The tests that need a malformed response build one in ``tmp_path`` and
mark it ``provenance=synthetic``; the transport refuses to serve such a
recording unless a test opts in, which is the guard that keeps a hand-written
body out of a published number.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
from unittest import mock

import pytest

from controlarm.gates.priorart import (
    CountBasis,
    PriorArtError,
    PriorArtVerdict,
    gate,
)
from controlarm.gates.sources import (
    RECORDED,
    SYNTHETIC,
    AsOf,
    CassetteMiss,
    CassetteStore,
    Fetcher,
    FetchMode,
    GitHubAdvisorySource,
    NvdSource,
    OsvSource,
    Recording,
    Request,
    TransportError,
    parse_subject,
    parse_timestamp,
    scrub,
    scrub_body,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASSETTES = ROOT / "benchmarks" / "dedup" / "cassettes"
MANIFEST = ROOT / "benchmarks" / "dedup" / "manifest.json"

NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.timezone.utc)
CUTOFF = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc)


@pytest.fixture
def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture
def replay() -> Fetcher:
    """A fetcher over the committed recordings. Replay only."""
    return Fetcher(store=CassetteStore(CASSETTES), mode=FetchMode.REPLAY)


@pytest.fixture
def no_network(monkeypatch):
    """Make any network or subprocess call an immediate test failure."""

    def explode(*args, **kwargs):
        raise AssertionError("this code path reached the network")

    monkeypatch.setattr("urllib.request.urlopen", explode)
    monkeypatch.setattr("subprocess.run", explode)


def item(manifest: dict, label: str, family: str) -> dict:
    for entry in manifest["items"]:
        if entry["label"] == label and entry["family"] == family:
            return entry
    raise AssertionError(f"no {label}/{family} item in the manifest")


def store_synthetic(tmp_path: pathlib.Path, request: Request, status: int, body: str) -> Fetcher:
    """A fetcher serving one hand-written response, clearly marked as such."""
    store = CassetteStore(tmp_path)
    store.save(Recording(request, status, body, NOW, SYNTHETIC))
    return Fetcher(store=store, mode=FetchMode.REPLAY, allow_synthetic=True)


# --------------------------------------------------------------- subject.py


def test_a_purl_parses_into_an_ecosystem_package_and_version():
    parsed = parse_subject("pkg:pypi/django@3.2.0")
    assert (parsed.ecosystem, parsed.package, parsed.version) == ("PyPI", "django", "3.2.0")
    assert parsed.is_queryable


def test_a_maven_coordinate_keeps_its_group_id():
    parsed = parse_subject("pkg:maven/org.elasticsearch:elasticsearch@7.9.3")
    assert parsed.package == "org.elasticsearch:elasticsearch"
    assert parsed.version == "7.9.3"


def test_shorthand_parses_the_same_way():
    parsed = parse_subject("PyPI:django@3.2.0")
    assert (parsed.ecosystem, parsed.package, parsed.version) == ("PyPI", "django", "3.2.0")


def test_both_identifier_namespaces_are_found_and_upper_cased():
    parsed = parse_subject("see ghsa-2gwj-7jmv-h26r, also cve-2022-28346")
    assert set(parsed.advisory_ids) == {"GHSA-2GWJ-7JMV-H26R", "CVE-2022-28346"}


def test_prose_is_not_queryable():
    """Failure mode 1. A zero from a question the corpus could not parse is the
    most dangerous row count in the module, so no source is allowed to produce
    one."""
    assert not parse_subject("SQL injection in the login form").is_queryable


def test_a_dotted_package_name_is_not_split_into_a_version():
    """Failure mode 3: ``lodash.merge`` is a package, not ``lodash`` at
    version ``merge``."""
    parsed = parse_subject("npm:lodash.merge")
    assert parsed.package == "lodash.merge"
    assert parsed.version is None


def test_a_colon_that_is_not_an_ecosystem_is_left_alone():
    """Failure mode 2 in its quiet form: prose containing a colon must not be
    read as a package coordinate."""
    parsed = parse_subject("note:the login form is broken")
    assert parsed.package is None


def test_an_unknown_ecosystem_is_refused_rather_than_passed_through():
    with pytest.raises(PriorArtError) as exc:
        parse_subject("pkg:notanecosystem/thing@1.0")
    assert "unknown ecosystem" in str(exc.value)


def test_an_empty_subject_is_refused():
    with pytest.raises(PriorArtError):
        parse_subject("   ")


# ------------------------------------------------------------------ asof.py


@pytest.mark.parametrize(
    ("raw", "expected_year"),
    [("2022-04-13T00:00:33Z", 2022), ("2022-04-12T05:15:06.927", 2022)],
)
def test_the_timestamp_spellings_these_corpora_emit_all_parse(raw, expected_year):
    parsed = parse_timestamp(raw)
    assert parsed is not None and parsed.year == expected_year
    assert parsed.tzinfo is not None


@pytest.mark.parametrize("raw", [None, "", "not a date", 17])
def test_an_unparseable_timestamp_is_none_rather_than_a_guess(raw):
    assert parse_timestamp(raw) is None


def test_a_naive_cutoff_is_refused():
    with pytest.raises(PriorArtError) as exc:
        AsOf(dt.datetime(2025, 6, 1))
    assert "timezone-aware" in str(exc.value)


def test_a_record_published_after_the_cutoff_is_dropped():
    kept, tally = AsOf(CUTOFF).filter([{"published": "2025-07-01T00:00:00Z"}])
    assert kept == []
    assert (tally.kept, tally.dropped) == (0, 1)


def test_a_record_published_before_the_cutoff_is_kept():
    kept, tally = AsOf(CUTOFF).filter([{"published": "2025-05-01T00:00:00Z"}])
    assert len(kept) == 1
    assert tally.dropped == 0


def test_an_undated_record_is_counted_and_said_to_be_undated():
    """Failure mode 2. Dropping it is the direction that invents novelty."""
    kept, tally = AsOf(CUTOFF).filter([{"id": "X"}])
    assert len(kept) == 1
    assert tally.undated == 1
    assert "undated-and-counted=1" in tally.note()


def test_no_cutoff_keeps_everything():
    kept, tally = AsOf().filter([{"published": "2099-01-01T00:00:00Z"}])
    assert len(kept) == 1 and tally.dropped == 0


# -------------------------------------------------------------- cassette.py


def test_a_request_key_is_stable_and_separates_different_bodies():
    one = Request("http", "https://example.invalid/q", "POST", {"a": 1})
    same = Request("http", "https://example.invalid/q", "POST", {"a": 1})
    other = Request("http", "https://example.invalid/q", "POST", {"a": 2})
    assert one.key == same.key
    assert one.key != other.key


def test_a_replay_miss_raises_and_does_not_reach_the_network(tmp_path, no_network):
    """Failure modes 1 and 2 together, and the most important test in the file.

    A miss returned as an empty body would score every unrecorded case CLEAR.
    """
    fetcher = Fetcher(store=CassetteStore(tmp_path), mode=FetchMode.REPLAY)
    with pytest.raises(CassetteMiss) as exc:
        fetcher.fetch(Request("http", "https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000"))
    assert "not a corpus that answered zero" in str(exc.value)
    assert fetcher.network_calls == 0


def test_a_replay_miss_makes_the_gate_ungated_not_clear(tmp_path, no_network):
    """The same thing one layer up: an empty cassette directory is the absence
    of a dedup pass, and must never read as a clean bill of health."""
    fetcher = Fetcher(store=CassetteStore(tmp_path), mode=FetchMode.REPLAY)
    assessment = gate("CVE-2022-28346", [OsvSource(fetcher)], now=NOW)
    assert assessment.verdict is PriorArtVerdict.UNGATED
    assert not assessment.is_clear
    assert not assessment.clears_promotion(NOW)


def test_a_synthetic_recording_is_refused_without_an_explicit_opt_in(tmp_path, no_network):
    """Failure mode 3: a hand-written body must not become a published number."""
    request = Request("http", "https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000")
    store = CassetteStore(tmp_path)
    store.save(Recording(request, 200, "{}", NOW, SYNTHETIC))
    strict = Fetcher(store=store, mode=FetchMode.REPLAY)
    with pytest.raises(TransportError) as exc:
        strict.fetch(request)
    assert "fault-injection fixture" in str(exc.value)
    permissive = Fetcher(store=store, mode=FetchMode.REPLAY, allow_synthetic=True)
    assert permissive.fetch(request).provenance == SYNTHETIC


def test_a_recorded_response_round_trips_through_the_store(tmp_path):
    request = Request("gh-graphql", "https://api.github.com/graphql", "POST", {"query": "query{x}"})
    store = CassetteStore(tmp_path)
    store.save(Recording(request, 200, '{"data": {}}', NOW, RECORDED))
    back = store.load(request)
    assert back is not None
    assert back.request == request
    assert back.recorded_at == NOW
    assert back.ok


def test_a_non_2xx_response_is_not_parsed_into_rows():
    """Failure mode 5. A 429 is not a corpus saying zero."""
    recording = Recording(Request("http", "https://api.osv.dev/v1/query"), 429, "slow down", NOW)
    with pytest.raises(TransportError) as exc:
        recording.json()
    assert "not a" in str(exc.value) and "429" in str(exc.value)


@pytest.mark.parametrize("body", ["{not json", "[1, 2, 3]"])
def test_a_body_that_is_not_a_json_object_raises(body):
    recording = Recording(Request("http", "https://api.osv.dev/v1/query"), 200, body, NOW)
    with pytest.raises(TransportError):
        recording.json()


@pytest.mark.parametrize(
    "url",
    [
        "http://api.osv.dev/v1/query",
        "https://user:pass@api.osv.dev/v1/query",
        "https://127.0.0.1/v1/query",
        "https://[::1]/v1/query",
    ],
)
def test_an_unsafe_endpoint_is_refused_before_any_request(tmp_path, url, no_network):
    """Failure mode 6. Checked before the socket, so ``no_network`` never fires."""
    fetcher = Fetcher(store=CassetteStore(tmp_path), mode=FetchMode.RECORD)
    with pytest.raises(TransportError) as exc:
        fetcher.fetch(Request("http", url))
    assert "refusing to fetch" in str(exc.value)


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "github_pat_11ABCDEFGHIJKLMNOPQRSTUV",
        "Bearer abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_a_token_shaped_string_is_scrubbed(secret):
    """Failure mode 4. The recordings are committed to a public repository."""
    assert secret not in scrub(f"prefix {secret} suffix")
    assert "REDACTED" in scrub(f"prefix {secret} suffix")


def test_the_scrub_does_not_eat_the_backslash_of_an_escaped_quote():
    """Regression. Two recordings in this repo were committed as invalid JSON.

    The value class was ``[^&\\s\\"]+``, which excludes the quote but not the
    backslash in front of it. Run over a serialised body, it consumed the
    escape and left a bare quote that closed the string early. The integrity
    check hashes bytes, so nothing noticed for weeks.
    """
    body = json.dumps({"repro": 'curl -d "_token=SECRETVALUE" https://host.invalid'})
    scrubbed = scrub(body)
    assert "SECRETVALUE" not in scrubbed
    assert "REDACTED" in scrubbed
    json.loads(scrubbed)  # the whole point: it must still parse


def test_scrub_body_refuses_to_return_a_body_it_broke():
    """The post-condition that would have caught the two corrupt recordings."""
    good = json.dumps({"k": "v"})
    assert json.loads(scrub_body(good)) == {"k": "v"}

    with (
        mock.patch("controlarm.gates.sources.cassette.scrub", return_value='{"k": "v'),
        pytest.raises(PriorArtError, match="invalid JSON"),
    ):
        scrub_body(good)


def test_scrub_body_passes_through_text_that_was_never_json():
    assert scrub_body("not json at all") == "not json at all"


def test_a_short_environment_value_is_not_treated_as_a_secret(monkeypatch):
    """A username is not a credential.

    ``USERNAME`` used to be scrubbed by bare substring. On the machine that
    recorded this corpus its value was ``user``, so the word ``user`` was
    replaced wherever it appeared in somebody else's advisory: 1147 places,
    including CVSS vectors whose ``userInteraction`` key became
    ``REDACTEDInteraction`` and one Maven coordinate in the scored manifest
    that was turned into a package which does not exist.
    """
    monkeypatch.setenv("GH_TOKEN", "user")
    text = "a user-defined userInteraction field and github.com/user-attachments/x"
    assert scrub(text) == text


def test_a_long_environment_value_is_still_scrubbed(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "averylongcredentialvalue")
    assert "averylongcredentialvalue" not in scrub("x averylongcredentialvalue y")


def test_every_committed_recording_is_parseable_json():
    """The gap the integrity index cannot see: it hashes bytes, not structure."""
    cassettes = sorted((ROOT / "benchmarks" / "dedup" / "cassettes").glob("*.json"))
    assert len(cassettes) > 100, "corpus not found; this test must not vacuously pass"
    broken = []
    for path in cassettes:
        raw = json.loads(path.read_text(encoding="utf-8"))
        body = raw["response"]["body"]
        try:
            json.loads(body)
        except json.JSONDecodeError as exc:
            broken.append(f"{path.name}: {exc}")
    assert not broken, "recorded bodies that are not valid JSON: " + chr(10).join(broken)


def test_an_api_key_query_parameter_is_scrubbed():
    assert scrub("https://host.invalid/x?apiKey=secretvalue&y=1") == (
        "https://host.invalid/x?apiKey=REDACTED&y=1"
    )


def test_the_scrub_runs_on_save_not_only_on_request(tmp_path):
    request = Request("http", "https://api.osv.dev/v1/query")
    store = CassetteStore(tmp_path)
    path = store.save(
        Recording(request, 200, '{"token": "ghp_abcdefghijklmnopqrstuvwxyz0123"}', NOW)
    )
    assert "ghp_" not in path.read_text(encoding="utf-8")


def test_network_calls_to_one_host_are_spaced(tmp_path, monkeypatch):
    """Failure mode 5: a loop with no pause hammers a free public API.

    ``ticked`` is the fetcher's monotonic injection point, so time stands
    still here rather than the assertion racing the machine.
    """
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", slept.append)
    fetcher = Fetcher(
        store=CassetteStore(tmp_path),
        mode=FetchMode.RECORD,
        min_interval=2.5,
        ticked=1000.0,
    )
    fetcher._wait("https://api.osv.dev/v1/query")
    fetcher._wait("https://api.osv.dev/v1/query")
    assert slept == [2.5]


def test_calls_to_different_hosts_do_not_wait_on_each_other(tmp_path, monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", slept.append)
    fetcher = Fetcher(
        store=CassetteStore(tmp_path),
        mode=FetchMode.RECORD,
        min_interval=2.5,
        ticked=1000.0,
    )
    fetcher._wait("https://api.osv.dev/v1/query")
    fetcher._wait("https://api.github.com/graphql")
    assert slept == []


def test_record_mode_replays_a_hit_without_touching_the_network(tmp_path, no_network):
    request = Request("http", "https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000")
    store = CassetteStore(tmp_path)
    store.save(Recording(request, 404, '{"code": 5}', NOW, RECORDED))
    fetcher = Fetcher(store=store, mode=FetchMode.RECORD)
    assert fetcher.fetch(request).status == 404
    assert fetcher.network_calls == 0


# ------------------------------------------------------- osv.py, on real rows


def test_osv_declines_a_subject_it_cannot_express(replay, no_network):
    assert OsvSource(replay).search("SQL injection in the login form") == ()


def test_osv_finds_a_pre_cutoff_advisory_by_identifier(manifest, replay, no_network):
    """Replayed from the committed recording of a real OSV response."""
    entry = item(manifest, "duplicate", "identifier")
    records = OsvSource(replay, as_of=AsOf(CUTOFF)).search(entry["subject"])
    assert records, "OSV produced no query record for a real advisory identifier"
    assert sum(r.row_count for r in records) >= 1
    assert all(r.basis is CountBasis.MEASURED for r in records)
    assert all(r.source == "osv.dev" for r in records)


def test_osv_does_not_see_a_post_cutoff_advisory_when_asked_as_of_the_cutoff(
    manifest, replay, no_network
):
    """This is the whole novelty half of the benchmark, in one assertion."""
    entry = item(manifest, "novel", "identifier")
    as_of = OsvSource(replay, as_of=AsOf(CUTOFF)).search(entry["subject"])
    unrestricted = OsvSource(replay, as_of=AsOf()).search(entry["subject"])
    assert sum(r.row_count for r in as_of) == 0
    assert sum(r.row_count for r in unrestricted) >= 1, (
        "the advisory is absent from OSV entirely, so this item proves nothing about as-of"
    )


def test_osv_records_the_as_of_label_and_the_rerun_command(manifest, replay, no_network):
    entry = item(manifest, "duplicate", "identifier")
    record = OsvSource(replay, as_of=AsOf(CUTOFF)).search(entry["subject"])[0]
    assert f"as-of={CUTOFF.isoformat()}" in record.query
    assert "rerun: curl" in record.query
    assert record.url.startswith("https://api.osv.dev/")


def test_osv_reports_an_estimate_when_a_page_token_is_outstanding(tmp_path, no_network):
    """Failure mode 2. Built as a synthetic fixture because provoking real
    pagination would mean recording a very large package; the shape of the
    field is from the OSV schema."""
    request = Request(
        "http",
        "https://api.osv.dev/v1/query",
        "POST",
        {"package": {"name": "django", "ecosystem": "PyPI"}, "version": "3.2.0"},
    )
    body = json.dumps(
        {"vulns": [{"id": "X-1", "published": "2020-01-01T00:00:00Z"}], "next_page_token": "more"}
    )
    fetcher = store_synthetic(tmp_path, request, 200, body)
    source = OsvSource(fetcher, max_pages=1)
    record = source.search("pkg:pypi/django@3.2.0")[0]
    assert record.basis is CountBasis.ESTIMATED
    assert "TRUNCATED" in record.query


def test_an_estimated_count_invalidates_the_assessment(tmp_path, no_network):
    """The reason failure mode 2 matters: the gate refuses the verdict."""
    request = Request(
        "http",
        "https://api.osv.dev/v1/query",
        "POST",
        {"package": {"name": "django", "ecosystem": "PyPI"}},
    )
    body = json.dumps({"vulns": [], "next_page_token": "more"})
    fetcher = store_synthetic(tmp_path, request, 200, body)
    assessment = gate("pkg:pypi/django", [OsvSource(fetcher, max_pages=1)], now=NOW)
    assert assessment.verdict is PriorArtVerdict.CLEAR
    validity = assessment.validity(NOW)
    assert not validity.valid
    assert any("estimated" in reason for reason in validity.reasons)


def test_osv_deduplicates_an_advisory_that_arrives_twice(tmp_path, no_network):
    """Failure mode 4: one advisory per matching range would double count."""
    request = Request(
        "http",
        "https://api.osv.dev/v1/query",
        "POST",
        {"package": {"name": "django", "ecosystem": "PyPI"}},
    )
    repeated = {"id": "GHSA-dupe", "published": "2020-01-01T00:00:00Z"}
    fetcher = store_synthetic(tmp_path, request, 200, json.dumps({"vulns": [repeated, repeated]}))
    record = OsvSource(fetcher).search("pkg:pypi/django")[0]
    assert record.row_count == 1


# ------------------------------------------------------ ghsa.py, on real rows


def test_github_finds_a_pre_cutoff_advisory_by_identifier(manifest, replay, no_network):
    entry = item(manifest, "duplicate", "identifier")
    records = GitHubAdvisorySource(replay, as_of=AsOf(CUTOFF)).search(entry["subject"])
    assert records
    assert sum(r.row_count for r in records) >= 1
    assert all(r.source == "github-advisory-database" for r in records)


def test_github_says_in_words_that_it_did_not_match_the_version(manifest, replay, no_network):
    """The documented coverage gap has to travel with the row count, because a
    package-granularity count over-states prior art for one version."""
    entry = item(manifest, "duplicate", "coordinate")
    records = GitHubAdvisorySource(replay, as_of=AsOf(CUTOFF)).search(entry["subject"])
    package_record = [r for r in records if "securityVulnerabilities" in r.query]
    assert package_record, "no package-level query was recorded"
    assert "PACKAGE GRANULARITY" in package_record[0].query
    assert entry["version"] in package_record[0].query


def test_a_graphql_error_is_not_a_row_count_of_zero(tmp_path, no_network):
    """Failure mode 1. ``len(nodes)`` of a missing list is zero, which would
    read as CLEAR, so an ``errors`` key has to raise."""

    class ErroringStore(CassetteStore):
        """Answers every request with a real GraphQL error envelope."""

        def load(self, request: Request) -> Recording:
            body = json.dumps({"data": None, "errors": [{"message": "rate limited"}]})
            return Recording(request, 200, body, NOW, RECORDED)

    source = GitHubAdvisorySource(Fetcher(store=ErroringStore(tmp_path)))
    with pytest.raises(TransportError) as exc:
        source.search("CVE-2022-28346")
    assert "not a row count of zero" in str(exc.value)


def test_a_graphql_error_makes_the_gate_ungated_not_clear(tmp_path, no_network):
    """The consequence: a corpus that errored has not answered."""

    class ErroringStore(CassetteStore):
        def load(self, request: Request) -> Recording:
            body = json.dumps({"data": None, "errors": [{"message": "rate limited"}]})
            return Recording(request, 200, body, NOW, RECORDED)

    source = GitHubAdvisorySource(Fetcher(store=ErroringStore(tmp_path)))
    assessment = gate("CVE-2022-28346", [source], now=NOW)
    assert assessment.verdict is PriorArtVerdict.UNGATED
    assert assessment.failures and "rate limited" in assessment.failures[0][1]


# -------------------------------------------------------- nvd.py, on real rows


def test_nvd_declines_an_identifier_namespace_it_does_not_carry(replay, no_network):
    """Failure mode 1. A GHSA with no CVE is not a question NVD can be asked,
    so NVD does not answer it with a zero."""
    assert NvdSource(replay).search("GHSA-2gwj-7jmv-h26r") == ()


def test_nvd_declines_a_package_coordinate(replay, no_network):
    assert NvdSource(replay).search("pkg:pypi/django@3.2.0") == ()


# ------------------------------------------------------------- the whole gate


def test_a_replayed_assessment_is_stale_and_the_gate_says_so(manifest, replay, no_network):
    """Replayed evidence ages, and that is correct.

    The recording carries the time the corpus was asked, not the time it was
    replayed, so an old cassette produces a verdict the freshness window
    refuses. The benchmark scores verdicts for exactly this reason.
    """
    entry = item(manifest, "duplicate", "identifier")
    sources = [
        OsvSource(replay, as_of=AsOf(CUTOFF)),
        GitHubAdvisorySource(replay, as_of=AsOf(CUTOFF)),
    ]
    far_future = dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)
    assessment = gate(entry["subject"], sources, now=far_future)
    assert assessment.verdict in (PriorArtVerdict.CROWDED, PriorArtVerdict.SATURATED)
    validity = assessment.validity(far_future)
    assert not validity.valid
    assert any("Re-stamping an assessment is not re-running it" in r for r in validity.reasons), (
        f"expected the stale-query reason, got {validity.reasons}"
    )


def test_two_sources_answering_lifts_coverage_but_not_past_the_cap(manifest, replay, no_network):
    entry = item(manifest, "duplicate", "identifier")
    sources = [
        OsvSource(replay, as_of=AsOf(CUTOFF)),
        GitHubAdvisorySource(replay, as_of=AsOf(CUTOFF)),
    ]
    assessment = gate(entry["subject"], sources, now=NOW)
    assert assessment.sources_answered == ("osv.dev", "github-advisory-database")
    assert assessment.coverage_confidence <= 0.6
    assert "public activity, not crowd coverage" in assessment.coverage_note
    assert assessment.validity(NOW).warnings == ()


# ---------------------------------------------- one fixed answer, for faults


class AlwaysStore(CassetteStore):
    """Answers every request with one body, marked as hand-written.

    Used only where provoking the real shape would mean recording something
    enormous (a package with six pages of advisories) or something that does
    not currently exist in the corpus (a rejected CVE). The body is marked
    ``synthetic``, so the fetcher has to be told explicitly to serve it and the
    measurement can never consume one.
    """

    def __init__(self, root, status: int, body: str) -> None:
        super().__init__(root)
        self.status = status
        self.body = body

    def load(self, request: Request) -> Recording:
        return Recording(request, self.status, self.body, NOW, SYNTHETIC)


def always(tmp_path, status: int, body: str) -> Fetcher:
    return Fetcher(
        store=AlwaysStore(tmp_path, status, body),
        mode=FetchMode.REPLAY,
        allow_synthetic=True,
    )


def test_osv_reports_a_recorded_404_as_a_measured_zero(replay, no_network):
    """A 404 from ``/v1/vulns/<id>`` means "no such advisory", which is a
    measurement. Taken from whichever 404 the committed recordings contain, so
    the parsed body is one OSV actually sent."""
    absent = None
    for path in sorted(CASSETTES.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        url = raw["request"]["url"]
        if raw["response"]["status"] == 404 and "/v1/vulns/" in url:
            absent = url.rsplit("/", 1)[-1]
            break
    assert absent, "no recorded OSV 404 to test against"
    record = OsvSource(replay).search(absent)[0]
    assert record.row_count == 0
    assert record.basis is CountBasis.MEASURED
    assert "not found" in record.query


def test_github_reports_an_estimate_when_a_page_remains(tmp_path, no_network):
    """Failure mode 2 in ghsa.py: ``totalCount`` is the server's number and the
    nodes are a page of it."""
    body = json.dumps(
        {
            "data": {
                "securityVulnerabilities": {
                    "totalCount": 500,
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-aaaa-bbbb-cccc",
                                "publishedAt": "2020-01-01T00:00:00Z",
                                "withdrawnAt": None,
                            }
                        }
                    ],
                }
            }
        }
    )
    source = GitHubAdvisorySource(always(tmp_path, 200, body), max_pages=2)
    record = [r for r in source.search("pkg:pypi/django") if "securityVulnerabilities" in r.query]
    assert record and record[0].basis is CountBasis.ESTIMATED
    assert "TRUNCATED" in record[0].query


def test_github_reports_an_estimate_when_an_identifier_lookup_is_truncated(tmp_path, no_network):
    """The identifier path has its own truncation check, and it needs its own
    test: the package path's accounting is separate code, so a test of one
    leaves the other unpinned. The isolated mutation sweep caught exactly that
    -- this test exists because the sweep reported the ``_truncation`` helper
    unpinned while the package-level one was covered.
    """
    body = json.dumps(
        {
            "data": {
                "securityAdvisories": {
                    "totalCount": 300,
                    "pageInfo": {"hasNextPage": True},
                    "nodes": [
                        {
                            "ghsaId": "GHSA-aaaa-bbbb-cccc",
                            "publishedAt": "2020-01-01T00:00:00Z",
                            "withdrawnAt": None,
                        }
                    ],
                }
            }
        }
    )
    record = GitHubAdvisorySource(always(tmp_path, 200, body)).search("CVE-2000-0001")[0]
    assert record.basis is CountBasis.ESTIMATED
    assert "TRUNCATED" in record.query


def test_a_rejected_cve_is_counted_rather_than_subtracted(tmp_path, no_network):
    """Failure mode 2 in nvd.py. Dropping it moves the count toward CLEAR,
    which is the direction that invents novelty."""
    body = json.dumps(
        {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2000-0001",
                        "published": "2000-01-01T00:00:00.000",
                        "vulnStatus": "Rejected",
                    }
                }
            ],
        }
    )
    record = NvdSource(always(tmp_path, 200, body)).search("CVE-2000-0001")[0]
    assert record.row_count == 1
    assert "rejected-and-counted=1" in record.query


def test_nvd_reports_an_estimate_when_the_result_set_was_truncated(tmp_path, no_network):
    """Failure mode 3 in nvd.py."""
    body = json.dumps(
        {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 9,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2000-0001", "published": "2000-01-01T00:00:00.000"}}
            ],
        }
    )
    record = NvdSource(always(tmp_path, 200, body)).search("CVE-2000-0001")[0]
    assert record.basis is CountBasis.ESTIMATED
    assert "TRUNCATED" in record.query
