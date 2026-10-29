"""The repository's own metadata must describe a repository that exists.

A reviewer with no priors was asked to read this project cold. The first
falsifiable claim they checked was the clone command in the README, and it was
false: the URL returned 404. Their note was exact and deserved -- this project
mechanised link-checking for every local path in the README and never checked
the one URL that everything else depends on.

So that check exists here. It is the same rule the harness applies to a probe:
the claim that can be checked mechanically must be, and a check that cannot run
reports that it could not rather than passing.

Offline, the network test SKIPS. It does not pass. A skip is visible in the
output; a pass would be a false one, and "absence of a measurement is not a
measurement" is the invariant this file is an instance of.
"""

from __future__ import annotations

import pathlib
import re
import urllib.error
import urllib.request

import pytest
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
README = (ROOT / "README.md").read_text(encoding="utf-8")
CITATION = (ROOT / "CITATION.cff").read_text(encoding="utf-8")


def _declared_urls() -> dict[str, str]:
    """Every place this repository names its own canonical location."""
    urls: dict[str, str] = {}
    home = PYPROJECT["project"].get("urls", {}).get("Homepage")
    if home:
        urls["pyproject.toml [project.urls] Homepage"] = home
    cff = re.search(r'^repository-code:\s*"?([^"\s]+)"?\s*$', CITATION, re.M)
    if cff:
        urls["CITATION.cff repository-code"] = cff.group(1)
    clone = re.search(r"git clone (https://\S+)", README)
    if clone:
        urls["README.md clone command"] = clone.group(1)
    return urls


def test_every_declared_url_is_the_same_url():
    """Three files name the repository. They must not disagree about where it is."""
    urls = _declared_urls()
    assert len(urls) >= 3, f"expected the URL in at least three places, found {list(urls)}"
    distinct = {u.rstrip("/").removesuffix(".git") for u in urls.values()}
    assert len(distinct) == 1, f"the declared repository URL disagrees across files: {urls}"


def test_the_version_in_citation_matches_the_package():
    """A citation that names a version the package never published is a wrong citation."""
    pkg = PYPROJECT["project"]["version"]
    cff = re.search(r"^version:\s*(\S+)\s*$", CITATION, re.M)
    assert cff, "CITATION.cff declares no version"
    assert cff.group(1) == pkg, (
        f"CITATION.cff says version {cff.group(1)!r} but the package is {pkg!r}"
    )


def test_the_readme_does_not_present_an_unpublished_clone_as_working():
    """Until the repository is pushed, the clone command fails for every reader.

    The README may still show it, because it is the command that will be correct,
    but it must say so adjacent to the command rather than letting a reader
    discover it by running it.
    """
    if "git clone" not in README:
        pytest.skip("the README no longer shows a clone command")
    before = README[: README.index("git clone")]
    assert "Not published yet" in before, (
        "the README shows a clone command without stating, above it, that the "
        "repository is not published. That was the first thing a cold reviewer "
        "checked, and it was the first thing that was false."
    )


@pytest.mark.release
def test_the_declared_repository_url_resolves():
    """The release gate. SKIPS offline; FAILS on a 404.

    This is the test whose absence a cold reviewer identified. It is marked
    ``release`` and therefore deselected from the default run: it asserts a
    property of the published world, so it is red until the repository is
    pushed. Run it with ``pytest -m release``, which is what the release job
    does. It is not hidden -- the README says the repository is unpublished and
    names this test as the gate.
    """
    url = _declared_urls().get("pyproject.toml [project.urls] Homepage")
    assert url, "pyproject.toml declares no Homepage"
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "controlarm-tests"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status < 400, f"{url} returned {response.status}"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 429):
            pytest.skip(f"{url} returned {exc.code}; cannot distinguish absent from restricted")
        pytest.fail(
            f"the declared repository URL {url} returned {exc.code}. Until this resolves, the "
            f"README's clone command fails for every reader and the citation names a repository "
            f"that does not exist. This is the release precondition, not a flaky test."
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        pytest.skip(f"no network ({type(exc).__name__}), so the URL could not be checked")
