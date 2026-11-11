"""What a prior-art query is *about*, parsed from a string.

``gate()`` takes a free-text ``subject`` because a finding is described in
prose. A corpus takes identifiers. This module is the join: it reads the
structured parts out of a subject string and leaves the rest alone.

A source that cannot express the parsed subject must **not answer** -- it
returns no query records, ``gate()`` files that under ``failures``, and with no
other source the verdict is ``UNGATED``. That is the honest outcome: NVD cannot
be asked "is this npm package version affected", and a source that invents an
answer to a question it cannot ask is worse than a source that is quiet.

Numbered failure modes this module exists to prevent:

  1  prose searched as an identifier    -> "SQL injection in the login form"
     submitted to an endpoint keyed on CVE ids returns zero rows, and a zero row
     count from a question the corpus could not parse reads as CLEAR. A subject
     with no identifier and no package yields an empty ``Subject``, and an empty
     ``Subject`` makes every source decline rather than answer zero.
  2  an ecosystem silently coerced      -> ``pypi`` and ``PyPI`` are the same
     ecosystem to a human and different strings to OSV; a mismatch returns zero
     rows rather than an error. Ecosystem names are mapped through an explicit
     table and an unknown one is refused, not passed through.
  3  a version read off a package name  -> ``lodash.merge`` is a package, not
     ``lodash`` at version ``merge``. Only an explicit ``@`` separator or purl
     version component is read as a version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from controlarm.gates.priorart import PriorArtError

__all__ = [
    "ECOSYSTEMS",
    "GITHUB_ECOSYSTEM_ENUM",
    "Subject",
    "parse_subject",
]

#: purl type / common spelling -> the ecosystem name OSV uses. Deliberately
#: explicit: OSV's names are case-sensitive and not guessable (``crates.io``,
#: ``Packagist``), and a near-miss returns zero rows instead of an error.
ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "pip": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "go": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "packagist": "Packagist",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "hackage": "Hackage",
    "cran": "CRAN",
    "conan": "ConanCenter",
    "github-actions": "GitHub Actions",
}

#: OSV ecosystem name -> the GitHub GraphQL ``SecurityAdvisoryEcosystem`` enum
#: member. An ecosystem absent from this table is one the GitHub Advisory
#: Database cannot be asked about, so that source declines the subject.
GITHUB_ECOSYSTEM_ENUM: dict[str, str] = {
    "PyPI": "PIP",
    "npm": "NPM",
    "Go": "GO",
    "Maven": "MAVEN",
    "crates.io": "RUST",
    "NuGet": "NUGET",
    "Packagist": "COMPOSER",
    "RubyGems": "RUBYGEMS",
    "Hex": "ERLANG",
    "Pub": "PUB",
    "SwiftURL": "SWIFT",
    "GitHub Actions": "ACTIONS",
}

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_GHSA = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
_PURL = re.compile(
    r"\bpkg:(?P<type>[a-zA-Z0-9.+-]+)/(?P<name>[^@\s#?]+)(?:@(?P<version>[^\s#?]+))?",
)
#: ``PyPI:django@3.2.0``. The ecosystem half is matched against ``ECOSYSTEMS``
#: before it is believed, so this cannot swallow ``note:see CVE-2022-1`` style
#: prose.
_SHORTHAND = re.compile(
    r"\b(?P<eco>[A-Za-z][A-Za-z0-9.+-]*):(?P<name>[^@\s,]+)(?:@(?P<version>\S+))?"
)


@dataclass(frozen=True)
class Subject:
    """The queryable parts of a subject string, plus the string itself.

    ``raw`` is kept verbatim because it is what a reader sees in the ledger;
    the parsed fields are what the corpora are actually asked.
    """

    raw: str
    advisory_ids: tuple[str, ...] = ()
    ecosystem: str | None = None
    package: str | None = None
    version: str | None = None

    @property
    def is_queryable(self) -> bool:
        """False when nothing structured was found. Failure mode 1.

        A source handed an unqueryable subject must decline. The alternative --
        running the prose as a keyword search -- produces a zero that reads as
        CLEAR and means "the corpus could not parse the question".
        """
        return bool(self.advisory_ids) or bool(self.package)

    def describe(self) -> str:
        parts = []
        if self.advisory_ids:
            parts.append("ids=" + ",".join(self.advisory_ids))
        if self.package:
            pkg = f"{self.ecosystem}/{self.package}"
            if self.version:
                pkg += f"@{self.version}"
            parts.append("package=" + pkg)
        return "; ".join(parts) or "nothing queryable"


def parse_subject(subject: str) -> Subject:
    """Read identifiers and a package coordinate out of ``subject``.

    Accepted shapes, in one string and in any order:

      ``CVE-2022-28346``            an advisory identifier
      ``GHSA-2gwj-7jmv-h26r``       an advisory identifier
      ``pkg:pypi/django@3.2.0``     a Package URL coordinate
      ``PyPI:django@3.2.0``         the same, shorthand

    Anything else is left in ``raw`` and makes the subject unqueryable.
    """
    if not isinstance(subject, str) or not subject.strip():
        raise PriorArtError(
            "a prior-art subject must be a non-empty string. An empty subject searched "
            "against any corpus returns zero rows, and that zero would read as CLEAR."
        )

    ids: list[str] = []
    for pattern in (_CVE, _GHSA):
        for match in pattern.finditer(subject):
            token = match.group(0).upper()
            if token not in ids:
                ids.append(token)

    ecosystem = package = version = None
    purl = _PURL.search(subject)
    if purl is not None:
        ecosystem = _ecosystem(purl.group("type"))
        package = purl.group("name")
        version = purl.group("version")
    else:
        for match in _SHORTHAND.finditer(subject):
            candidate = ECOSYSTEMS.get(match.group("eco").lower())
            if candidate is None:
                continue  # failure mode 2: not an ecosystem, so not a package
            ecosystem = candidate
            package = match.group("name")
            version = match.group("version")
            break

    return Subject(
        raw=subject,
        advisory_ids=tuple(ids),
        ecosystem=ecosystem,
        package=package,
        version=version,
    )


def _ecosystem(raw: str) -> str:
    try:
        return ECOSYSTEMS[raw.lower()]
    except KeyError:
        raise PriorArtError(
            f"unknown ecosystem {raw!r}. Known: {sorted(ECOSYSTEMS)}. An unrecognised "
            "ecosystem name is not passed through: OSV's names are case-sensitive and a "
            "near-miss returns zero rows rather than an error, which would read as CLEAR."
        ) from None
