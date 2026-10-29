"""The CVE registry: external ground truth, declared before anything was executed.

Every field here is either a public fact about a published advisory or a
statement about this study's own design. None of it is a verdict. The verdicts
come from running the probes, and the vendor's released fix -- not a label in
this repository -- is what makes a pre-fix negative wrong.

Why each field exists
---------------------
``advisory_url``
    The public advisory. A CVE with no public advisory is out of scope by rule
    X3 of ``SELECTION_RULE.md``.
``fix_release_url``
    The vendor's own identification of the fix, as a release. This is the
    authority for ground truth.
``fix_evidence``
    The source change actually observed between the two pinned versions, as a
    sentence. It is recorded because it is *stronger* than the URL: it is the
    vendor's own code, read off the two artefacts this study measured, and it
    is what makes "pre-fix" and "post-fix" mean something here rather than
    being two more labels. Checkable by diffing the two pins under ``.cache/pins/``
    after ``run_study.py --acquire``.
``oracle``
    The mechanical oracle, named before execution, as rule C5 requires.
``reachability``
    One line on why reachability is real. Required by the brief, and the honest
    answer for some targets is that it is not, which is what ``status`` records.
``status``
    ``REACHED``     the probe discriminates: it fires pre-fix and not post-fix.
    ``UNREACHED``   admissible on paper, reachability not demonstrated here.
    ``REJECTED``    failed a clause of the selection rule; kept with the reason.

Only ``REACHED`` targets enter any headline number. ``UNREACHED`` and
``REJECTED`` are published next to them rather than deleted, because a selection
rule whose rejections are invisible is not a selection rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "CLASSES",
    "MEMORY_SAFETY_CLASSES",
    "REACHED",
    "STATUSES",
    "TARGETS",
    "Target",
    "by_cve",
    "reached",
    "support_requirements",
]

#: Vulnerability classes admissible under rule C4. Memory safety is absent by
#: rule X1, and a test asserts that no target carries a memory-safety class.
CLASSES = (
    "authorization",
    "business-logic",
    "deserialisation-allowlist-bypass",
    "open-redirect",
    "parser-differential",
    "path-traversal",
    "sanitizer-bypass",
    "signature-verification",
)

#: Classes excluded by rule X1. Named explicitly so the test that enforces the
#: exclusion has something to check against rather than a convention.
MEMORY_SAFETY_CLASSES = (
    "buffer-overflow",
    "double-free",
    "memory-safety",
    "null-dereference",
    "out-of-bounds-read",
    "out-of-bounds-write",
    "type-confusion",
    "uninitialised-memory",
    "use-after-free",
)

STATUSES = ("REACHED", "UNREACHED", "REJECTED")


@dataclass(frozen=True)
class Target:
    cve: str
    package: str
    pre: str
    post: str
    vuln_class: str
    advisory_url: str
    fix_release_url: str
    fix_evidence: str
    oracle: str
    reachability: str
    probe: str = ""
    status: str = "REACHED"
    sdist_subtree: str | None = None
    notes: str = ""
    #: Libraries the probe needs merely in order to import the pin. Installed
    #: UNPINNED into a shared cache directory, because they are scaffolding and
    #: not the independent variable: the CVE is in ``package``, and pinning the
    #: scaffolding would invite a reader to think otherwise. The pin always
    #: shadows any copy of itself that arrives this way, which every probe's
    #: liveness arm asserts.
    support_requirements: tuple[str, ...] = field(default_factory=tuple)

    @property
    def pins(self) -> tuple[tuple[str, str], ...]:
        return ((self.package, self.pre), (self.package, self.post))


TARGETS: tuple[Target, ...] = (
    Target(
        cve="CVE-2020-14343",
        package="PyYAML",
        pre="5.3.1",
        post="5.4",
        vuln_class="deserialisation-allowlist-bypass",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2020-14343",
        fix_release_url="https://github.com/yaml/pyyaml/releases/tag/5.4",
        fix_evidence=(
            "5.4's FullConstructor refuses the python/object/new tag path that 5.3.1 accepts, "
            "so the same document raises ConstructorError instead of constructing a type."
        ),
        oracle=(
            "a directory the probe never creates itself exists on disk after full_load() "
            "returns, because the deserialiser called os.mkdir. A filesystem side effect, "
            "not a substring of the document the probe supplied."
        ),
        reachability=(
            "yaml.full_load is the documented entry point advertised as safe against "
            "arbitrary code execution; the probe calls it directly and the observable is a "
            "real directory created during the parse."
        ),
        probe="cve_2020_14343_pyyaml",
        sdist_subtree="lib3",
        notes=(
            "Acquired from the sdist's pure-Python lib3 subtree, together with its LICENSE, "
            "because PyYAML 5.x publishes no wheel for CPython 3.12 and its C extension is "
            "optional. The cached code is the released source, unmodified, and like every "
            "other pin it lives in the gitignored cache rather than in the repository."
        ),
    ),
    Target(
        cve="CVE-2024-22195",
        package="Jinja2",
        pre="3.1.2",
        post="3.1.3",
        vuln_class="sanitizer-bypass",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2024-22195",
        fix_release_url="https://github.com/pallets/jinja/releases/tag/3.1.3",
        fix_evidence=(
            "3.1.3's xmlattr filter raises ValueError for a key containing whitespace; "
            "3.1.2 interpolates the key verbatim into the attribute string."
        ),
        oracle=(
            "the rendered tag carries an attribute name the template author never wrote, "
            "measured by parsing the rendered tag's attribute names rather than by searching "
            "the output for the payload text."
        ),
        reachability=(
            "xmlattr is a shipped filter; the probe renders a template through the public "
            "Environment API and the injected attribute appears in the returned markup."
        ),
        probe="cve_2024_22195_jinja2",
        support_requirements=("markupsafe",),
    ),
    Target(
        cve="CVE-2024-34064",
        package="Jinja2",
        pre="3.1.3",
        post="3.1.4",
        vuln_class="sanitizer-bypass",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2024-34064",
        fix_release_url="https://github.com/pallets/jinja/releases/tag/3.1.4",
        fix_evidence=(
            "3.1.4's xmlattr filter raises ValueError for keys containing '/', '>' or '='; "
            "3.1.3 rejected only whitespace, so a key with none of it passed through."
        ),
        oracle=(
            "the same attribute-name parse as CVE-2024-22195, driven by a key that contains "
            "no whitespace, so the two Jinja2 targets are not one payload scored twice."
        ),
        reachability=(
            "the same public filter, and the 3.1.3 pin demonstrably renders the '=' key that "
            "3.1.4 rejects, so the two pins differ on exactly this input."
        ),
        probe="cve_2024_34064_jinja2",
        support_requirements=("markupsafe",),
    ),
    Target(
        cve="CVE-2023-23934",
        package="Werkzeug",
        pre="2.2.2",
        post="2.2.3",
        vuln_class="parser-differential",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2023-23934",
        fix_release_url="https://github.com/pallets/werkzeug/releases/tag/2.2.3",
        fix_evidence=(
            "2.2.3 stops treating a nameless cookie's value as a further cookie string, so "
            "the header '=__Host-auth=x' no longer yields a '__Host-auth' key."
        ),
        oracle=(
            "parse_cookie() returns a mapping containing the key '__Host-auth'. The probe "
            "reads a parsed field, not a substring of the header it supplied."
        ),
        reachability=(
            "werkzeug.http.parse_cookie is the public parser Flask uses for request cookies; "
            "the probe calls it with a header value and reads the parsed mapping back."
        ),
        probe="cve_2023_23934_werkzeug",
        support_requirements=("markupsafe",),
    ),
    Target(
        cve="CVE-2022-29217",
        package="PyJWT",
        pre="2.3.0",
        post="2.4.0",
        vuln_class="signature-verification",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2022-29217",
        fix_release_url="https://github.com/jpadilla/pyjwt/releases/tag/2.4.0",
        fix_evidence=(
            "2.4.0 replaces HMACAlgorithm.prepare_key's four-string blocklist with "
            "is_pem_format/is_ssh_key, so an OpenSSH-format ed25519 public key is refused as "
            "an HMAC secret; 2.3.0's blocklist named only 'ssh-rsa'."
        ),
        oracle=(
            "jwt.decode() returns a verified claim set for a token signed HS256 with a public "
            "key as the secret. The observable is a successful signature verification."
        ),
        reachability=(
            "the probe generates a throwaway ed25519 key pair in-process, uses only its "
            "public half, and 2.3.0 both signs and verifies with it while 2.4.0 raises "
            "InvalidKeyError. No network and no pre-existing key material."
        ),
        probe="cve_2022_29217_pyjwt",
        support_requirements=("cryptography",),
    ),
    Target(
        cve="CVE-2024-53861",
        package="PyJWT",
        pre="2.10.0",
        post="2.10.1",
        vuln_class="signature-verification",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2024-53861",
        fix_release_url="https://github.com/jpadilla/pyjwt/releases/tag/2.10.1",
        fix_evidence=(
            "2.10.1 compares the iss claim for equality; 2.10.0 used a containment test, so "
            "an iss of 'good' satisfied an expected issuer of 'https://good.example'."
        ),
        oracle=(
            "jwt.decode(..., issuer=...) returns instead of raising InvalidIssuerError for a "
            "token whose iss is a strict substring of the expected issuer."
        ),
        reachability=(
            "issuer validation is a documented decode option; the probe mints its own HS256 "
            "token and the 2.10.0 pin accepts the wrong issuer while 2.10.1 rejects it."
        ),
        probe="cve_2024_53861_pyjwt",
    ),
    Target(
        cve="CVE-2022-24761",
        package="waitress",
        pre="2.1.0",
        post="2.1.1",
        vuln_class="parser-differential",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2022-24761",
        fix_release_url="https://github.com/Pylons/waitress/releases/tag/v2.1.1",
        fix_evidence=(
            "2.1.1 validates Content-Length against ONLY_DIGIT_RE before calling int(); "
            "2.1.0 passed the raw value to int(), which accepts a leading '+' and underscore "
            "digit separators."
        ),
        oracle=(
            "the parser reports no error and a numeric content_length for a Content-Length "
            "header that is not a digit string. That front-end/back-end disagreement is what "
            "makes request smuggling possible, and it is read off the parser's own state."
        ),
        reachability=(
            "waitress.parser.HTTPRequestParser is fed raw request bytes directly; no socket "
            "is opened and no server is started."
        ),
        probe="cve_2022_24761_waitress",
    ),
    Target(
        cve="CVE-2021-42771",
        package="Babel",
        pre="2.9.0",
        post="2.9.1",
        vuln_class="path-traversal",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-42771",
        fix_release_url="https://github.com/python-babel/babel/releases/tag/v2.9.1",
        fix_evidence=(
            "2.9.1 adds resolve_locale_filename, which applies os.path.basename to the locale "
            "identifier before joining it to the locale-data directory; 2.9.0 joined it raw."
        ),
        oracle=(
            "localedata.load() returns a sentinel value that exists only in a file the probe "
            "placed OUTSIDE the locale-data directory. The traversal is proven by the content "
            "that came back, not by the path that went in."
        ),
        reachability=(
            "babel.localedata.load is the loader Locale.parse uses; the probe writes one "
            "out-of-tree .dat file and the 2.9.0 pin reads it through a '../' identifier."
        ),
        probe="cve_2021_42771_babel",
        support_requirements=("pytz",),
    ),
    Target(
        cve="CVE-2021-45116",
        package="Django",
        pre="3.2.10",
        post="3.2.11",
        vuln_class="business-logic",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-45116",
        fix_release_url="https://docs.djangoproject.com/en/stable/releases/3.2.11/",
        fix_evidence=(
            "3.2.11 replaces dictsort's Variable(arg).resolve with a restricted chain of "
            "__getitem__/getattr that does not invoke callables and forbids private names; "
            "3.2.10 resolved through the template Variable machinery, which calls them."
        ),
        oracle=(
            "a sentinel method that the filter argument never marks as a call is nonetheless "
            "invoked, recorded by the sentinel object itself. A side effect in the target."
        ),
        reachability=(
            "dictsort is a built-in template filter taking an attribute path; the probe calls "
            "the filter directly with settings configured in-process, with no database and no "
            "request cycle."
        ),
        probe="cve_2021_45116_django",
        support_requirements=("asgiref", "sqlparse", "pytz", "tzdata"),
    ),
    Target(
        cve="CVE-2024-6221",
        package="Flask-Cors",
        pre="4.0.2",
        post="5.0.0",
        vuln_class="authorization",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2024-6221",
        fix_release_url="https://github.com/corydolphin/flask-cors/releases/tag/5.0.0",
        fix_evidence=(
            "5.0.0 flips the allow_private_network default in flask_cors/core.py from True to "
            "False, so Access-Control-Allow-Private-Network is no longer sent as 'true' under "
            "a default CORS() configuration."
        ),
        oracle=(
            "the response carries Access-Control-Allow-Private-Network: true under a default "
            "CORS() setup -- a response header the application never set."
        ),
        reachability=(
            "the probe drives a Flask app through its own in-process test client, so no socket "
            "is bound, and reads the header off the response object."
        ),
        probe="cve_2024_6221_flask_cors",
        support_requirements=("flask",),
        notes=(
            "The pre-fix pin is 4.0.2, not 4.0.1: 4.0.2 is where allow_private_network first "
            "exists and defaults to True, so 4.0.2 -> 5.0.0 isolates the default flip. Using "
            "4.0.1 would have confounded the fix with the option's introduction."
        ),
    ),
    Target(
        cve="CVE-2023-28370",
        package="tornado",
        pre="6.3.1",
        post="6.3.2",
        vuln_class="open-redirect",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2023-28370",
        fix_release_url="https://github.com/tornadoweb/tornado/releases/tag/v6.3.2",
        fix_evidence=(
            "6.3.2 raises HTTPError(403, 'cannot redirect path with two initial slashes') in "
            "StaticFileHandler.validate_absolute_path before the trailing-slash redirect; "
            "6.3.1 issued the redirect."
        ),
        oracle=(
            "the handler's own redirect() sink is called with a protocol-relative target, "
            "captured at the sink. What the library decided to do, not what the probe asked "
            "it for."
        ),
        reachability=(
            "the probe instantiates StaticFileHandler against a real temporary directory with "
            "a default_filename and calls validate_absolute_path; no listening socket. 6.3.1 "
            "redirects to '//evil.example/' and 6.3.2 raises 403."
        ),
        probe="cve_2023_28370_tornado",
    ),
    Target(
        cve="CVE-2024-49766",
        package="Werkzeug",
        pre="3.0.4",
        post="3.0.6",
        vuln_class="path-traversal",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2024-49766",
        fix_release_url="https://github.com/pallets/werkzeug/releases/tag/3.0.6",
        fix_evidence=(
            "3.0.6 adds a leading-slash rejection to safe_join, carrying the comment that "
            "ntpath.isabs does not catch this on Python older than 3.11."
        ),
        oracle="safe_join() returns a path instead of None for an absolute or UNC filename.",
        reachability=(
            "NOT ESTABLISHED. The fix's own comment scopes the vulnerable branch to Python "
            "older than 3.11; this study ran on CPython 3.12.5, where ntpath.isabs already "
            "rejects the payload and both pins return None for every variant tried. "
            "Reachability would need an interpreter this environment does not have, so the "
            "target is excluded from every headline rather than guessed at."
        ),
        status="UNREACHED",
    ),
    Target(
        cve="CVE-2021-45452",
        package="Django",
        pre="3.2.10",
        post="3.2.11",
        vuln_class="path-traversal",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-45452",
        fix_release_url="https://docs.djangoproject.com/en/stable/releases/3.2.11/",
        fix_evidence=(
            "3.2.11 normalises backslashes in Storage.get_available_name and re-validates the "
            "name returned by _save."
        ),
        oracle="a file exists outside MEDIA_ROOT after Storage.save() returns.",
        reachability=(
            "NOT ESTABLISHED. With the stock FileSystemStorage on this platform both pins "
            "raise SuspiciousFileOperation for every traversal payload tried, because an "
            "earlier validation catches it first. The fix guards a name returned by a custom "
            "_save override, so reaching it would mean shipping a deliberately broken storage "
            "backend and measuring that instead of Django. Excluded from the headline."
        ),
        status="UNREACHED",
    ),
    Target(
        cve="CVE-2021-23980",
        package="bleach",
        pre="3.3.0",
        post="3.3.1",
        vuln_class="sanitizer-bypass",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23980",
        fix_release_url="https://github.com/mozilla/bleach/releases/tag/v3.3.1",
        fix_evidence=(
            "NONE FOUND between these pins: diffing the two installed trees shows bleach/ "
            "differing only in the version string in __init__.py and the removal of a "
            "vendored Django copy. No sanitizer or html5lib-shim change is present."
        ),
        oracle="n/a -- rejected before an oracle was declared.",
        reachability=(
            "n/a. Rejected under rule C2: this pin pair does not straddle the fix, so it "
            "cannot supply pre-fix/post-fix ground truth. Kept in the registry to record "
            "that the rule rejected a candidate rather than being bent to admit it."
        ),
        status="REJECTED",
    ),
    Target(
        cve="CVE-2023-37920",
        package="certifi",
        pre="2023.5.7",
        post="2023.7.22",
        vuln_class="business-logic",
        advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2023-37920",
        fix_release_url="https://github.com/certifi/python-certifi/releases/tag/2023.07.22",
        fix_evidence="2023.07.22 removes the e-Tugra root certificates from cacert.pem.",
        oracle="n/a -- rejected before an oracle was declared.",
        reachability=(
            "n/a. Rejected under rule C4: searching a PEM bundle for a removed root is a "
            "cheap mechanical oracle that already exists, so this target would not exercise "
            "the claim the study is about. Recorded because excluding it was a judgement "
            "call and a reader is entitled to disagree with it."
        ),
        status="REJECTED",
    ),
)

REACHED = tuple(t for t in TARGETS if t.status == "REACHED")


def support_requirements() -> list[str]:
    """Every scaffolding library any reached probe needs, de-duplicated."""
    out: set[str] = set()
    for target in REACHED:
        out.update(target.support_requirements)
    return sorted(out)


def reached() -> tuple[Target, ...]:
    """The targets that enter the headline. Nothing else does."""
    return REACHED


def by_cve(cve: str) -> Target:
    for t in TARGETS:
        if t.cve == cve:
            return t
    raise KeyError(cve)
