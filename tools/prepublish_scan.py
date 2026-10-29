"""Refuse to publish a tree that leaks the machine it was built on.

This replaces a scanner that was deleted. Read why before extending it, because
the two reasons it was deleted are the two mistakes worth not repeating.

  1  **It exempted itself from its own scan.** One line read
     ``if path.resolve() == self_path: continue``, justified by a comment
     saying the file necessarily contains the patterns it searches for. The
     consequence: it printed ``scrub clean`` while being the only dirty file in
     the tree. A check that excludes itself is the defect this repository is
     named after. This scanner has no such exclusion, and
     ``tests/test_prepublish_scan.py`` asserts that it does not.

  2  **It carried the sensitive content inside itself.** To detect mentions of
     particular unreported vulnerabilities, it listed their identifiers as
     regexes. The scanner *was* the leak: those strings existed nowhere else in
     the tree.

The rule taken from both: **a scanner must not know any secret.** Every pattern
here matches on *shape* -- something that looks like an absolute local path, a
provider key prefix, a private key with a body, a serialised token, an address.
There is no denylist of names, so there is nothing in this file worth leaking,
and therefore no reason to exempt it.

A third mistake, made while writing this file and worth recording because it is
the same family: an earlier revision contained literal ``0x08`` bytes where
``\\b`` was intended, because the text was written through a shell heredoc that
interpreted the escape. The word-boundary assertions therefore matched a
backspace character, which never occurs, so two rules silently matched nothing
and the scan reported clean. **A rule that cannot fire is indistinguishable
from a tree that is clean.** The tests now plant a finding for every rule, so a
rule that matches nothing fails the build.

It is not a general secret scanner and does not pretend to be. Use `gitleaks`
or GitHub push protection for that. This is a tripwire for the accident that
already happened here once: a committed results file carrying the operator's
home directory, after the previous scanner was deleted and nothing took over.

    python tools/prepublish_scan.py

Exit 0 clean, 1 with findings, 2 when the scan could not run -- which is never
reported as clean, because an empty scan that prints OK is exactly how the
previous version of this idea failed.
"""

from __future__ import annotations

import pathlib
import re
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "node_modules",
    "dist",
    "build",
    ".cache",
}

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".toml",
    ".yml",
    ".yaml",
    ".json",
    ".jsonl",
    ".cfg",
    ".ini",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".html",
    ".css",
    ".cff",
    ".lock",
    "",
}

#: Below this, the scan is broken rather than clean. Its predecessor printed OK
#: on "0 file(s) scanned".
MIN_FILES = 40

#: Recorded third-party API responses: public advisory text. They legitimately
#: contain organisational CNA and vendor contact addresses, other researchers'
#: profile links, and example filesystem paths from reproduction steps, because
#: that is what the upstream advisories say. All of it is already public
#: wherever the advisory is.
#:
#: This is a NARROWED rule set, never a skipped directory. Blanket-skipping a
#: path is how a scan comes to cover nothing.
RECORDED_THIRD_PARTY = "benchmarks/dedup/cassettes/"
RULES_RELAXED_FOR_RECORDINGS = frozenset({"personal-email", "local-path-posix"})

#: A test that a credential is redacted must contain a credential-shaped
#: string, or it tests nothing. Narrowed the same way: the key-shape rule is
#: dropped under tests/, and every other rule still applies there.
SYNTHETIC_FIXTURES = "tests/"
RULES_RELAXED_FOR_FIXTURES = frozenset({"provider-key-prefix"})


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    why: str


RULES: tuple[Rule, ...] = (
    Rule(
        "local-path-windows",
        re.compile(r"[A-Za-z]:[\\/](?:Users|home)[\\/]"),
        "a committed results file once carried the operator's home directory, "
        "captured out of exception text. Never relaxed anywhere: the build "
        "machine is Windows, so a drive-lettered home path in any file is this "
        "tree leaking rather than third-party content",
    ),
    Rule(
        "local-path-posix",
        re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/"),
        "relaxed inside recorded third-party responses only, where advisory "
        "reproduction steps legitimately print a daemon's own data directory",
    ),
    Rule(
        "provider-key-prefix",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{16,}|sk-ant-[A-Za-z0-9-]{16,}"
            r"|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,})"
        ),
        "matched on shape, so this rule knows no secret and needs no denylist",
    ),
    Rule(
        "private-key-block",
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40,}"),
        "the header alone is a legitimate detection pattern, so a body on the "
        "following line is required before this fires",
    ),
    Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
        "a serialised token is a credential even after it expires",
    ),
    Rule(
        "personal-email",
        re.compile(
            # The lookbehind rejects a URL's userinfo (user:pass@host) and a
            # package coordinate (group:artifact@1.2.3). Both have an address's
            # shape and none of its substance, which is the mistake this
            # project's own catalogue calls matching on a value you supplied.
            r"(?<![:/\w.])[A-Za-z0-9._%+-]+@"
            r"(?!example\.(?:com|org|net)\b|invalid\b)"
            # Every label must contain a letter, so a version string cannot
            # pass as a domain.
            r"(?:[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*\.)+[A-Za-z]{2,}\b"
        ),
        "example.com and .invalid are reserved for documentation; URL userinfo "
        "and package coordinates are excluded as shape without substance",
    ),
)

#: Consumer mail domains. Organisational contacts are expected in advisory
#: text; a consumer address is where a personal one would appear, so this keeps
#: the real risk covered inside the recordings. It names no individual.
CONSUMER_MAIL = re.compile(
    r"@(?:gmail|googlemail|outlook|hotmail|live|yahoo|ymail|icloud|proton"
    r"|protonmail|gmx|yandex|aol|zoho)\.[A-Za-z.]{2,}\b",
    re.IGNORECASE,
)


def files() -> list[pathlib.Path]:
    out = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        out.append(path)
    return out


def main() -> int:
    scanned = 0
    skipped_binary: list[str] = []
    findings: list[str] = []

    for path in files():
        rel = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES:
            skipped_binary.append(rel)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            findings.append(f"{rel}: UNREADABLE ({type(exc).__name__}); cannot be cleared")
            continue
        scanned += 1

        recorded = rel.startswith(RECORDED_THIRD_PARTY)
        fixture = rel.startswith(SYNTHETIC_FIXTURES)
        for rule in RULES:
            if recorded and rule.name in RULES_RELAXED_FOR_RECORDINGS:
                continue
            if fixture and rule.name in RULES_RELAXED_FOR_FIXTURES:
                continue
            for match in rule.pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{rel}:{line}: {rule.name} -- {rule.why}")
        if recorded:
            for match in CONSUMER_MAIL.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{rel}:{line}: consumer-mail-domain in a recorded response -- "
                    f"advisory text carries organisational contacts, not personal ones"
                )

    print(f"scanned {scanned} text files under {ROOT.name}/")
    if skipped_binary:
        print(f"{len(skipped_binary)} non-text file(s) were not scanned and are not cleared:")
        for rel in skipped_binary[:20]:
            print(f"  {rel}")
        if len(skipped_binary) > 20:
            print(f"  ... and {len(skipped_binary) - 20} more")

    if scanned < MIN_FILES:
        print(
            f"\nSCAN DID NOT RUN: {scanned} files were read, fewer than the {MIN_FILES} this "
            f"tree contains. Exit 2. An empty scan is not a clean scan."
        )
        return 2

    if findings:
        print(f"\nSCAN FAILED: {len(findings)} finding(s)\n")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print("\nclean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
