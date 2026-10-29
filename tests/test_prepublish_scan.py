"""The pre-publication scan must be able to fail, and must not exempt itself.

Its predecessor printed "scrub clean" while being the only dirty file in the
tree, because it skipped its own source. A later revision of the replacement
contained literal backspace bytes where word-boundary escapes were intended, so
two of its rules matched a character that never occurs and the scan again
reported clean.

Both failures have the same shape, and it is the one this repository is named
after: **a check that cannot fire is indistinguishable from a tree that is
clean.** So these tests plant a finding for every rule and require a non-zero
exit, assert the scanner's own file is inside the set it scans, and assert that
an almost-empty tree is reported as a broken scan rather than a clean one.
"""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCANNER = ROOT / "tools" / "prepublish_scan.py"

#: Planted findings are ASSEMBLED AT RUNTIME, never written as literals.
#:
#: The path rules are documented as applying everywhere, and that has to include
#: this file, or the strictest rules in the scanner acquire an exception for the
#: one directory most likely to contain a careless paste. Building the strings
#: from parts keeps the rules absolute and still proves each one fires.
_BS = chr(92)
_AT = chr(64)
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
    "dBjftJeZ4CVPmB92K27uhbUJU1p1r0wWCBqFJfv6nFQ"
)


def _planted() -> dict[str, str]:
    """One probe per rule, each built rather than quoted."""
    return {
        "local-path-windows": "p = 'C:" + _BS + "Users" + _BS + "someone" + _BS + "s.txt'",
        "local-path-posix": "p = '/" + "home" + "/someone/s.txt'",
        "provider-key-prefix": "k = 'ghp_" + "abcdefghijklmnopqrstuvwxyz0123" + "'",
        "private-key-block": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxyz0123456789\n"
        ),
        "jwt": "t = '" + _JWT + "'",
        "personal-email": "contact = 'someone" + _AT + "realdomain.co.uk'",
    }


def _run(cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "tools/prepublish_scan.py"],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _load_scanner():
    spec = importlib.util.spec_from_file_location("ps_under_test", SCANNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_under_test"] = module
    spec.loader.exec_module(module)
    return module


def test_the_tree_is_currently_clean():
    result = _run(ROOT)
    assert result.returncode == 0, "the tree is not clean:\n" + result.stdout
    assert "clean" in result.stdout


def test_the_scanner_scans_its_own_source():
    """Behavioural, not textual: the file must be in the set it walks.

    Checking for a string like "self_path" would pass on a scanner that
    documents the old defect, and fail on one that merely mentions it. The
    property that matters is whether the file is scanned.
    """
    module = _load_scanner()
    scanned = {p.resolve() for p in module.files()}
    assert SCANNER.resolve() in scanned, (
        "the scanner excludes its own source from the walk, which is how its "
        "predecessor reported clean while being the only dirty file in the tree"
    )


def test_every_rule_has_a_planted_finding():
    """A rule with no probe is a rule nothing checks."""
    module = _load_scanner()
    names = {rule.name for rule in module.RULES}
    probes = set(_planted())
    assert names == probes, (
        "rules with no planted finding: "
        + str(sorted(names - probes))
        + "; probes for rules that no longer exist: "
        + str(sorted(probes - names))
    )


def test_no_rule_matches_a_backspace_character():
    """The exact defect that made two rules silently dead.

    A word-boundary escape written through a shell heredoc became byte 0x08.
    Both rules then matched a character that never appears in source, so the
    scan passed by matching nothing.
    """
    source = SCANNER.read_bytes()
    assert bytes([8]) not in source, (
        "the scanner source contains a literal backspace byte, which means a "
        "word-boundary escape was written as a control character and the rule "
        "containing it can never fire"
    )


@pytest.mark.parametrize("name", sorted(_planted()))
def test_the_scan_fails_on_a_planted_finding(tmp_path, name):
    """A gate nobody has seen fail is not known to work."""
    tree = tmp_path / "tree"
    (tree / "tools").mkdir(parents=True)
    shutil.copy2(SCANNER, tree / "tools" / "prepublish_scan.py")
    # Clear MIN_FILES so the failure is the planted finding, not the empty-scan guard.
    for index in range(60):
        (tree / ("filler" + str(index) + ".md")).write_text("nothing here", encoding="utf-8")
    (tree / "planted.py").write_text(_planted()[name], encoding="utf-8")

    result = _run(tree)
    assert result.returncode == 1, "the scan passed on a planted " + name + ":\n" + result.stdout
    assert name in result.stdout, "the " + name + " rule did not name itself:\n" + result.stdout


def test_an_empty_scan_is_not_a_clean_scan(tmp_path):
    """Exit 2, never 0. Its predecessor printed OK on nothing scanned."""
    tree = tmp_path / "tree"
    (tree / "tools").mkdir(parents=True)
    shutil.copy2(SCANNER, tree / "tools" / "prepublish_scan.py")
    result = _run(tree)
    assert result.returncode == 2, "an almost-empty tree did not exit 2:\n" + result.stdout
    assert "not a clean scan" in result.stdout
