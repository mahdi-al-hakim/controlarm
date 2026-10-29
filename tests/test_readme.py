"""The README's claims about itself are tested, not asserted.

An external reviewer's sharpest criticism of this repository was that its README
followed a researched template in exact order, including a section titled
"Sixty seconds" whose code did not run and which referenced an example file that
did not exist. The checklist item had been satisfied cosmetically.

So the README is now an input to the test suite. The snippet is extracted from
the file and executed, and the verdicts it claims are the assertions. A README
that drifts from the code fails the build.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def _snippet() -> str:
    """The first python block under the 'Sixty seconds' heading."""
    text = README.read_text(encoding="utf-8")
    match = re.search(r"## Sixty seconds.*?```python\n(.*?)```", text, re.S)
    assert match, "the README no longer has a python snippet under 'Sixty seconds'"
    return match.group(1)


@pytest.mark.parametrize(
    "mode,expected",
    [("flawed", "CANDIDATE"), ("patched", "KILL"), ("unauthorized-all", "VOID")],
)
def test_the_readme_snippet_runs_and_says_what_the_readme_claims(mode, expected, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    code = _snippet().replace('Target(mode="flawed")', f'Target(mode="{mode}")')
    code = code.replace('print(verdict.value, "-", why)', "RESULT.append(verdict.value)")
    namespace: dict[str, object] = {"RESULT": []}
    exec(compile(code, "<readme-snippet>", "exec"), namespace)
    assert namespace["RESULT"] == [expected], (
        f"the README's snippet in mode {mode!r} produced "
        f"{namespace['RESULT']}, but the README claims {expected}"
    )


def test_every_command_the_readme_shows_refers_to_a_file_that_exists():
    """The README referenced `examples/run_controls.py` before it existed."""
    text = README.read_text(encoding="utf-8")
    missing = []
    for script in re.findall(r"^python ([\w./-]+\.py)", text, re.M):
        if not (ROOT / script).exists():
            missing.append(script)
    assert not missing, f"the README invokes scripts that do not exist: {missing}"


def test_every_relative_link_in_the_readme_resolves():
    text = README.read_text(encoding="utf-8")
    broken = []
    for target in re.findall(r"\]\((?!https?:|#)([^)]+)\)", text):
        path = (ROOT / target.split("#")[0]).resolve()
        if not path.exists():
            broken.append(target)
    assert not broken, f"the README links to paths that do not exist: {broken}"


@pytest.mark.pristine
def test_the_worked_example_produces_the_verdicts_it_documents():
    """`examples/run_controls.py` exits non-zero if its own table is wrong."""
    proc = subprocess.run(
        [sys.executable, "examples/run_controls.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"the worked example failed:\n{proc.stdout}\n{proc.stderr}"
    # The four verdicts the module docstring promises must all actually appear.
    for verdict in ("VOID", "KILL", "CANDIDATE"):
        assert verdict in proc.stdout, f"{verdict} never appeared in the example's output"


def test_the_readme_does_not_claim_a_pypi_install_that_does_not_exist():
    """It did, and `pip install controlarm` would have failed for every reader."""
    text = README.read_text(encoding="utf-8")
    assert "pip install controlarm" not in text, (
        "the README advertises a PyPI install; either publish the package or "
        "keep the from-source instructions"
    )


#: Paths excluded from the prose sweep. Third-party source acquired for the CVE
#: study is not ours to reformat, and this file necessarily contains the
#: character it searches for.
_NOT_OURS = (
    "__pycache__",
    "vendor",
    ".cache",
    ".ruff_cache",
    ".pytest_cache",
    ".venv",
    "node_modules",
)


def _authored_docs() -> list[pathlib.Path]:
    return [p for p in sorted(ROOT.rglob("*.md")) if not any(part in _NOT_OURS for part in p.parts)]


def test_no_em_dashes_in_any_authored_document():
    """A house rule inherited from the source methodology's wording gate.

    An em dash is also the most common tell that prose was not written by hand,
    and a reviewer flagged the register of this repository specifically. An
    earlier version of this test named four files and therefore missed 51
    occurrences across four others, so it now walks every document we wrote.
    """
    offenders = {
        p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8").count("—")
        for p in _authored_docs()
        if "—" in p.read_text(encoding="utf-8")
    }
    assert not offenders, f"em dashes found in {offenders}"


def test_the_prose_sweep_actually_covers_the_documents():
    """A sweep that walks nothing passes trivially, which is the defect this
    repository is named after. Assert it found the files it is meant to check."""
    found = {p.name for p in _authored_docs()}
    for required in ("README.md", "GAPS.md", "CONTRIBUTING.md", "SECURITY.md"):
        assert required in found, f"the prose sweep did not reach {required}"
    assert len(_authored_docs()) >= 6, (
        f"the prose sweep only reached {len(_authored_docs())} documents, which is "
        "fewer than this repository has; it is probably walking the wrong root"
    )
