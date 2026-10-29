"""The exit-code contract is the product, so it is tested as one.

A shell script wrapping this tool must be able to distinguish **"the instrument
broke"** from **"the instrument refused"** without parsing text. That is the
single claim the command line makes, and three tests here are the whole of it:

* every subcommand's code is asserted in both its success and its refusal path;
* **exit 2 is never produced by a refusal**, asserted over every refusal the
  subcommands can reach;
* **exit 3 is never produced by a crash**, asserted by injecting a handler that
  raises each of a list of unrelated exception types.

The fourth is the renderer: ``--json`` must parse and must carry the *same*
verdict as the human rendering, for every subcommand and for every outcome,
because two renderers that disagree about the verdict are two instruments.

The fifth is the documentation, in both directions: every subcommand in
``docs/cli.md`` must exist, and every subcommand that exists must be documented.
A tool whose help is a superset of its documentation has undocumented behaviour;
one whose documentation is a superset has stubs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import io
import itertools
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

from controlarm.cli import build_parser, main
from controlarm.cli.commands import EXIT_FOR_VERDICT, G8
from controlarm.cli.exits import (
    EXIT_FOR,
    CannotMeasure,
    CliOutcome,
    Exit,
    NotPromoted,
    Refused,
    exit_for,
)
from controlarm.cli.plan import ArmSpec, OracleSpec, Plan, PlanError, execute
from controlarm.cli.rules import RulesDerivationError, derive
from controlarm.cli.selftest import EXPECTED_BAD_FAILURES, clean_fixture, known_bad_fixture
from controlarm.cli.selftest import selftest as run_selftest
from controlarm.controls.run import Verdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "cli.md"

#: Fixed everywhere. ``tests/test_clock.py`` forbids a test from reading the
#: wall clock at all, and the subcommands that stamp a time take an injection
#: flag for exactly this reason.
TODAY = "2026-01-02"
NOW = "2026-01-02T12:00:00+00:00"

IN_SCOPE = json.dumps(
    {
        "last_verified": "2026-01-01",
        "in_scope": [{"host": "api.example", "allow_subdomains": True}],
        "out_of_scope": [{"host": "internal.api.example", "notes": "carve-out"}],
    }
)
STALE_SCOPE = json.dumps({"last_verified": "2025-01-01", "in_scope": [{"host": "api.example"}]})


# --------------------------------------------------------------------- harness


class Result:
    """What one invocation produced: the code and both streams."""

    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.out, self.err = code, out, err

    @property
    def verdict(self) -> str:
        """The verdict the human renderer printed, read back off the last line.

        Defect 3 of ``render.py``: the greppable line exists so a wrapper that
        cannot use the exit code does not have to grep English. This test is
        the thing that keeps it there.
        """
        match = re.search(r"^verdict: (\S+)  exit: (\d+)$", self.out, re.M)
        assert match, f"no greppable verdict line in:\n{self.out}"
        assert int(match.group(2)) == self.code, "the printed code and the real one differ"
        return match.group(1)

    @property
    def json(self) -> dict:
        return json.loads(self.out)


def run(*argv: str) -> Result:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return Result(code, out.getvalue(), err.getvalue())


@pytest.fixture
def workspace(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "scope.json").write_text(IN_SCOPE, encoding="utf-8")
    (tmp_path / "stale.json").write_text(STALE_SCOPE, encoding="utf-8")
    (tmp_path / "broken.json").write_text('{"in_scope": "not a list"}', encoding="utf-8")
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")
    return tmp_path


#: A fresh suffix per call, so ``_cases`` can be evaluated more than once in
#: one test without the second evaluation meeting its own first-evaluation
#: side effects -- a reused row id is a refusal, which would turn a success
#: row of the table into a failing one for a reason that is not the code
#: under test.
_RUN = itertools.count()


def _ledger_with_rows(tmp_path: pathlib.Path, tag: str = "") -> str:
    """A ledger holding one good row and one honest bad one."""
    path = str(tmp_path / f"ledger{tag}.jsonl")
    assert (
        run(
            "ledger",
            "add",
            "--ledger",
            path,
            "--id",
            "n1",
            "--subject",
            "the allowlist",
            "--verdict",
            "KILL",
            "--oracle",
            "parsed_field_diff",
            "--control-name",
            "HC",
            "--control-passed",
            "true",
            "--control-independent",
            "true",
            "--artifact",
            "run.json",
            "--assumption",
            "one parser disagreement only",
            "--now",
            NOW,
        ).code
        == 0
    )
    assert (
        run(
            "ledger",
            "add",
            "--ledger",
            path,
            "--id",
            "v1",
            "--subject",
            "under 401",
            "--verdict",
            "VOID",
            "--oracle",
            "model_text",
            "--now",
            NOW,
        ).code
        == 0
    )
    return path


def _plan(tmp_path: pathlib.Path, name: str, **overrides) -> str:
    source = json.loads((ROOT / "examples" / "plans" / "fetch_allowlist.json").read_text("utf-8"))
    source.update(overrides)
    path = tmp_path / name
    path.write_text(json.dumps(source), encoding="utf-8")
    return str(path)


# ============================================================ the exit contract


#: ``(argv, expected code)``, success and refusal for every subcommand that can
#: produce both. The two that cannot are asserted separately below, because
#: "this subcommand has no refusal path" is a property worth naming rather than
#: a row worth omitting.
def _cases(w: pathlib.Path) -> list[tuple[tuple[str, ...], int]]:
    tag = str(next(_RUN))
    scope, stale = str(w / "scope.json"), str(w / "stale.json")
    ledger = _ledger_with_rows(w, tag)
    to_verify = w / f"verify-{tag}.json"
    to_verify.write_text(STALE_SCOPE, encoding="utf-8")
    return [
        # scope check: in scope, denied, denied-for-staleness
        (("scope", "check", "https://api.example/x", "--scope", scope, "--today", TODAY), 0),
        (
            (
                "scope",
                "check",
                "https://internal.api.example/x",
                "--scope",
                scope,
                "--today",
                TODAY,
            ),
            3,
        ),
        (
            ("scope", "check", "https://nope.example/x", "--scope", scope, "--today", TODAY),
            3,
        ),
        (
            (
                "scope",
                "check",
                "https://api.example/x",
                "--scope",
                stale,
                "--today",
                TODAY,
                "--refuse-untrusted",
            ),
            3,
        ),
        # scope verify: cited, uncited, not-a-citation
        (
            (
                "scope",
                "verify",
                "--scope",
                str(to_verify),
                "--source",
                "https://example.invalid/policy",
                "--today",
                TODAY,
            ),
            0,
        ),
        (("scope", "verify", "--scope", scope, "--today", TODAY), 3),
        (("scope", "verify", "--scope", scope, "--source", "I looked", "--today", TODAY), 3),
        # oracle rate: admissible, below the floor, unscored
        (("oracle", "rate", "source_diff"), 0),
        (("oracle", "rate", "revert_or_crash"), 3),
        (("oracle", "rate", "no-such-oracle"), 3),
        # run: KILL, VOID, CANDIDATE, refused plan
        (
            (
                "run",
                str(ROOT / "examples/plans/fetch_allowlist_patched.json"),
                "--out",
                str(w / f"a{tag}.json"),
                "--now",
                NOW,
            ),
            0,
        ),
        (
            (
                "run",
                str(ROOT / "examples/plans/fetch_allowlist_unauthorized.json"),
                "--out",
                str(w / f"b{tag}.json"),
                "--now",
                NOW,
            ),
            3,
        ),
        (
            (
                "run",
                str(ROOT / "examples/plans/fetch_allowlist.json"),
                "--out",
                str(w / f"c{tag}.json"),
                "--now",
                NOW,
            ),
            4,
        ),
        (
            (
                "run",
                str(ROOT / "examples/plans/weak_oracle.json"),
                "--out",
                str(w / f"d{tag}.json"),
                "--now",
                NOW,
            ),
            3,
        ),
        # ledger add: accepted, refused for a reused id
        (
            (
                "ledger",
                "add",
                "--ledger",
                ledger,
                "--id",
                f"n2-{tag}",
                "--subject",
                "s",
                "--verdict",
                "CANDIDATE",
                "--oracle",
                "source_diff",
                "--now",
                NOW,
            ),
            0,
        ),
        (
            (
                "ledger",
                "add",
                "--ledger",
                ledger,
                "--id",
                "n1",
                "--subject",
                "s",
                "--verdict",
                "CANDIDATE",
                "--oracle",
                "source_diff",
                "--now",
                NOW,
            ),
            3,
        ),
        # ledger show and audit ledger: no refusal path, by design
        (("ledger", "show", "--ledger", ledger), 0),
        (("audit", "ledger", "--ledger", ledger, "--now", NOW), 0),
        # audit rules: cannot be derived, so 2 and never 0
        (("audit", "rules", "--repo", str(ROOT)), 2),
        # selftest
        (("selftest",), 0),
    ]


def test_every_subcommand_exits_with_the_contracted_code(workspace):
    """Success and refusal, every subcommand, in one table."""
    for argv, expected in _cases(workspace):
        result = run(*argv)
        assert result.code == expected, (
            f"{' '.join(argv)}\n  expected exit {expected}, got {result.code}\n{result.out}"
        )


def test_the_table_covers_every_subcommand_in_both_directions(workspace):
    """Without this, a subcommand could be dropped from the table unnoticed."""
    covered = {_command_of(argv) for argv, _ in _cases(workspace)}
    assert covered == _implemented(), covered.symmetric_difference(_implemented())
    codes: dict[str, set[int]] = {}
    for argv, expected in _cases(workspace):
        codes.setdefault(_command_of(argv), set()).add(expected)
    # The two reporting subcommands have no refusal path on purpose: an audit
    # that rejected imperfect input would only ever see flattering input.
    reporting = {"ledger show", "audit ledger"}
    # ``audit rules`` has no success path on purpose: see rules.py.
    for command, seen in codes.items():
        if command in reporting:
            assert seen == {0}, f"{command} is a reporting subcommand and must only exit 0"
        elif command == "audit rules":
            assert seen == {2}, "audit rules must not acquire a success path by accident"
        elif command == "selftest":
            assert seen == {0}, "selftest passes on the committed tree; drift is tested separately"
        else:
            assert {0}.issubset(seen) and len(seen) > 1, (
                f"{command} is asserted in only one direction: {seen}"
            )


def test_a_refusal_never_exits_2(workspace):
    """The load-bearing half of the contract.

    Every refusal the subcommands can reach is exercised and asserted to be 3.
    A refusal that exited 2 would be read as the instrument breaking, and a
    wrapper would retry it instead of acting on the reason.
    """
    scope = str(workspace / "scope.json")
    ledger = _ledger_with_rows(workspace)
    refusals = [
        ("scope", "check", "https://nope.example/x", "--scope", scope, "--today", TODAY),
        ("scope", "check", "https://internal.api.example/x", "--scope", scope, "--today", TODAY),
        (
            "scope",
            "check",
            "https://api.example/x",
            "--scope",
            str(workspace / "stale.json"),
            "--today",
            TODAY,
            "--refuse-untrusted",
        ),
        ("scope", "verify", "--scope", scope, "--today", TODAY),
        ("scope", "verify", "--scope", scope, "--source", " ", "--today", TODAY),
        ("scope", "verify", "--scope", scope, "--source", "looked at it", "--today", TODAY),
        ("oracle", "rate", "model_text"),
        ("oracle", "rate", "revert_or_crash"),
        ("oracle", "rate", "status_code_argument"),
        ("oracle", "rate", "nothing-like-this"),
        (
            "run",
            str(ROOT / "examples/plans/weak_oracle.json"),
            "--out",
            str(workspace / "e.json"),
            "--now",
            NOW,
        ),
        (
            "run",
            str(ROOT / "examples/plans/fetch_allowlist_unauthorized.json"),
            "--out",
            str(workspace / "f.json"),
            "--now",
            NOW,
        ),
        (
            "run",
            _plan(workspace, "no-oracle.json", oracle=None),
            "--out",
            str(workspace / "g.json"),
            "--now",
            NOW,
        ),
        (
            "run",
            _plan(workspace, "no-control.json", control=None),
            "--out",
            str(workspace / "h.json"),
            "--now",
            NOW,
        ),
        (
            "run",
            _plan(workspace, "unknown-key.json", surprise="hello"),
            "--out",
            str(workspace / "i.json"),
            "--now",
            NOW,
        ),
        (
            "ledger",
            "add",
            "--ledger",
            ledger,
            "--id",
            "n1",
            "--subject",
            "s",
            "--verdict",
            "KILL",
            "--oracle",
            "source_diff",
            "--now",
            NOW,
        ),
        (
            "ledger",
            "add",
            "--ledger",
            ledger,
            "--id",
            "z9",
            "--subject",
            "s",
            "--verdict",
            "KILL",
            "--oracle",
            "source_diff",
            "--now",
            NOW,
        ),
        (
            "ledger",
            "add",
            "--ledger",
            ledger,
            "--id",
            "z9",
            "--subject",
            "s",
            "--verdict",
            "KILL",
            "--oracle",
            "source_diff",
            "--artifact",
            "run.json",
            "--now",
            NOW,
        ),
        (
            "ledger",
            "add",
            "--ledger",
            ledger,
            "--id",
            "z9",
            "--subject",
            "s",
            "--verdict",
            "CANDIDATE",
            "--oracle",
            "source_diff",
            "--supersedes",
            "nope",
            "--now",
            NOW,
        ),
    ]
    for argv in refusals:
        result = run(*argv)
        assert result.code == Exit.REFUSED, (
            f"{' '.join(argv)} exited {result.code}, and a refusal must exit 3\n{result.out}"
        )
        assert result.code != Exit.TOOL_FAILURE


CRASH_TYPES = [RuntimeError, ValueError, KeyError, TypeError, AttributeError, ZeroDivisionError]


@pytest.mark.parametrize("exc_type", CRASH_TYPES, ids=[t.__name__ for t in CRASH_TYPES])
def test_a_crash_never_exits_3(exc_type, monkeypatch):
    """The other load-bearing half.

    An unhandled exception is the instrument breaking. If it could exit 3 a
    reader would record a refusal that never happened, and if it could exit 0 a
    reader would record a clean negative that never happened. Both are the
    defect ``|| true`` produced in the pipeline this is ported from.
    """

    def boom(_ns):
        raise exc_type("the rig fell over")

    monkeypatch.setattr("controlarm.cli.commands.build_parser", _parser_with_handler(boom))
    result = run("selftest")
    assert result.code == Exit.TOOL_FAILURE
    assert result.code not in (Exit.OK, Exit.REFUSED, Exit.NOT_PROMOTED)
    assert result.verdict == "TOOL-FAILURE"
    assert "NOT a negative result" in result.out
    assert exc_type.__name__ in result.out


def test_a_crash_in_json_mode_is_still_a_tool_failure(monkeypatch):
    def boom(_ns):
        raise RuntimeError("the rig fell over")

    monkeypatch.setattr("controlarm.cli.commands.build_parser", _parser_with_handler(boom))
    result = run("--json", "selftest")
    assert result.code == Exit.TOOL_FAILURE
    assert result.json["verdict"] == "TOOL-FAILURE"
    assert result.json["exit_code"] == 2


def _parser_with_handler(handler):
    def build():
        parser = argparse.ArgumentParser(prog="controlarm")
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--json", dest="json", action="store_true", default=False)
        group.add_argument("--human", dest="human", action="store_true", default=False)
        sub = parser.add_subparsers(dest="group")
        leaf = sub.add_parser("selftest")
        leaf.set_defaults(handler=handler)
        return parser

    return build


def test_no_subcommand_exits_1(workspace):
    """``1`` is unassigned, so nothing may produce it.

    A generic "something failed" code inside a contract whose point is that
    failures are distinguishable re-creates the ambiguity the contract removes.
    """
    for argv, _ in _cases(workspace):
        assert run(*argv).code != 1, " ".join(argv)


def test_a_missing_subcommand_is_a_tool_failure_not_a_refusal():
    """A mis-invoked instrument measured nothing. It did not refuse anything."""
    for argv in ((), ("scope",), ("oracle",), ("ledger",), ("audit",)):
        out, err = io.StringIO(), io.StringIO()
        assert main(list(argv), out=out, err=err) == Exit.TOOL_FAILURE, argv
        assert "usage" in err.getvalue()


def test_an_unreadable_input_is_a_tool_failure_not_a_refusal(workspace, tmp_path):
    """Being pointed at nothing is breakage. Reading something and rejecting it
    is a refusal. The two are different codes and the split is deliberate."""
    broken = run(
        "scope",
        "check",
        "https://api.example/x",
        "--scope",
        str(workspace / "broken.json"),
        "--today",
        TODAY,
    )
    assert broken.code == Exit.TOOL_FAILURE
    absent = run("run", str(tmp_path / "no-such-plan.json"), "--out", str(tmp_path / "o.json"))
    assert absent.code == Exit.TOOL_FAILURE
    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text("{not json}\n", encoding="utf-8")
    assert run("ledger", "show", "--ledger", str(corrupt)).code == Exit.TOOL_FAILURE
    assert run("audit", "ledger", "--ledger", str(corrupt), "--now", NOW).code == (
        Exit.TOOL_FAILURE
    )


# ====================================================== the exits module itself


def test_the_exit_mapping_cannot_render_a_refusal_as_breakage():
    assert EXIT_FOR[Refused] is Exit.REFUSED
    assert EXIT_FOR[CannotMeasure] is Exit.TOOL_FAILURE
    assert EXIT_FOR[NotPromoted] is Exit.NOT_PROMOTED
    assert exit_for(Refused("r", verdict="V")) is Exit.REFUSED
    assert exit_for(CannotMeasure("c", verdict="V")) is Exit.TOOL_FAILURE
    assert exit_for(NotPromoted("n", verdict="V")) is Exit.NOT_PROMOTED


def test_refusal_and_inability_to_measure_are_siblings_not_relatives():
    """Defect 4 of ``exits.py``.

    If one were a subclass of the other, a refactor of the mapping could hand
    either the other's exit code, and the two mean opposite things: a refusal is
    a verdict about the subject, an inability to measure is a verdict about the
    instrument.
    """
    assert not issubclass(Refused, CannotMeasure)
    assert not issubclass(CannotMeasure, Refused)
    assert not issubclass(Refused, NotPromoted)
    assert issubclass(Refused, CliOutcome)


def test_an_undeclared_outcome_is_breakage_and_never_success():
    """Defect 2: an exception nobody anticipated has not measured anything."""
    assert exit_for(RuntimeError("x")) is Exit.TOOL_FAILURE
    assert exit_for(CliOutcome("bare", verdict="V")) is Exit.TOOL_FAILURE
    assert exit_for(KeyboardInterrupt()) is Exit.TOOL_FAILURE


def test_the_four_codes_are_the_only_ones():
    assert sorted(int(e) for e in Exit) == [0, 2, 3, 4]


def test_every_lattice_verdict_has_a_contracted_code():
    """A new verdict must be given a code deliberately, not default to one."""
    assert set(EXIT_FOR_VERDICT) == set(Verdict)
    assert EXIT_FOR_VERDICT[Verdict.KILL] is Exit.OK
    assert EXIT_FOR_VERDICT[Verdict.CANDIDATE] is Exit.NOT_PROMOTED
    for verdict in (Verdict.VOID, Verdict.CONFOUNDED, Verdict.INCONCLUSIVE, Verdict.NO_TESTS):
        assert EXIT_FOR_VERDICT[verdict] is Exit.REFUSED, verdict


# ========================================================== the two renderers


def test_json_parses_and_carries_the_same_verdict_as_the_human_renderer(workspace):
    """Two renderers that disagree about the verdict are two instruments.

    The table is built twice, once per renderer, because some rows have a
    one-shot side effect -- appending a ledger row -- and replaying one would
    turn a success row into a refusal for a reason that is not the renderer.
    """
    for (human_argv, expected), (machine_argv, _) in zip(
        _cases(workspace), _cases(workspace), strict=True
    ):
        human = run(*human_argv)
        machine = run(*machine_argv, "--json")
        label = " ".join(human_argv)
        assert machine.code == human.code == expected, label
        payload = machine.json
        assert payload["verdict"] == human.verdict, label
        assert payload["exit_code"] == human.code, label
        assert payload["reason"], f"{label} emitted no reason"


def test_the_output_flag_works_before_and_after_the_subcommand(workspace):
    scope = str(workspace / "scope.json")
    before = run(
        "--json", "scope", "check", "https://api.example/x", "--scope", scope, "--today", TODAY
    )
    after = run(
        "scope", "check", "https://api.example/x", "--scope", scope, "--today", TODAY, "--json"
    )
    assert before.json == after.json


def test_human_is_the_default_and_can_be_asked_for(workspace):
    scope = str(workspace / "scope.json")
    default = run("scope", "check", "https://api.example/x", "--scope", scope, "--today", TODAY)
    explicit = run(
        "scope", "check", "https://api.example/x", "--scope", scope, "--today", TODAY, "--human"
    )
    assert default.out == explicit.out
    with pytest.raises(SystemExit):
        main(["--json", "--human", "selftest"], out=io.StringIO(), err=io.StringIO())


def test_a_warning_goes_to_stderr_in_both_modes(workspace):
    """Defect 2 of ``render.py``: a warning folded into the body gets dropped."""
    stale = str(workspace / "stale.json")
    human = run("scope", "check", "https://api.example/x", "--scope", stale, "--today", TODAY)
    assert human.code == 0
    assert "warning:" in human.err
    assert "last verified" in human.err
    machine = run(
        "scope", "check", "https://api.example/x", "--scope", stale, "--today", TODAY, "--json"
    )
    assert "warning:" in machine.err
    assert machine.json["warnings"], "the warning is absent from the JSON as well"


def test_the_library_never_writes_to_stdout():
    """Only ``render`` prints. Walked as an AST, not grepped.

    A library that prints has decided on the caller's behalf that there is a
    terminal, that the caller wants prose, and that the caller is not assembling
    a machine-readable record out of the same facts. ``render.write`` is the
    single writer, and this is what keeps a convenience ``print`` out of a gate.
    ``main`` is allowed to *name* the streams because that is where they are
    injected from, and nowhere else may.
    """
    import ast

    src = ROOT / "src" / "controlarm"
    printers: set[str] = set()
    streamers: set[str] = set()
    for path in sorted(src.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        where = path.relative_to(src).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print":
                printers.add(where)
            if (
                isinstance(node, ast.Attribute)
                and node.attr in ("stdout", "stderr")
                and getattr(node.value, "id", "") == "sys"
            ):
                streamers.add(where)
    assert printers == {"cli/render.py"}, printers
    assert streamers == {"cli/commands.py"}, streamers


# ================================================== the documentation, both ways


def _implemented() -> set[str]:
    """Every command path the parser binds a handler to."""
    found: set[str] = set()

    def walk(parser: argparse.ArgumentParser, prefix: str) -> None:
        for action in parser._actions:  # the only way argparse exposes its tree
            if not isinstance(action, argparse._SubParsersAction):
                continue
            for name, sub in action.choices.items():
                path = f"{prefix} {name}".strip()
                if sub.get_default("handler") is not None:
                    found.add(path)
                walk(sub, path)

    walk(build_parser(), "")
    return found


def _documented() -> set[str]:
    text = DOCS.read_text(encoding="utf-8")
    return set(re.findall(r"^### `controlarm ([a-z][a-z ]*)`", text, re.M))


@pytest.mark.pristine
def test_every_documented_subcommand_exists():
    """Documentation that is a superset of the code describes stubs."""
    assert not _documented() - _implemented(), _documented() - _implemented()


@pytest.mark.pristine
def test_every_subcommand_that_exists_is_documented():
    """Help that is a superset of the documentation hides behaviour."""
    assert not _implemented() - _documented(), _implemented() - _documented()


@pytest.mark.pristine
def test_the_docs_carry_the_exit_code_table():
    text = DOCS.read_text(encoding="utf-8")
    for code, meaning in (
        ("0", "success"),
        ("2", "tool failure"),
        ("3", "refused"),
        ("4", "not promoted"),
    ):
        assert re.search(rf"\|\s*`?{code}`?\s*\|", text), f"exit {code} is not in a table"
        assert meaning in text.lower(), f"{meaning!r} is not stated"
    assert "never" in text.lower(), "the 'never a negative result' rule is not stated"


@pytest.mark.pristine
def test_every_documented_subcommand_has_a_worked_example():
    """A documented subcommand with no runnable example is a claim, not a doc."""
    text = DOCS.read_text(encoding="utf-8")
    blocks = re.split(r"^### ", text, flags=re.M)[1:]
    for block in blocks:
        name = block.splitlines()[0].strip("` ")
        assert "```console" in block or "```bash" in block, f"{name} has no example block"
        assert "controlarm " in block, f"{name}'s example does not invoke the tool"


@pytest.mark.pristine
def test_the_docs_name_what_is_deliberately_not_implemented():
    """The specification lists more subcommands than exist. Saying which, and
    why, is what keeps an absent one from being read as an overlooked one."""
    text = DOCS.read_text(encoding="utf-8")
    for absent in ("init", "phase0", "dedup", "saturation", "promote", "bundle", "lint", "replay"):
        assert absent in text, f"{absent} is in the specification and unmentioned here"


# =============================================================== the plan format


def test_a_plan_cannot_be_constructed_without_an_oracle_or_a_control():
    """The guard is the constructor signature, not a later check."""
    with pytest.raises(TypeError):
        Plan(id="x", subject="y")  # type: ignore[call-arg]
    arm = ArmSpec("a", "m:f", {}, "refused")
    oracle = OracleSpec("source_diff", "the field")
    with pytest.raises(PlanError, match="must be an OracleSpec"):
        Plan("x", "y", None, arm, arm, ())  # type: ignore[arg-type]
    with pytest.raises(PlanError, match="must be an ArmSpec"):
        Plan("x", "y", oracle, None, arm, ())  # type: ignore[arg-type]
    with pytest.raises(PlanError, match="must be an ArmSpec"):
        Plan("x", "y", oracle, arm, None, ())  # type: ignore[arg-type]


def test_a_blank_required_field_is_refused_at_construction():
    """The loader's own type checks catch a blank before these loops do, so the
    loops are only reachable by constructing a spec directly -- which is how a
    probe written in Python reaches them, and therefore worth pinning."""
    with pytest.raises(PlanError, match=r"oracle\.kind is empty"):
        OracleSpec("", "the field")
    with pytest.raises(PlanError, match=r"oracle\.observable is empty"):
        OracleSpec("source_diff", "   ")

    with pytest.raises(PlanError, match="arm 'name' is empty"):
        ArmSpec("", "m:f", {}, "refused")
    with pytest.raises(PlanError, match="arm 'call' is empty"):
        ArmSpec("a", "   ", {}, "refused")

    oracle, arm = OracleSpec("source_diff", "the field"), ArmSpec("a", "m:f", {}, "refused")
    with pytest.raises(PlanError, match="plan 'id' is empty"):
        Plan("", "subject", oracle, arm, arm, ())
    with pytest.raises(PlanError, match="plan 'subject' is empty"):
        Plan("an-id", "  ", oracle, arm, arm, ())


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        ({"oracle": None}, "is null"),
        ({"control": None}, "is null"),
        ({"liveness": None}, "is null"),
        ({"arms": None}, "is null"),
        ({"oracle": {"kind": "source_diff"}}, "oracle is missing"),
        ({"oracle": {"kind": "", "observable": "x"}}, "empty"),
        ({"oracle": {"kind": "source_diff", "observable": ""}}, "empty"),
        ({"oracle": {"kind": "source_diff", "observable": "x", "extra": 1}}, "unknown key"),
        ({"surprise": 1}, "unknown key"),
        ({"arms": "not a list"}, "must be a list"),
        ({"control": {"name": "c"}}, "missing required key 'call'"),
        ({"control": {"name": "c", "call": "no-colon"}}, "dotted path"),
    ],
)
def test_the_plan_loader_refuses_loudly_and_early(tmp_path, mutate, match):
    source = json.loads((ROOT / "examples/plans/fetch_allowlist.json").read_text("utf-8"))
    source.update(mutate)
    with pytest.raises(PlanError, match=match):
        Plan.from_text(json.dumps(source), source="<test>")


def test_a_required_key_cannot_simply_be_absent(tmp_path):
    source = json.loads((ROOT / "examples/plans/fetch_allowlist.json").read_text("utf-8"))
    for key in ("id", "subject", "oracle", "control", "liveness", "arms"):
        missing = {k: v for k, v in source.items() if k != key}
        with pytest.raises(PlanError, match="missing required key"):
            Plan.from_text(json.dumps(missing), source="<test>")


def test_a_plan_is_not_valid_json_is_a_refusal_not_a_crash():
    with pytest.raises(PlanError, match="not valid JSON"):
        Plan.from_text("{nope}", source="<test>")
    with pytest.raises(PlanError, match="must be a JSON object"):
        Plan.from_text("[1, 2]", source="<test>")


def test_an_inadmissible_oracle_refuses_the_plan_before_any_arm_fires():
    """Item 1: an inadmissible oracle makes every arm unreadable, so firing
    them spends the budget to learn nothing."""
    fired: list[str] = []

    def spy(path):
        def probe(**_kwargs):
            fired.append(path)
            return (True, "200")

        return probe

    weak = Plan.from_path(ROOT / "examples/plans/weak_oracle.json")
    with pytest.raises(PlanError, match="below the floor"):
        execute(weak, resolver=spy)
    assert fired == [], "an arm fired under an inadmissible oracle"

    unscored = json.loads((ROOT / "examples/plans/fetch_allowlist.json").read_text("utf-8"))
    unscored["oracle"] = {"kind": "vibes", "observable": "x"}
    with pytest.raises(PlanError, match="not in the strength table"):
        execute(Plan.from_text(json.dumps(unscored)), resolver=spy)
    assert fired == []


def test_every_callable_is_resolved_before_the_first_arm_runs(tmp_path):
    """Item 5: a half-executed plan looks exactly like a target that stopped
    answering."""
    source = json.loads((ROOT / "examples/plans/fetch_allowlist.json").read_text("utf-8"))
    source["arms"].append(
        {"name": "typo", "call": "examples.local_target.probes:no_such_probe", "args": {}}
    )
    plan = Plan.from_text(json.dumps(source), source="<test>")
    with pytest.raises(PlanError, match="no attribute"):
        execute(plan)

    source["arms"][-1]["call"] = "no.such.module:f"
    with pytest.raises(PlanError, match="could not import"):
        execute(Plan.from_text(json.dumps(source), source="<test>"))

    source["arms"][-1]["call"] = "examples.local_target.probes:ALLOWLIST"
    with pytest.raises(PlanError, match="not a callable"):
        execute(Plan.from_text(json.dumps(source), source="<test>"))


def test_run_writes_the_lattice_to_disk_with_the_plan_beside_it(workspace):
    out = workspace / "written.json"
    result = run(
        "run",
        str(ROOT / "examples/plans/fetch_allowlist_patched.json"),
        "--out",
        str(out),
        "--now",
        NOW,
    )
    assert result.code == 0
    record = json.loads(out.read_text(encoding="utf-8"))
    assert record["verdict"] == "KILL"
    assert record["generated"] == NOW
    assert record["plan"]["oracle"]["strength"] == 3
    assert [a["role"] for a in record["arms"]] == ["liveness", "honest-control", "test"]


def test_a_refused_run_still_writes_nothing_a_reader_could_mistake_for_clean(workspace):
    out = workspace / "void.json"
    result = run(
        "run",
        str(ROOT / "examples/plans/fetch_allowlist_unauthorized.json"),
        "--out",
        str(out),
        "--now",
        NOW,
        "--json",
    )
    assert result.code == Exit.REFUSED
    assert result.json["verdict"] == "VOID"
    assert "VOID, not KILL" in result.json["reason"]
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "VOID"


# ============================================================ oracle rate and G8


@pytest.mark.parametrize(
    "argv",
    [
        ("oracle", "rate", "source_diff"),
        ("oracle", "rate", "assertion_only"),
        ("oracle", "rate", "model_text"),
        ("oracle", "rate", "revert_or_crash"),
        ("oracle", "rate", "not-a-kind"),
    ],
)
def test_oracle_rate_always_states_that_the_scale_is_unvalidated(argv):
    """GAPS.md G8. A tool that printed a bare 0-4 would be lending its own
    heuristic an authority this repository explicitly disclaims, and the
    refusal paths need the caveat as much as the success path does."""
    human = run(*argv)
    assert "GAPS.md G8" in human.out
    assert "UNVALIDATED" in human.out
    machine = run(*argv, "--json")
    assert machine.json["scale_is_validated"] is False
    assert machine.json["caveat"] == G8
    assert G8 in machine.err


def test_oracle_rate_refuses_an_unscored_kind_as_unscored_not_as_unknown():
    result = run("oracle", "rate", "whatever", "--json")
    assert result.code == Exit.REFUSED
    assert result.json["verdict"] == "UNSCORED"
    assert result.json["strength"] is None


# ============================================================== scope verify


def test_scope_verify_records_the_citation_beside_the_file(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(STALE_SCOPE, encoding="utf-8")
    result = run(
        "scope",
        "verify",
        "--scope",
        str(scope),
        "--source",
        "https://example.invalid/policy",
        "--today",
        TODAY,
        "--json",
    )
    assert result.code == 0
    assert json.loads(scope.read_text(encoding="utf-8"))["last_verified"] == TODAY
    log = tmp_path / "scope.json.verification.jsonl"
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["source"] == "https://example.invalid/policy"
    assert entry["last_verified"] == TODAY
    assert len(entry["sha256"]) == 64
    # The stamp made the scope fresh, so the same file now checks trusted.
    check = run(
        "scope", "check", "https://api.example/x", "--scope", str(scope), "--today", TODAY, "--json"
    )
    assert check.json["trusted"] is True


def test_scope_verify_refuses_a_source_that_is_not_a_citation(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(STALE_SCOPE, encoding="utf-8")
    for bad in ("", "   ", "yes", "I checked", "the scope page"):
        result = run("scope", "verify", "--scope", str(scope), "--source", bad, "--today", TODAY)
        assert result.code == Exit.REFUSED, bad
        assert json.loads(scope.read_text(encoding="utf-8"))["last_verified"] == "2025-01-01"
    for good in ("https://example.invalid/policy", '"assets in scope: api.example"'):
        assert (
            run("scope", "verify", "--scope", str(scope), "--source", good, "--today", TODAY).code
            == 0
        )


def test_scope_verify_names_which_of_the_two_citation_refusals_it_is(tmp_path):
    """Two refusals, two reasons, and the reason is the whole value of a refusal.

    Both exit 3, so the exit code alone cannot tell them apart -- and an
    operator who passed a source and is told they passed none will go looking
    for the wrong mistake.
    """
    scope = tmp_path / "scope.json"
    scope.write_text(STALE_SCOPE, encoding="utf-8")
    absent = run("scope", "verify", "--scope", str(scope), "--today", TODAY)
    assert absent.code == Exit.REFUSED
    assert "no cited source" in absent.out
    assert "is not a citation" not in absent.out

    present = run(
        "scope", "verify", "--scope", str(scope), "--source", "I looked", "--today", TODAY
    )
    assert present.code == Exit.REFUSED
    assert "is not a citation" in present.out
    assert "no cited source" not in present.out


def test_scope_check_warns_on_a_stale_file_and_can_be_made_to_refuse(workspace):
    """``check`` reports and ``assert_in_scope`` refuses. ``--refuse-untrusted``
    is how a shell script reaches the second one, and the default is documented
    as the first."""
    stale = str(workspace / "stale.json")
    lenient = run("scope", "check", "https://api.example/x", "--scope", stale, "--today", TODAY)
    assert lenient.code == 0
    assert lenient.verdict == "IN-SCOPE"
    assert "warning:" in lenient.err
    strict = run(
        "scope",
        "check",
        "https://api.example/x",
        "--scope",
        stale,
        "--today",
        TODAY,
        "--refuse-untrusted",
    )
    assert strict.code == Exit.REFUSED
    assert strict.verdict == "BLOCKED-UNTRUSTED"


def test_a_block_is_marked_as_not_a_result(workspace):
    """ "We were not allowed to test it" must not be recorded as "we tested it
    and found nothing"."""
    result = run(
        "scope",
        "check",
        "https://nope.example/x",
        "--scope",
        str(workspace / "scope.json"),
        "--today",
        TODAY,
        "--json",
    )
    assert result.code == Exit.REFUSED
    assert result.json["is_result"] is False


# ================================================================ ledger, audit


def test_the_ledger_refuses_an_absence_it_could_not_reconstruct(tmp_path):
    path = str(tmp_path / "l.jsonl")
    base = [
        "ledger",
        "add",
        "--ledger",
        path,
        "--subject",
        "s",
        "--verdict",
        "KILL",
        "--oracle",
        "source_diff",
        "--now",
        NOW,
    ]
    no_artifact = run(*base, "--id", "a", "--assumption", "only one disagreement")
    assert no_artifact.code == Exit.REFUSED
    assert "results artifact" in no_artifact.out
    no_assumption = run(*base, "--id", "a", "--artifact", "run.json")
    assert no_assumption.code == Exit.REFUSED
    assert "assumption" in no_assumption.out
    both = run(*base, "--id", "a", "--artifact", "run.json", "--assumption", "only one")
    assert both.code == 0


def test_recording_that_no_control_ran_is_allowed_and_is_counted(tmp_path):
    """An honest row must be recordable, or the audit only sees flattering ones."""
    path = str(tmp_path / "l.jsonl")
    assert (
        run(
            "ledger",
            "add",
            "--ledger",
            path,
            "--id",
            "v",
            "--subject",
            "s",
            "--verdict",
            "VOID",
            "--oracle",
            "model_text",
            "--now",
            NOW,
        ).code
        == 0
    )
    report = run("audit", "ledger", "--ledger", path, "--now", NOW, "--json").json
    assert report["control_rate"] == 0.0
    assert report["admissible_oracle_rate"] == 0.0
    notes = report["findings"][0]["notes"]
    assert any("no positive control is recorded" in note for note in notes), notes


def test_an_omitted_tristate_is_not_a_failed_control(tmp_path):
    path = str(tmp_path / "l.jsonl")
    assert (
        run(
            "ledger",
            "add",
            "--ledger",
            path,
            "--id",
            "a",
            "--subject",
            "s",
            "--verdict",
            "CANDIDATE",
            "--oracle",
            "source_diff",
            "--now",
            NOW,
        ).code
        == 0
    )
    row = run("ledger", "show", "--ledger", path, "--json").json["rows"][0]
    assert row["control"]["passed"] is None
    assert row["control"]["independent"] is None
    with pytest.raises(SystemExit):
        main(
            [
                "ledger",
                "add",
                "--ledger",
                path,
                "--id",
                "b",
                "--subject",
                "s",
                "--verdict",
                "CANDIDATE",
                "--oracle",
                "source_diff",
                "--control-passed",
                "maybe",
            ],
            out=io.StringIO(),
            err=io.StringIO(),
        )


def test_an_empty_ledger_reports_no_proportion_rather_than_a_perfect_one(tmp_path):
    """``0/0`` is not ``1.0``. A fresh ledger reporting full coverage would be
    this harness making exactly the claim it audits against."""
    report = run(
        "audit", "ledger", "--ledger", str(tmp_path / "empty.jsonl"), "--now", NOW, "--json"
    ).json
    assert report["n_rows"] == 0
    for key in ("artifact_rate", "control_rate", "admissible_oracle_rate"):
        assert report[key] is None, key
    human = run("audit", "ledger", "--ledger", str(tmp_path / "empty.jsonl"), "--now", NOW)
    assert human.code == 0
    assert "not a passing score" in human.out


def test_audit_ledger_prints_the_three_proportions(tmp_path):
    path = _ledger_with_rows(tmp_path)
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")
    human = run("audit", "ledger", "--ledger", path, "--now", NOW)
    assert human.code == 0
    assert "rows whose results artifact exists" in human.out
    assert "rows with a passing independent positive control" in human.out
    assert "rows with an admissible oracle" in human.out
    machine = run("audit", "ledger", "--ledger", path, "--now", NOW, "--json").json
    assert machine["artifact_rate"] == 0.5
    assert machine["control_rate"] == 0.5
    assert machine["admissible_oracle_rate"] == 0.5


def test_the_audit_checks_the_artifact_is_actually_on_disk(tmp_path):
    """A promise of an artifact is not an artifact."""
    path = _ledger_with_rows(tmp_path)
    without = run("audit", "ledger", "--ledger", path, "--now", NOW, "--json").json
    assert without["artifact_rate"] == 0.0
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")
    with_file = run("audit", "ledger", "--ledger", path, "--now", NOW, "--json").json
    assert with_file["artifact_rate"] == 0.5


def test_audit_ledger_refuses_nothing(tmp_path):
    """The asymmetry is the design: a store that rejected every imperfect row
    would leave an audit that only ever sees flattering ones."""
    path = str(tmp_path / "l.jsonl")
    for i, (verdict, oracle) in enumerate(
        [("VOID", "model_text"), ("CONFOUNDED", "nope"), ("BLOCKED", "string_co_occurrence")]
    ):
        assert (
            run(
                "ledger",
                "add",
                "--ledger",
                path,
                "--id",
                f"r{i}",
                "--subject",
                "s",
                "--verdict",
                verdict,
                "--oracle",
                oracle,
                "--now",
                NOW,
            ).code
            == 0
        )
    result = run("audit", "ledger", "--ledger", path, "--now", NOW)
    assert result.code == Exit.OK
    assert result.verdict == "AUDITED"


def test_audit_ledger_writes_the_markdown_artifact_when_asked(tmp_path):
    path = _ledger_with_rows(tmp_path)
    out = tmp_path / "audit-2026-01-02.md"
    assert run("audit", "ledger", "--ledger", path, "--now", NOW, "--out", str(out)).code == 0
    assert "# Ledger audit" in out.read_text(encoding="utf-8")


def test_an_uncited_claim_is_counted(tmp_path):
    path = str(tmp_path / "l.jsonl")
    assert (
        run(
            "ledger",
            "add",
            "--ledger",
            path,
            "--id",
            "a",
            "--subject",
            "s",
            "--verdict",
            "CANDIDATE",
            "--oracle",
            "source_diff",
            "--now",
            NOW,
            "--claim",
            "the parsers disagree",
            "--claim",
            "and so does the fetcher::https://example.invalid/spec",
        ).code
        == 0
    )
    report = run("audit", "ledger", "--ledger", path, "--now", NOW, "--json").json
    assert report["uncited_claim_count"] == 1


# ================================================================= audit rules


@pytest.mark.pristine
def test_audit_rules_refuses_to_print_a_ratio_it_cannot_derive():
    """The mandated behaviour: print that you cannot, and exit 2.

    Two candidate mappings exist and they disagree by an order of magnitude,
    which is the proof that neither is a measurement. Printing either would be
    printing a coverage number that had never been measured.
    """
    result = run("audit", "rules", "--repo", str(ROOT))
    assert result.code == Exit.TOOL_FAILURE
    assert result.verdict == "UNDERIVABLE"
    assert "NOT COMPUTED" in result.out
    assert "NEITHER IS USABLE" in result.out
    machine = run("audit", "rules", "--repo", str(ROOT), "--json").json
    assert machine["declared_to_enforced_ratio"] is None
    assert machine["unenforced_rules_named"] is False
    assert machine["declared_rules_enumerated_in_repo"] is False
    assert machine["ratio_refused_because"]


@pytest.mark.pristine
def test_audit_rules_derives_every_count_from_a_committed_artifact():
    """Item 1 of ``rules.py``: nothing here is a literal."""
    from tools.mutate_guards import MUTATIONS

    coverage = derive(ROOT)
    assert coverage.declared_rules == 96
    assert "stated validity rules" in coverage.declared_rules_citation
    assert coverage.guards == len(MUTATIONS)
    assert coverage.invariant_rows > 0
    assert coverage.sections_covered == len(coverage.section_coverage)
    # Every library invariant section joins to a real mutation target.
    from tools.mutate_guards import TARGETS

    for module, target in coverage.section_coverage.items():
        assert target in TARGETS, f"{module} -> {target}"


def test_audit_rules_refuses_to_measure_rather_than_degrading(tmp_path):
    """Item 3: a derivation that cannot read its inputs has measured nothing."""
    with pytest.raises(RulesDerivationError, match="unreadable"):
        derive(tmp_path)

    (tmp_path / "GAPS.md").write_text("no rule count here\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "invariants.md").write_text("# nothing\n", encoding="utf-8")
    with pytest.raises(RulesDerivationError, match="could not find the sentence"):
        derive(tmp_path)

    (tmp_path / "GAPS.md").write_text(
        "The methodology this came from carries roughly 96 stated validity rules.\n",
        encoding="utf-8",
    )
    with pytest.raises(RulesDerivationError, match="no '## ' sections"):
        derive(tmp_path)

    (tmp_path / "docs" / "invariants.md").write_text(
        "## The thing -- `controlarm.nothing.here`\n\n"
        "| invariant | wrong verdict |\n|---|---|\n| a rule | a verdict |\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "mutate_guards.py").write_text("MUTATIONS = []\n", encoding="utf-8")
    with pytest.raises(RulesDerivationError, match=r"no mutation in tools/mutate_guards\.py"):
        derive(tmp_path)

    result = run("audit", "rules", "--repo", str(tmp_path))
    assert result.code == Exit.TOOL_FAILURE


def test_audit_rules_in_a_directory_with_no_repository_is_a_tool_failure(tmp_path):
    result = run("audit", "rules", "--repo", str(tmp_path / "nowhere"), "--json")
    assert result.code == Exit.TOOL_FAILURE
    assert result.json["verdict"] == "UNDERIVABLE"


# ==================================================================== selftest


def test_the_selftest_fires_the_exact_expected_multiset():
    """Item 1: a ``Counter`` equality, not a subset assertion."""
    report = run_selftest()
    assert not report.drifted, [o.detail for o in report.failures]
    assert sorted(report.bad_fired) == sorted(EXPECTED_BAD_FAILURES)
    assert report.clean_fired == ()


def test_the_selftest_notices_a_mode_that_stopped_firing():
    report = run_selftest(expected=(*EXPECTED_BAD_FAILURES, "raw_artifact_read"))
    assert report.drifted
    failed = [o for o in report.outcomes if not o.passed]
    assert any("expected but silent" in o.detail for o in failed)
    assert any("raw_artifact_read" in o.detail for o in failed)


def test_the_selftest_notices_a_mode_that_started_firing():
    report = run_selftest(expected=("own_input_echo",))
    assert report.drifted
    assert any("unexpected failures" in o.detail for o in report.outcomes if not o.passed)


def test_the_clean_fixture_must_gate_something_not_merely_fail_nothing():
    """Item 3: a fixture whose every mode was skipped also fires zero.

    Zero failures and zero passes is not a calibrated instrument, it is an
    instrument that was never pointed at anything. ``GateReport.clean`` requires
    at least one mode to have actually passed, and this is the test that keeps
    the second half of that condition in place.
    """
    from dataclasses import replace

    from controlarm.gates.fp import MODES

    # Every mode suppressed, and no claim declared so the claim-scoped ones are
    # NOT-APPLICABLE rather than failing. Nothing fails; nothing passes either.
    skipped = replace(
        clean_fixture(),
        claims=frozenset(),
        suppressed={m.name: "suppressed for this test" for m in MODES if m.claim is None},
    )
    report = run_selftest(refusals=(), inputs={"bad": known_bad_fixture(), "clean": skipped})
    assert report.clean_fired == (), "the point of the fixture is that nothing fails"
    assert report.drifted
    gated = [o for o in report.outcomes if "actually gated something" in o.name]
    assert gated and not gated[0].passed, [o.name for o in report.outcomes]


def test_the_selftest_rejects_a_wrong_exception_type_and_a_wrong_reason():
    """Item 2: both halves are asserted, so a refusal cannot pass by accident."""
    from controlarm.cli.selftest import RefusalMode

    def raises_keyerror():
        raise KeyError("nothing to do with the gate")

    def raises_nothing():
        return "no refusal at all"

    wrong_type = run_selftest(
        refusals=(RefusalMode("x", raises_keyerror, RuntimeError, "anything"),),
    )
    assert wrong_type.drifted
    assert any("raised KeyError, expected RuntimeError" in o.detail for o in wrong_type.outcomes)

    silent = run_selftest(refusals=(RefusalMode("y", raises_nothing, RuntimeError, "a"),))
    assert silent.drifted
    assert any("did not refuse at all" in o.detail for o in silent.outcomes)

    wrong_reason = run_selftest(
        refusals=(RefusalMode("z", raises_keyerror, KeyError, "not in that message"),),
    )
    assert wrong_reason.drifted
    assert any("the reason does not contain" in o.detail for o in wrong_reason.outcomes)


def test_a_drifted_selftest_is_a_tool_failure_and_says_it_voids_prior_verdicts(monkeypatch):
    """E11: if the selftest drifts, every clean verdict since the last pass is
    void and must be re-run. The exit code has to say so."""
    monkeypatch.setattr(
        "controlarm.cli.selftest.selftest",
        lambda **_kwargs: run_selftest(expected=("own_input_echo",)),
    )
    result = run("selftest", "--json")
    assert result.code == Exit.TOOL_FAILURE
    assert result.json["verdict"] == "DRIFTED"
    assert result.json["voids_prior_clean_verdicts"] is True
    assert "VOID and must be re-run" in result.json["reason"]


def test_the_selftest_covers_every_gate_that_can_refuse():
    """A selftest that calibrated only the cheap half would leave the state
    machine that actually blocks a promotion never observed to block one."""
    from controlarm.cli.selftest import REFUSAL_MODES

    families = {mode.expected.__name__ for mode in REFUSAL_MODES}
    assert families == {"LedgerError", "PriorArtError", "ScopeError", "PayloadError"}


def test_selftest_output_states_that_a_non_zero_exit_voids_prior_verdicts():
    result = run("selftest")
    assert result.code == 0
    assert "voids every clean verdict" in result.out


# =========================================================== the public surface


SUBMODULES = [
    "controlarm.controls.run",
    "controlarm.rails.scope",
    "controlarm.rails.payload",
    "controlarm.gates.fp",
    "controlarm.gates.priorart",
    "controlarm.ledger",
]


def test_the_top_level_re_exports_are_the_same_objects_as_the_submodules():
    """The top level is ergonomic; the submodule is canonical. They must not be
    two different objects, or a reviewer's ``isinstance`` check against the
    canonical path would fail on an object imported the convenient way."""
    import controlarm

    defined: dict[str, object] = {}
    for name in SUBMODULES:
        module = importlib.import_module(name)
        for exported in module.__all__:
            defined.setdefault(exported, getattr(module, exported))
    for exported in controlarm.__all__:
        assert exported in defined, f"{exported} is re-exported from nowhere"
        assert getattr(controlarm, exported) is defined[exported], exported


def test_every_public_submodule_name_is_reachable_from_the_top_level():
    """The reviewer's complaint was that the new modules were not importable
    from ``controlarm`` directly. This is that complaint, as a test."""
    import controlarm

    missing = []
    for name in SUBMODULES:
        module = importlib.import_module(name)
        for exported in module.__all__:
            if exported not in controlarm.__all__:
                missing.append(f"{name}.{exported}")
    assert not missing, missing


def test_the_cli_is_not_re_exported_at_the_top_level():
    """A library import that could print is the defect the split prevents."""
    import controlarm

    assert "main" not in controlarm.__all__
    assert not hasattr(controlarm, "Emission")


def test_the_docstring_says_which_path_is_canonical():
    import controlarm

    doc = controlarm.__doc__ or ""
    assert "submodule is canonical" in doc
    assert "top level is ergonomic" in doc


# ========================================================== the installed script


@pytest.mark.pristine
def test_the_console_script_is_wired_to_this_main():
    """The entry point in ``pyproject.toml`` must name the function tested here."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.scripts]" in text
    assert 'controlarm = "controlarm.cli:main"' in text
    module_name, _, attr = "controlarm.cli:main".partition(":")
    assert getattr(importlib.import_module(module_name), attr) is main


@pytest.mark.pristine
@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["selftest"], 0),
        (["oracle", "rate", "model_text"], 3),
        (["oracle", "rate", "source_diff"], 0),
        (["audit", "rules", "--repo", "."], 2),
        (["run", "examples/plans/fetch_allowlist.json"], 4),
        (["run", "examples/plans/fetch_allowlist_patched.json"], 0),
        (["run", "examples/plans/fetch_allowlist_unauthorized.json"], 3),
        (["run", "examples/plans/weak_oracle.json"], 3),
    ],
    ids=lambda v: " ".join(v) if isinstance(v, list) else str(v),
)
def test_module_invocation_agrees_with_the_in_process_exit_code(argv, expected, tmp_path):
    """``python -m controlarm.cli`` must not differ from the function.

    A second entry point reporting a different answer would be a second
    instrument, which is what this whole repository is about. The subprocess
    runs from the repository root, because a plan names its probes by dotted
    path and those are resolved against the working directory.
    """
    if argv[0] == "run":
        argv = [*argv, "--out", str(tmp_path / "run.json")]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    proc = subprocess.run(
        [sys.executable, "-m", "controlarm.cli", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == expected, f"{argv}\n{proc.stdout}\n{proc.stderr}"
    in_process = run(*argv)
    assert in_process.code == proc.returncode


# ------------------------------------------------------------------- bookkeeping


def _command_of(argv: tuple[str, ...]) -> str:
    """The command path an argv names, for comparing against the parser's tree."""
    groups = {"scope", "oracle", "ledger", "audit"}
    head = argv[0]
    if head in groups:
        return f"{head} {argv[1]}"
    return head


def test_the_date_flags_exist_so_no_test_has_to_read_the_clock():
    """``tests/test_clock.py`` forbids a test from calling the wall clock, so
    every subcommand that stamps a time has to accept one."""
    parser = build_parser()
    for argv in (
        ["scope", "check", "x", "--today", TODAY],
        ["scope", "verify", "--today", TODAY],
        [
            "ledger",
            "add",
            "--id",
            "a",
            "--subject",
            "b",
            "--verdict",
            "KILL",
            "--oracle",
            "source_diff",
            "--now",
            NOW,
        ],
        ["audit", "ledger", "--now", NOW],
        ["run", "p", "--now", NOW],
    ):
        ns = parser.parse_args(argv)
        stamped = getattr(ns, "today", None) or getattr(ns, "now", None)
        assert stamped is not None, argv
        assert isinstance(stamped, dt.date)
