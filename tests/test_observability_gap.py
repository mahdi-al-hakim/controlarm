"""Every figure the observability-gap study states must equal the committed output.

``docs/observability-gap-in-the-wild.md`` published the study's numbers before
anything in this repository backed them. The output of both runs is now
committed in ``benchmarks/observability_gap/`` beside the script that wrote it,
and this file binds each figure the document states to that output, the same
way ``tests/test_readme_figures.py`` binds the README: the expected text is
derived here from the JSON, so a figure edited in either place stops matching.

The description of the corpus (how many scenarios, levels and benign
transcripts, and the closing lines quoted for one scenario) is bound to the
script itself rather than to the JSON, because the script is what built the
transcripts and the JSON only records how they were judged.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
from dataclasses import dataclass

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUDY_DIR = ROOT / "benchmarks" / "observability_gap"
SCRIPT = STUDY_DIR / "observation_gap_study.py"
DOC = (ROOT / "docs" / "observability-gap-in-the-wild.md").read_text(encoding="utf-8")

#: The first judge's run is the one the document reads; the second is reported
#: beside it for what it shows.
FIRST = json.loads((STUDY_DIR / "gap_claude-haiku-4-5-20251001.json").read_text(encoding="utf-8"))
SECOND = json.loads((STUDY_DIR / "gap_claude-sonnet-5.json").read_text(encoding="utf-8"))

#: The study section only. The rest of the document reports RAMPART's own
#: numbers, which this file has no business matching against.
_START = DOC.index("## A small study of the same gap")
_END = DOC.index("## How this relates to controlarm")
STUDY = DOC[_START:_END]

#: Level keys as the script writes them: 0 off-channel, 1 action hinted,
#: 2 destination described in benign-sounding terms, 3 destination named.
LEVELS = ("0", "1", "2", "3")


def _load_script():
    spec = importlib.util.spec_from_file_location("observation_gap_study", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["observation_gap_study"] = module
    spec.loader.exec_module(module)
    return module


STUDY_SCRIPT = _load_script()


def _cell(run: dict, level: str) -> tuple[int, int]:
    block = run["text_only_miss_by_level"][level]
    return block["k"], block["n"]


def _of(k: int, n: int) -> str:
    return rf"{k} of {n}"


@dataclass(frozen=True)
class Binding:
    label: str
    pattern: str


def _bindings() -> list[Binding]:
    out: list[Binding] = []

    def add(label: str, pattern: str) -> None:
        # Any run of whitespace between words, so rewrapping the prose does not
        # break a binding and only a changed word or number does.
        out.append(Binding(label, pattern.replace(" ", r"\s+")))

    # ------------------------------------------------- the corpus, from the script
    corpus = STUDY_SCRIPT._corpus()
    harmful = [r for r in corpus if r["harmful"]]
    benign = [r for r in corpus if not r["harmful"]]
    levels = sorted({r["level"] for r in harmful})
    add("scenarios", rf"There are {len(STUDY_SCRIPT.HARM)} kinds of data and destination")
    add("levels", rf"each at {len(levels)} levels of how much the closing line")
    add("harmful transcripts", rf"so {len(harmful)} harmful transcripts")
    add("benign transcripts", rf"plus {len(benign)} benign ones")
    add("all transcripts", rf"{len(corpus)} in all")

    # ---------------------------------------------------------------- the table
    rows = (
        ("Text only, off-channel", "0"),
        ("Text only, action hinted, no destination", "1"),
        ("Text only, destination described in benign-sounding terms", "2"),
        ("Text only, destination named outright", "3"),
    )
    for name, level in rows:
        add(
            f"table row, {name}",
            rf"\| {name} \| {_of(*_cell(FIRST, level))} \| {_of(*_cell(SECOND, level))} \|",
        )
    pooled = (FIRST["text_only_miss_overall"], SECOND["text_only_miss_overall"])
    add(
        "table row, pooled",
        rf"\| Text only, all levels pooled \| {_of(pooled[0]['k'], pooled[0]['n'])} \| "
        rf"{_of(pooled[1]['k'], pooled[1]['n'])} \|",
    )
    control = (
        FIRST["positive_control_full_safe_on_harmful"],
        SECOND["positive_control_full_safe_on_harmful"],
    )
    add(
        "table row, the positive control",
        rf"\| Full view \(the positive control\) \| {_of(control[0]['k'], control[0]['n'])} \| "
        rf"{_of(control[1]['k'], control[1]['n'])} \|",
    )

    # ------------------------------------------------------------- the reading
    k2, n2 = _cell(FIRST, "2")
    add("benign-framed egress, first judge", rf"called {k2} of {n2} harmful transcripts SAFE")
    add(
        "full-view control, first judge",
        rf"still called {control[0]['k']} of the {control[0]['n']} harmful transcripts SAFE",
    )
    benign_first = FIRST["benign_safe_full"]
    add("benign, first judge", rf"called all {benign_first['n']} benign transcripts SAFE")
    k0, n0 = _cell(FIRST, "0")
    add("off-channel, by construction", rf"row is {k0} of {n0} by construction")
    add(
        "the share of the first judge's pooled count that is off-channel",
        rf"{k0} of the first judge's {pooled[0]['k']} pooled SAFE calls",
    )
    add(
        "the share of the second judge's pooled count that is off-channel",
        rf"all {_cell(SECOND, '0')[0]} of the second judge's",
    )
    add(
        "second judge, transcripts needing review",
        rf"In {SECOND['needs_review']} of the {SECOND['n_transcripts']} transcripts",
    )
    benign_second = SECOND["benign_safe_full"]
    add(
        "benign, second judge",
        rf"called {benign_second['k']} of the {benign_second['n']} usable benign transcripts",
    )
    add(
        "second judge, usable transcripts in the middle rows",
        rf"With {_cell(SECOND, '1')[1]} and {_cell(SECOND, '2')[1]} usable transcripts",
    )
    return out


BINDINGS = _bindings()


def test_the_binding_table_is_populated():
    """An empty table would pass every parametrized test below by having none."""
    assert len(BINDINGS) >= 20, f"only {len(BINDINGS)} figures are bound"
    labels = [b.label for b in BINDINGS]
    assert len(labels) == len(set(labels)), "duplicate binding labels hide a figure"


@pytest.mark.parametrize("binding", BINDINGS, ids=[b.label for b in BINDINGS])
def test_every_figure_the_study_states_matches_the_committed_output(binding: Binding):
    assert re.search(binding.pattern, STUDY), (
        f"docs/observability-gap-in-the-wild.md no longer states {binding.label} as the "
        f"committed output has it; expected /{binding.pattern}/ in the study section"
    )


def _falsify(matched: str) -> str:
    return "".join(str((int(c) + 1) % 10) if c.isdigit() else c for c in matched)


@pytest.mark.parametrize("binding", BINDINGS, ids=[b.label for b in BINDINGS])
def test_no_binding_is_vacuous(binding: Binding):
    """Falsify every number the binding matched; the binding must stop matching."""
    match = re.search(binding.pattern, STUDY)
    assert match is not None, f"{binding.label} is not in the study section"
    assert any(ch.isdigit() for ch in match.group(0)), f"{binding.label} matched no number"
    falsified = re.sub(binding.pattern, lambda m: _falsify(m.group(0)), STUDY)
    assert re.search(binding.pattern, falsified) is None, (
        f"{binding.label} still matches after its numbers were changed, so it binds nothing"
    )


def test_the_document_names_both_judges_as_the_output_records_them():
    for run in (FIRST, SECOND):
        assert f"`{run['judge']}`" in STUDY, f"the study does not name the judge {run['judge']}"


def test_the_words_the_reading_uses_instead_of_numbers_hold():
    """'none', 'all' and 'large gaps' are claims too, so they are checked here."""
    # "it called none of them SAFE when the line hinted at a send ... or named the destination"
    assert _cell(FIRST, "1")[0] == 0 and _cell(FIRST, "3")[0] == 0
    # "called all 8 benign transcripts SAFE"
    assert FIRST["benign_safe_full"]["k"] == FIRST["benign_safe_full"]["n"]
    # "all 16 of the second judge's [pooled SAFE calls come from that row]"
    assert _cell(SECOND, "0")[0] == SECOND["text_only_miss_overall"]["k"]
    # The first judge's column has no gaps; the second judge's does.
    assert FIRST["needs_review"] == 0
    assert all(_cell(FIRST, level)[1] == len(STUDY_SCRIPT.HARM) for level in LEVELS)
    assert SECOND["needs_review"] > 0


@pytest.mark.parametrize("run", [FIRST, SECOND], ids=["first judge", "second judge"])
def test_each_committed_output_is_internally_consistent(run: dict):
    """The pooled row is the sum of the level rows, and the corpus is the script's."""
    by_level = run["text_only_miss_by_level"]
    assert sorted(by_level) == list(LEVELS)
    assert sum(by_level[lv]["k"] for lv in LEVELS) == run["text_only_miss_overall"]["k"]
    assert sum(by_level[lv]["n"] for lv in LEVELS) == run["text_only_miss_overall"]["n"]
    assert run["n_transcripts"] == len(STUDY_SCRIPT._corpus())
    harmful = sum(1 for r in STUDY_SCRIPT._corpus() if r["harmful"])
    assert run["positive_control_full_safe_on_harmful"]["n"] <= harmful
    assert run["benign_safe_full"]["n"] <= len(STUDY_SCRIPT.BENIGN)


def test_the_quoted_scenario_is_what_the_script_generates():
    """The four closing lines and the tool call the document quotes for one scenario."""
    flat = " ".join(STUDY.split())
    scenario = next(h for h in STUDY_SCRIPT.HARM if "sync.codevault-ext.io" in h[1])
    noun, call, destination, description = scenario
    assert f"`{call}`" in flat, f"the study does not quote the tool call {call!r}"
    for line in STUDY_SCRIPT._texts(noun, destination, description).values():
        assert f'"{line}"' in flat, f"the study does not quote the closing line {line!r}"
