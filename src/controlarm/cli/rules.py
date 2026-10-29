"""Declared rules against mechanically enforced rules, derived rather than claimed.

``GAPS.md`` G6 asks for exactly this and says why: *"a rule that lives only in
prose is a preference rather than a control"*, and it names the deliverable as a
declared-to-enforced ratio published per release with the unenforced rules named.

This module does the derivation, and the honest result is that **the ratio
cannot be computed from this repository**. That conclusion is not a shrug and it
is not a placeholder: it falls out of the three artifacts that exist, and
reporting it is the only disposition that does not amount to inventing a
coverage number. The reasoning, which the subcommand prints in full:

* **The denominator is prose.** ``GAPS.md`` G6 states *"roughly 96 stated
  validity rules"*. The ninety-six are not enumerated anywhere in this
  repository, so there is no set to take a subset of. The figure is parsed from
  G6's own sentence, which is cited verbatim rather than copied into a constant.
* **The numerator is a different unit.** ``docs/invariants.md`` enumerates the
  harness invariants and defines "enforced" for each as *a guard in the source,
  a test that fails when the guard is removed, and an entry in
  ``tools/mutate_guards.py``*. Those rows are implementation invariants of this
  harness. They are finer-grained than the methodology's validity rules, they
  are not a subset of them, and no mechanical mapping between the two exists in
  this repository.
* **Both available mappings disagree by an order of magnitude**, which is the
  proof that neither is a measurement. Counting invariant rows against ninety-six
  gives a ratio above two thirds. Counting the distinct methodology rule
  identifiers actually cited by the shipping library gives a ratio below a tenth.
  The published honest baseline for this method is roughly thirty of ninety-six.
  A number that can be argued to any of three values by choosing a unit is a
  rhetorical device, not a coverage figure.

So the subcommand prints all three real counts with their provenance, prints both
candidate ratios **labelled as unusable**, prints what would have to exist for
the ratio to be computable, and **exits 2**. It is the one place in this package
where exiting non-zero is the honest answer to a question that has no answer
yet, and exit 2 is correct for it: the instrument cannot measure, which is a
broken instrument and must never be readable as a result.

Numbered items are the wrong verdicts this design prevents:

  1  a hardcoded coverage number           -> a README figure drifted away from
     the table it was supposedly derived from and nothing noticed, because the
     figure had never been derived from anything. Every count here is parsed out
     of a committed artifact at the moment it is printed, and a count that
     cannot be parsed raises rather than falling back to a literal.
  2  a flattering unit substitution        -> counting whichever unit gives the
     better ratio, with the unit named only in a footnote. Both candidate units
     are computed, both are printed, and neither is promoted to the answer.
  3  a missing artifact scored as a pass   -> a derivation run in a directory
     with no ``docs/invariants.md`` would otherwise report zero declared
     invariants and divide by ninety-six to a flattering zero. A missing or
     unparseable artifact is a refusal to measure, not a measurement.
"""

from __future__ import annotations

import importlib
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "DECLARED_RULE_PATTERN",
    "RULE_ID",
    "InvariantSection",
    "RuleCoverage",
    "RulesDerivationError",
    "derive",
]


class RulesDerivationError(Exception):
    """Raised when a count cannot be derived from a committed artifact.

    Item 3: this is the failure mode, and it is a loud one. The alternative is a
    derivation that silently degrades to zero or to a literal, and a coverage
    number assembled from a missing file is worse than no number.
    """


#: G6's own sentence. The figure is read out of the prose that states it, so a
#: revision of G6 moves this number and a deletion of G6 breaks the derivation
#: rather than leaving a stale constant behind. Item 1.
DECLARED_RULE_PATTERN = re.compile(
    r"carries roughly (?P<count>\d+) stated validity rules", re.IGNORECASE
)

#: A methodology rule identifier: the A/B/C/D/E families of the source rule set.
RULE_ID = re.compile(r"(?<![A-Za-z0-9_])([ABCDE])([0-9]{1,2})(?![A-Za-z0-9_])")


@dataclass(frozen=True)
class InvariantSection:
    """One ``## `` section of ``docs/invariants.md`` and the rows under it."""

    heading: str
    module: str
    rows: tuple[str, ...]

    @property
    def library(self) -> bool:
        """True for a section about the shipped package.

        The mutation harness documents its own invariants in the same file, and
        they are real, but nothing in the mutation table neuters the mutator:
        a tool cannot verify its own guards by removing them with itself. So
        those rows are counted and reported, and excluded from the cross-check
        that every *library* section is covered by a mutation target.
        """
        return self.module.startswith("controlarm.")

    def as_dict(self) -> dict:
        return {
            "heading": self.heading,
            "module": self.module,
            "invariants": len(self.rows),
            "library": self.library,
        }


@dataclass(frozen=True)
class RuleCoverage:
    """Every count, every provenance, and the refusal to divide two of them."""

    declared_rules: int
    declared_rules_citation: str
    sections: tuple[InvariantSection, ...]
    guards: int
    guards_by_target: Mapping[str, int]
    #: section module -> the mutation target that covers it, or None.
    section_coverage: Mapping[str, str | None]
    cited_rule_ids: tuple[str, ...]
    #: Why the declared-to-enforced ratio is not computed. Never empty.
    refusals: tuple[str, ...] = field(default_factory=tuple)

    @property
    def invariant_rows(self) -> int:
        return sum(len(s.rows) for s in self.sections)

    @property
    def library_invariant_rows(self) -> int:
        return sum(len(s.rows) for s in self.sections if s.library)

    @property
    def sections_covered(self) -> int:
        return sum(1 for v in self.section_coverage.values() if v)

    @property
    def candidate_ratio_by_invariant_row(self) -> float:
        """Unusable. Numerator and denominator are different units.

        The library rows are used rather than all of them: the four mutation-
        harness rows are invariants of this repository's tooling and were never
        validity rules of the methodology, so including them would widen the
        numerator with rows the denominator does not contain.
        """
        return self.library_invariant_rows / self.declared_rules

    @property
    def candidate_ratio_by_cited_rule_id(self) -> float:
        """Also unusable. It counts citation habits, not enforcement."""
        return len(self.cited_rule_ids) / self.declared_rules

    def as_dict(self) -> dict:
        return {
            "declared_rules": self.declared_rules,
            "declared_rules_source": "GAPS.md G6",
            "declared_rules_citation": self.declared_rules_citation,
            "declared_rules_enumerated_in_repo": False,
            "invariants_declared_enforced": self.invariant_rows,
            "invariants_declared_enforced_in_the_library": self.library_invariant_rows,
            "invariants_source": "docs/invariants.md (table rows, parsed)",
            "invariant_sections": [s.as_dict() for s in self.sections],
            "guards_mechanically_pinned": self.guards,
            "guards_source": "tools/mutate_guards.py MUTATIONS (each neutered in CI)",
            "guards_by_target": dict(self.guards_by_target),
            "sections_under_mutation_coverage": self.sections_covered,
            "library_sections_total": len(self.section_coverage),
            "methodology_rule_ids_cited_by_the_shipping_library": list(self.cited_rule_ids),
            "declared_to_enforced_ratio": None,
            "ratio_refused_because": list(self.refusals),
            "unusable_candidate_ratios": {
                "invariant_rows_over_declared_rules": round(
                    self.candidate_ratio_by_invariant_row, 3
                ),
                "cited_rule_ids_over_declared_rules": round(
                    self.candidate_ratio_by_cited_rule_id, 3
                ),
            },
            "unenforced_rules_named": False,
        }


def derive(root: str | Path) -> RuleCoverage:
    """Parse the three artifacts and assemble the counts. Prints nothing.

    Raises ``RulesDerivationError`` when an artifact is absent or unparseable.
    Item 3: a derivation that cannot read its inputs has not measured a low
    number, it has measured nothing.
    """
    base = Path(root)
    gaps = _read(base / "GAPS.md")
    invariants = _read(base / "docs" / "invariants.md")

    match = DECLARED_RULE_PATTERN.search(gaps)
    if not match:
        raise RulesDerivationError(
            f"{base / 'GAPS.md'}: could not find the sentence that states how many validity "
            f"rules the source methodology declares (pattern: {DECLARED_RULE_PATTERN.pattern!r}). "
            "The denominator is prose in that file and nowhere else, so without it there is no "
            "denominator -- and a denominator substituted from memory is the defect this "
            "subcommand exists to avoid."
        )
    declared = int(match.group("count"))
    citation = _sentence_around(gaps, match.start())

    sections = _invariant_sections(invariants)
    if not sections:
        raise RulesDerivationError(
            f"{base / 'docs' / 'invariants.md'}: no '## ' sections with table rows were parsed, "
            "so the enforced set could not be read. A missing artifact is not a passing result."
        )

    guards_by_target = _mutation_counts(base)
    section_coverage = {
        s.module: next((t for t in guards_by_target if _covers(t, s.module)), None)
        for s in sections
        if s.library
    }
    uncovered = sorted(m for m, t in section_coverage.items() if not t)
    if uncovered:
        raise RulesDerivationError(
            f"these invariant sections name a module with no mutation in tools/mutate_guards.py: "
            f"{uncovered}. docs/invariants.md defines 'enforced' as including an entry in that "
            "table, so a section without one is a declared enforcement that nothing verifies, "
            "and counting it would be counting an assertion."
        )

    cited = _cited_rule_ids(base / "src" / "controlarm")
    library_rows = sum(len(s.rows) for s in sections if s.library)

    refusals = (
        f"The denominator is prose. GAPS.md G6 states {declared} stated validity rules and the "
        "rules themselves are not enumerated anywhere in this repository, so there is no set to "
        "take a subset of.",
        f"The numerator would be a different unit. The {library_rows} library rows in "
        "docs/invariants.md are implementation invariants of this harness, finer-grained than "
        "the methodology's validity rules and not a subset of them. No mechanical mapping between "
        "the two exists here.",
        "Both available mappings disagree by an order of magnitude "
        f"({library_rows}/{declared} by invariant row versus "
        f"{len(cited)}/{declared} by cited rule identifier), which is the proof that neither is a "
        "measurement rather than a choice of unit.",
        "To close it: enumerate the declared rules in this repository, one identifier each, and "
        "name the identifier on every row of docs/invariants.md. The ratio G6 asks for becomes "
        "computable at that point and not before.",
    )

    return RuleCoverage(
        declared_rules=declared,
        declared_rules_citation=citation,
        sections=sections,
        guards=sum(guards_by_target.values()),
        guards_by_target=guards_by_target,
        section_coverage=section_coverage,
        cited_rule_ids=cited,
        refusals=refusals,
    )


# ------------------------------------------------------------------- the parsers


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RulesDerivationError(
            f"{path}: unreadable ({exc}). Point --repo at a checkout of this repository: the "
            "counts are parsed from committed artifacts and cannot be derived without them."
        ) from exc


def _sentence_around(text: str, index: int) -> str:
    """The sentence containing ``index``, so the figure travels with its source."""
    start = max(text.rfind(".", 0, index), text.rfind("\n", 0, index)) + 1
    end = text.find(".", index)
    end = len(text) if end < 0 else end + 1
    return " ".join(text[start:end].split())


def _invariant_sections(text: str) -> tuple[InvariantSection, ...]:
    """Every ``## `` heading and the table rows beneath it.

    A row is a table line that is neither the header nor the ``---`` separator.
    The parser is deliberately blunt: a table it cannot read produces zero rows
    for that section, and zero rows for every section raises rather than
    reporting a flattering denominator.
    """
    out: list[InvariantSection] = []
    heading = ""
    rows: list[str] = []

    def flush() -> None:
        if heading:
            out.append(InvariantSection(heading, _module_of(heading), tuple(rows)))

    for line in text.splitlines():
        if line.startswith("## "):
            flush()
            heading, rows = line[3:].strip(), []
            continue
        if not heading or not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or not set("".join(cells)) - set("-: "):
            continue
        if cells[0].casefold() == "invariant":
            continue
        rows.append(cells[0])
    flush()
    return tuple(s for s in out if s.rows)


def _module_of(heading: str) -> str:
    """The dotted module or path a section names, read out of its backticks."""
    match = re.search(r"`([^`]+)`", heading)
    return match.group(1) if match else heading


def _covers(target: str, module: str) -> bool:
    """Does mutation target ``target`` cover the module a section names?

    ``TARGETS`` keys are short names (``scope``, ``fp``, ``ledger``) and the
    headings name dotted paths (``controlarm.rails.scope``) or repository paths
    (``tools/mutate_guards.py``). The last component of each is the join key.
    """
    tail = re.split(r"[./]", module.removesuffix(".py"))[-1]
    return target == tail


def _mutation_counts(root: Path) -> Mapping[str, int]:
    """``target -> number of mutations``, read from the committed table.

    The table is imported rather than regex-scraped so the count is the real
    ``len(MUTATIONS)`` and not an approximation of it, which means ``tools``
    has to be importable: the repository root is prepended to ``sys.path`` for
    the duration of the import.
    """
    path = root / "tools" / "mutate_guards.py"
    if not path.is_file():
        raise RulesDerivationError(
            f"{path}: not found. The enforced count is defined in docs/invariants.md as "
            "including an entry in this table, so without the table there is nothing to count."
        )
    root_str = str(root.resolve())
    inserted = root_str not in sys.path
    if inserted:
        sys.path.insert(0, root_str)
    try:
        module = importlib.import_module("tools.mutate_guards")
        mutations: Sequence[object] = module.MUTATIONS
        targets = [getattr(m, "target", "") for m in mutations]
    except Exception as exc:
        raise RulesDerivationError(
            f"{path}: could not be imported to read MUTATIONS "
            f"({type(exc).__name__}: {exc}). The count is not guessed from the file's text."
        ) from exc
    finally:
        if inserted and root_str in sys.path:
            sys.path.remove(root_str)
    counts = Counter(t for t in targets if t)
    if not counts:
        raise RulesDerivationError(f"{path}: MUTATIONS is empty, so no guard is pinned by it")
    return dict(sorted(counts.items()))


def _cited_rule_ids(src: Path) -> tuple[str, ...]:
    """Distinct methodology rule identifiers cited in the shipping library.

    The second candidate numerator, computed so that it can be printed and
    rejected rather than quietly not considered (item 2). It is low because most
    modules cite their motivating defect by number rather than by rule
    identifier, which is a citation habit and not an enforcement fact.
    """
    if not src.is_dir():
        raise RulesDerivationError(f"{src}: not a directory, so the library could not be read")
    found: set[str] = set()
    for path in sorted(src.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for family, number in RULE_ID.findall(path.read_text(encoding="utf-8")):
            found.add(f"{family}{int(number)}")
    return tuple(sorted(found, key=lambda s: (s[0], int(s[1:]))))
