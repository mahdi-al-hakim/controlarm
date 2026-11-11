"""The only module in the package that writes to a stream.

Library code must not print. A library that prints has decided, on the caller's
behalf, that there is a terminal, that the caller wants prose, and that the
caller is not assembling a machine-readable record out of the same facts. So
every module under ``src/controlarm`` returns values, and this one turns the
value into bytes on a stream. ``tests/test_cli.py`` walks the AST of the whole
package and fails the build if a write to ``stdout`` appears anywhere else.

An ``Emission`` is the single shape every subcommand returns: one exit code,
one verdict word, one reason, a machine-readable payload, the human lines, and
warnings. Both renderers read the *same* ``Emission``, which is what makes it
possible to assert that ``--json`` and the human output carry the same verdict
rather than hoping they do.

  1  two renderers assembled from two sources  -> a tool printed one verdict to
     the terminal and a different one into its JSON, because each formatter
     re-derived the answer from the raw record. Closed by construction: there is
     exactly one ``Emission`` per invocation and both renderers are pure
     functions of it, so a disagreement is not expressible.
  2  a warning folded into the body            -> a staleness warning printed
     among the results was read as part of them and then dropped by a wrapper
     that kept only the last line. Warnings go to ``stderr`` in both modes and
     also appear as a field in the JSON, so neither a human nor a pipe can
     lose one without discarding a stream.
  3  the verdict printed only as prose         -> a wrapper that could not use
     the exit code had to grep English. The human renderer therefore always
     ends with a machine-greppable ``verdict: X  exit: N`` line, in every mode
     and for every subcommand, including the refusals.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import IO

from controlarm.cli.exits import Exit

__all__ = ["Emission", "render_human", "render_json", "write"]


@dataclass(frozen=True)
class Emission:
    """What one subcommand decided, before anybody has chosen a format."""

    command: str
    verdict: str
    reason: str
    code: Exit = Exit.OK
    #: The machine-readable body. Merged into the top level of the JSON object.
    data: Mapping[str, object] = field(default_factory=dict)
    #: The human body, one line each. Never contains the verdict line: that is
    #: appended by the renderer so it cannot be forgotten by a subcommand.
    lines: Sequence[str] = ()
    #: Goes to stderr in both modes, and into the JSON as a field. Defect 2.
    warnings: Sequence[str] = ()

    def as_dict(self) -> dict:
        return {
            "command": self.command,
            "verdict": self.verdict,
            "reason": self.reason,
            "exit_code": int(self.code),
            "warnings": list(self.warnings),
            **dict(self.data),
        }


def render_json(emission: Emission) -> str:
    """One JSON object, sorted, with the verdict and the exit code in it."""
    return json.dumps(emission.as_dict(), indent=2, sort_keys=True, default=str)


def render_human(emission: Emission) -> str:
    """The default rendering. Ends with the greppable verdict line, always."""
    out: list[str] = []
    out.extend(emission.lines)
    if emission.reason:
        if out:
            out.append("")
        out.append(emission.reason)
    out.append("")
    out.append(f"verdict: {emission.verdict}  exit: {int(emission.code)}")
    return "\n".join(out)


def write(emission: Emission, *, as_json: bool, out: IO[str], err: IO[str]) -> Exit:
    """Print ``emission`` and return its code. The only writer in the package."""
    for warning in emission.warnings:
        print(f"warning: {warning}", file=err)
    body = render_json(emission) if as_json else render_human(emission)
    print(body, file=out)
    return emission.code
