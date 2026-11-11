"""Clopper-Pearson intervals, with no dependency on SciPy.

A proportion out of forty is not a number, it is a range, and the range is wide
enough that quoting the point estimate alone would misrepresent it. This module
exists so the benchmark cannot report a rate without its interval: ``rate()``
returns both or neither.

Clopper-Pearson rather than Wald because Wald's interval is nonsense at the
boundary -- it is zero-width at 0/n and n/n, which is exactly where a small
benchmark lands -- and because Clopper-Pearson is conservative, which is the
right direction for a number this repository publishes about itself.

The implementation is a bisection on the exact binomial tail, using
``math.comb``. For the n this benchmark has (tens) that is exact to the printed
precision and needs nothing installed. For an n in the millions it would be
slow; it refuses rather than being slow.

Numbered failure modes:

  1  a point estimate published alone  -> ``Rate`` carries the interval as a
     field, so the number cannot be formatted without it.
  2  a boundary interval reported as zero-width -> 0/n and n/n get the exact
     one-sided interval, not ``[0, 0]`` or ``[1, 1]``.
  3  a rate computed from an empty denominator -> ``None``, not ``0.0``.
     "Nothing was measured" and "the rate is zero" are opposite claims.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = ["Rate", "clopper_pearson", "rate"]

#: Beyond this the exact tail is too slow to be worth it, and the normal
#: approximation would be fine -- but this benchmark will never get there, so
#: it refuses rather than quietly switching method.
MAX_N = 100_000


@dataclass(frozen=True)
class Rate:
    """A proportion, its denominator, and its 95% Clopper-Pearson interval."""

    successes: int
    total: int
    point: float
    low: float
    high: float
    confidence: float = 0.95

    def __str__(self) -> str:
        pct = f"{self.point * 100:.1f}%"
        return (
            f"{pct} ({self.successes}/{self.total}; "
            f"{int(self.confidence * 100)}% CI "
            f"{self.low * 100:.1f}%-{self.high * 100:.1f}%)"
        )


def rate(successes: int, total: int, confidence: float = 0.95) -> Rate | None:
    """``None`` when nothing was measured. Failure mode 3."""
    if total <= 0:
        return None
    low, high = clopper_pearson(successes, total, confidence)
    return Rate(successes, total, successes / total, low, high, confidence)


def clopper_pearson(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """The exact two-sided binomial confidence interval for ``successes/total``."""
    if not isinstance(successes, int) or not isinstance(total, int):
        raise TypeError("successes and total must be ints")
    if total <= 0:
        raise ValueError("a confidence interval needs a positive denominator")
    if not 0 <= successes <= total:
        raise ValueError(f"successes={successes} is not within 0..{total}")
    if total > MAX_N:
        raise ValueError(
            f"n={total} exceeds MAX_N={MAX_N}; the exact tail is computed with math.comb and "
            "this module refuses to switch silently to an approximation."
        )
    if not 0 < confidence < 1:
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")

    alpha = (1.0 - confidence) / 2.0
    # Failure mode 2: at the boundary the interval is one-sided, not degenerate.
    low = 0.0 if successes == 0 else _bisect(lambda p: _tail_ge(successes, total, p) - alpha)
    high = 1.0 if successes == total else _bisect(lambda p: alpha - _tail_le(successes, total, p))
    return low, high


def _tail_ge(k: int, n: int, p: float) -> float:
    """P(X >= k). Increasing in p."""
    return sum(math.comb(n, i) * p**i * (1.0 - p) ** (n - i) for i in range(k, n + 1))


def _tail_le(k: int, n: int, p: float) -> float:
    """P(X <= k). Decreasing in p."""
    return sum(math.comb(n, i) * p**i * (1.0 - p) ** (n - i) for i in range(0, k + 1))


def _bisect(f, iterations: int = 200) -> float:
    """Root of a function increasing over [0, 1]. Fixed iteration count so the
    cost is bounded and the result is reproducible to the last bit."""
    low, high = 0.0, 1.0
    for _ in range(iterations):
        mid = (low + high) / 2.0
        if f(mid) < 0.0:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0
