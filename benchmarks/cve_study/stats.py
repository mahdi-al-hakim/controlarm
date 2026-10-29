"""Clopper-Pearson intervals and a two-sided Fisher exact test. Stdlib only.

Both are computed rather than quoted, because the numbers this study most needs
to publish are the ones that say its headline is not significant, and a number a
reader cannot recompute from the committed results is a number they have to take
on trust.

``fisher_two_sided`` is deliberately the same definition as
``benchmarks/run_benchmark.py``'s, and ``tests/test_cve_study.py`` asserts the
two agree across a grid of tables. Re-deriving it here keeps this directory
importable on its own; pinning it to the existing one keeps it from drifting
into a friendlier statistic.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import comb

__all__ = ["Rate", "clopper_pearson", "fisher_two_sided", "rate"]


def _binomial_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p). Exact, by summation."""
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0 if k < n else 1.0
    return sum(comb(n, i) * p**i * (1.0 - p) ** (n - i) for i in range(k + 1))


def _solve(predicate, low: float, high: float, iterations: int = 200) -> float:
    """Bisect for the p where ``predicate`` flips. Monotone in p by construction."""
    for _ in range(iterations):
        mid = (low + high) / 2.0
        if predicate(mid):
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def clopper_pearson(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """The exact binomial interval, by inverting the binomial CDF.

    Clopper-Pearson rather than Wald because Wald is nonsense at the
    denominators this study actually has: eleven CVEs, and a rate of zero would
    get an interval of zero width from Wald, which would be a lie told with a
    straight face. Clopper-Pearson is conservative, which is the right direction
    for a study whose own thesis is that unsupported precision is the enemy.
    """
    if total <= 0:
        raise ValueError("an interval needs a denominator")
    if not 0 <= successes <= total:
        raise ValueError(f"{successes} successes out of {total}")
    alpha = 1.0 - confidence
    # The lower bound is the p at which P(X >= successes) = alpha/2, which is
    # P(X <= successes-1) = 1 - alpha/2. Using alpha/2 on this side instead of
    # 1 - alpha/2 is a real mistake with a plausible-looking result: it reported
    # 54/55 as [1.00, 1.00], an interval that excludes its own point estimate.
    lower = (
        0.0
        if successes == 0
        else _solve(lambda p: _binomial_cdf(successes - 1, total, p) > 1.0 - alpha / 2.0, 0.0, 1.0)
    )
    # The upper bound is the p at which P(X <= successes) = alpha/2.
    upper = (
        1.0
        if successes == total
        else _solve(lambda p: _binomial_cdf(successes, total, p) > alpha / 2.0, 0.0, 1.0)
    )
    return (round(lower, 4), round(upper, 4))


@dataclass(frozen=True)
class Rate:
    """A proportion with its denominator and its exact interval, kept together.

    They are one object because reporting the point estimate without the
    denominator is how ``0.00`` comes to look like a result on eleven cases.
    """

    successes: int
    total: int
    low: float
    high: float

    @property
    def value(self) -> float | None:
        return None if self.total == 0 else self.successes / self.total

    def as_dict(self) -> dict:
        return {
            "successes": self.successes,
            "total": self.total,
            "rate": self.value,
            "ci95": [self.low, self.high],
        }

    def __str__(self) -> str:
        if self.total == 0:
            return "n/a (no cases)"
        return f"{self.successes}/{self.total} = {self.value:.2f} [{self.low:.2f}, {self.high:.2f}]"


def rate(successes: int, total: int, confidence: float = 0.95) -> Rate:
    if total == 0:
        return Rate(0, 0, 0.0, 1.0)
    low, high = clopper_pearson(successes, total, confidence)
    return Rate(successes, total, low, high)


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Two-sided Fisher exact p for the 2x2 table ``[[a, b], [c, d]]``.

    Sums every table whose probability is at most the observed table's, which is
    the conventional two-sided definition. Identical to the implementation in
    ``benchmarks/run_benchmark.py``; a test pins them together.
    """
    n = a + b + c + d
    if n == 0 or (a + b) == 0 or (c + d) == 0 or (a + c) == 0 or (b + d) == 0:
        return 1.0

    def probability(x: int) -> float:
        return comb(a + c, x) * comb(b + d, (a + b) - x) / comb(n, a + b)

    observed = probability(a)
    low, high = max(0, (a + b) - (b + d)), min(a + b, a + c)
    return min(
        1.0,
        sum(
            probability(x) for x in range(low, high + 1) if probability(x) <= observed * (1 + 1e-9)
        ),
    )
