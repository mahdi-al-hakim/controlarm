"""Network prior-art sources for ``controlarm.gates.priorart``.

Importing this package is an explicit act. ``controlarm.gates.priorart`` does
not import it, so the core gate stays stdlib-only and offline, and
``StaticSource`` remains the default everywhere -- tests, examples and the
quickstart never open a socket. These sources are declared behind the
``[dedup]`` extra (see ``pyproject.toml``) to name that boundary.

Nothing here reaches the network at import time, and nothing reaches it at call
time either unless the ``Fetcher`` it was handed is in ``RECORD`` or ``LIVE``
mode. The default is ``REPLAY``: recordings only.

    from controlarm.gates.priorart import gate
    from controlarm.gates.sources import CassetteStore, Fetcher, OsvSource

    fetcher = Fetcher(CassetteStore("benchmarks/dedup/cassettes"))   # REPLAY
    assessment = gate("pkg:pypi/django@3.2.0", [OsvSource(fetcher)], now=now)

The three sources cover different things and are wrong in different directions;
each module's docstring says where. That is the point of asking more than one:
``gate()`` records every source's rows separately, so a disagreement is in the
assessment rather than averaged out of it.
"""

from __future__ import annotations

from controlarm.gates.sources.asof import AsOf, Tally, parse_timestamp
from controlarm.gates.sources.cassette import (
    RECORDED,
    SYNTHETIC,
    USER_AGENT,
    CassetteMiss,
    CassetteStore,
    Fetcher,
    FetchMode,
    Recording,
    Request,
    TransportError,
    scrub,
    scrub_body,
)
from controlarm.gates.sources.ghsa import GitHubAdvisorySource
from controlarm.gates.sources.nvd import NvdSource
from controlarm.gates.sources.osv import OsvSource
from controlarm.gates.sources.subject import (
    ECOSYSTEMS,
    GITHUB_ECOSYSTEM_ENUM,
    Subject,
    parse_subject,
)

__all__ = [
    "ECOSYSTEMS",
    "GITHUB_ECOSYSTEM_ENUM",
    "RECORDED",
    "SYNTHETIC",
    "USER_AGENT",
    "AsOf",
    "CassetteMiss",
    "CassetteStore",
    "FetchMode",
    "Fetcher",
    "GitHubAdvisorySource",
    "NvdSource",
    "OsvSource",
    "Recording",
    "Request",
    "Subject",
    "Tally",
    "TransportError",
    "parse_subject",
    "parse_timestamp",
    "scrub",
    "scrub_body",
]
