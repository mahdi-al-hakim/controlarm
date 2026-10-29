"""controlarm - a red-team evidence harness.

It does not find vulnerabilities. It refuses to let an unaccompanied claim
become a result, and it makes a negative result something you can believe.

Two import paths, and which is which matters
--------------------------------------------
**The submodule is canonical.** ``controlarm.rails.scope``,
``controlarm.rails.payload``, ``controlarm.gates.fp``,
``controlarm.gates.priorart``, ``controlarm.controls.run`` and
``controlarm.ledger`` are where these names are defined, where their docstrings
and numbered defects live, and what the tests, the mutation table and
``docs/invariants.md`` all refer to. Cite the submodule path in a bug report, a
review or a document.

**The top level is ergonomic.** Everything below is re-exported here so that
``from controlarm import ScopeGuard, check_payload_host, run_gate, Ledger``
works, because a reviewer pointed out that the public surface of a rail you are
asked to copy should not require three import lines to reach. The names are the
same objects, not wrappers: ``controlarm.ScopeGuard is
controlarm.rails.scope.ScopeGuard``, and a test asserts that for every name
here.

What is deliberately **not** re-exported: the private helpers of any module, and
anything from ``controlarm.cli``. The CLI is the only part of this package that
writes to a stream, and a library import that could print is the defect the
split exists to prevent. Reach it as ``from controlarm.cli import main``, or by
the installed ``controlarm`` command, which is what it is for.
"""

from controlarm.controls.run import (
    CONFOUND_PATTERNS,
    Arm,
    Outcome,
    Role,
    Run,
    Verdict,
    classify_failure,
)
from controlarm.gates.fp import (
    MODES,
    ORACLE_STRENGTH,
    PLACEHOLDER_PATTERNS,
    REFUSAL_MARKERS,
    STRENGTH_FLOOR,
    CheckState,
    ClaimKind,
    Differential,
    EvidenceSource,
    FPGateResult,
    GateInputs,
    GateReport,
    Mode,
    NoveltyBasis,
    OracleAccess,
    run_gate,
    summarise,
)
from controlarm.gates.priorart import (
    COVERAGE_CONFIDENCE_CAP,
    COVERAGE_NOTE,
    DEFAULT_FRESHNESS,
    CountBasis,
    PriorArtAssessment,
    PriorArtError,
    PriorArtQuery,
    PriorArtThresholds,
    PriorArtVerdict,
    Source,
    StaticSource,
    Validity,
    assert_gated,
    gate,
)
from controlarm.ledger import (
    ASSERTS_ABSENCE,
    BANDS,
    MIN_ADMISSIBLE_STRENGTH,
    AuditReport,
    Band,
    Claim,
    ControlReading,
    Ledger,
    LedgerError,
    LedgerRow,
    LedgerVerdict,
    RowFinding,
    audit,
    negatives_only,
)
from controlarm.rails.payload import (
    DOCUMENTATION_NETWORKS,
    ENV_ADDRESSES,
    ENV_HOSTNAMES,
    OwnedInfra,
    PayloadDecision,
    PayloadError,
    PayloadVerdict,
    assert_own_payload_host,
    check_payload_host,
    decode_candidates,
)
from controlarm.rails.scope import (
    DEFAULT_MAX_AGE_DAYS,
    LOOPBACK_NAMES,
    ScopeConfigError,
    ScopeDecision,
    ScopeEntry,
    ScopeError,
    ScopeFile,
    ScopeGuard,
    ScopeTrust,
    ScopeVerdict,
    host_matches,
    host_of,
)

#: Sorted, not grouped: ruff enforces an isort-style ordering here, and the
#: module each name is defined in is in the docstring above. The submodule
#: path stays the canonical one to cite.
__all__ = [
    "ASSERTS_ABSENCE",
    "BANDS",
    "CONFOUND_PATTERNS",
    "COVERAGE_CONFIDENCE_CAP",
    "COVERAGE_NOTE",
    "DEFAULT_FRESHNESS",
    "DEFAULT_MAX_AGE_DAYS",
    "DOCUMENTATION_NETWORKS",
    "ENV_ADDRESSES",
    "ENV_HOSTNAMES",
    "LOOPBACK_NAMES",
    "MIN_ADMISSIBLE_STRENGTH",
    "MODES",
    "ORACLE_STRENGTH",
    "PLACEHOLDER_PATTERNS",
    "REFUSAL_MARKERS",
    "STRENGTH_FLOOR",
    "Arm",
    "AuditReport",
    "Band",
    "CheckState",
    "Claim",
    "ClaimKind",
    "ControlReading",
    "CountBasis",
    "Differential",
    "EvidenceSource",
    "FPGateResult",
    "GateInputs",
    "GateReport",
    "Ledger",
    "LedgerError",
    "LedgerRow",
    "LedgerVerdict",
    "Mode",
    "NoveltyBasis",
    "OracleAccess",
    "Outcome",
    "OwnedInfra",
    "PayloadDecision",
    "PayloadError",
    "PayloadVerdict",
    "PriorArtAssessment",
    "PriorArtError",
    "PriorArtQuery",
    "PriorArtThresholds",
    "PriorArtVerdict",
    "Role",
    "RowFinding",
    "Run",
    "ScopeConfigError",
    "ScopeDecision",
    "ScopeEntry",
    "ScopeError",
    "ScopeFile",
    "ScopeGuard",
    "ScopeTrust",
    "ScopeVerdict",
    "Source",
    "StaticSource",
    "Validity",
    "Verdict",
    "assert_gated",
    "assert_own_payload_host",
    "audit",
    "check_payload_host",
    "classify_failure",
    "decode_candidates",
    "gate",
    "host_matches",
    "host_of",
    "negatives_only",
    "run_gate",
    "summarise",
]
__version__ = "0.1.0.dev0"
